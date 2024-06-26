package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
)

func main() {
	mode := askUserForMode("服务端", "客户端")
	port := 15252
	blockSize := 64 * 1024

	if mode == 1 {
		runServer(port, blockSize)
	} else {
		serverIP := getIP()
		runClient(serverIP, port, blockSize)
	}

	fmt.Println("按任意键退出...")
	fmt.Scanln()
}

func askUserForMode(option1, option2 string) int {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("请选择:1 - %s, 0 - %s: ", option1, option2)
		modeStr, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("读取输入错误: %v\n", err)
			continue
		}
		modeStr = strings.TrimSpace(modeStr)
		mode, err := strconv.Atoi(modeStr)
		if err != nil || (mode != 0 && mode != 1) {
			log.Println("无效的选择, 请输入 1 或 0.")
			continue
		}
		return mode
	}
}

func runServer(port, blockSize int) {
	listener, err := quic.ListenAddr(fmt.Sprintf(":%d", port), generateTLSConfig(), nil)
	if err != nil {
		log.Fatalf("监听错误: %v", err)
	}
	log.Printf("服务端正在监听端口 %d...\n", port)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("与客户端建立连接时出错: %v\n", err)
			continue
		}
		log.Printf("与客户端 %s 建立连接\n", conn.RemoteAddr().String())
		go handleConnection(conn, blockSize)
	}
}

func runClient(serverIP string, port, blockSize int) {
	conn, err := quic.DialAddr(context.Background(), fmt.Sprintf("%s:%d", serverIP, port), generateTLSConfig(), nil)
	if err != nil {
		log.Fatalf("连接服务端错误: %v", err)
	}
	log.Printf("成功连接到服务端 %s\n", serverIP)
	handleConnection(conn, blockSize)
}

func handleConnection(conn quic.Connection, blockSize int) {
	for {
		mode := askUserForMode("接收模式", "发送模式")
		var modeData [1]byte
		modeData[0] = byte(mode)
		stream, err := conn.OpenStream()
		if err != nil {
			log.Fatalf("打开流错误: %v", err)
		}
		if _, err := stream.Write(modeData[:]); err != nil {
			log.Fatalf("协商收发模式错误: %v", err)
		}
		if mode == 1 {
			receiveFile(stream, blockSize)
		} else {
			sendFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode("继续传输", "结束程序")
		if choice != 1 {
			conn.CloseWithError(0, "正常关闭")
			return
		}
	}
}

func getIP() string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("请输入服务端IP地址: ")
		serverIP, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("读取输入错误: %v\n", err)
			continue
		}
		serverIP = strings.TrimSpace(serverIP)
		ip := net.ParseIP(serverIP)
		if ip == nil {
			log.Printf("请输入合法的IPv4或IPv6地址\n")
			continue
		}
		return serverIP
	}
}

func sendFile(stream quic.Stream, blockSize int) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入要发送的文件路径（输入 q 退出）: ")
	filePath, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("读取文件路径错误: %v", err)
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "q" {
		fmt.Println("退出文件发送")
		return
	}
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("打开文件错误: %v", err)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("获取文件信息错误: %v", err)
	}
	fileNameLength := uint8(len(fileInfo.Name()))
	if err := binary.Write(stream, binary.BigEndian, fileNameLength); err != nil {
		log.Fatalf("发送文件名长度错误: %v", err)
	}
	if err := binary.Write(stream, binary.BigEndian, []byte(fileInfo.Name())); err != nil {
		log.Fatalf("发送文件名错误: %v", err)
	}
	if err := binary.Write(stream, binary.BigEndian, fileInfo.Size()); err != nil {
		log.Fatalf("发送文件大小错误: %v", err)
	}
	buffer := make([]byte, blockSize)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			log.Fatalf("读取文件内容错误: %v", err)
		}
		if n == 0 {
			break
		}
		if _, err := stream.Write(buffer[:n]); err != nil {
			log.Fatalf("发送文件内容错误: %v", err)
		}
	}
	fmt.Printf("文件 %s 发送完成\n", fileInfo.Name())
}

func receiveFile(stream quic.Stream, blockSize int) {
	var fileNameLength uint8
	if err := binary.Read(stream, binary.BigEndian, &fileNameLength); err != nil {
		log.Fatalf("接收文件名长度错误: %v", err)
	}
	fileNameBytes := make([]byte, fileNameLength)
	if _, err := stream.Read(fileNameBytes); err != nil {
		log.Fatalf("接收文件名错误: %v", err)
	}
	fileName := string(fileNameBytes)
	var fileSize int64
	if err := binary.Read(stream, binary.BigEndian, &fileSize); err != nil {
		log.Fatalf("接收文件大小错误: %v", err)
	}
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("创建文件错误: %v", err)
	}
	defer file.Close()
	buffer := make([]byte, blockSize)
	var receivedBytes int64
	for {
		n, err := stream.Read(buffer)
		if err != nil && err != io.EOF {
			log.Fatalf("接收文件内容错误: %v", err)
		}
		if n == 0 {
			break
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			log.Fatalf("写入文件内容错误: %v", err)
		}
		receivedBytes += int64(n)
		if receivedBytes >= fileSize {
			break
		}
	}
	fmt.Printf("接收到文件:%s, 大小:%d bytes\n", fileName, fileSize)
}

func generateTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // 仅用于测试
	}
}
