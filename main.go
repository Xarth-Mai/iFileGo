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
	"regexp"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func main() {
	mode := askUserForMode("服务端", "客户端")
	port := 15252
	blockSize := 64 * 1024

	if mode == 1 {
		runServer(port, blockSize)
	} else {
		serverIP, serverName := getServer()
		runClient(serverIP, port, blockSize, serverName)
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
	listener, err := quic.ListenAddr(fmt.Sprintf(":%d", port), generateTLSConfig(1, "null"), nil)
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
		handleServerConnection(conn, blockSize)
		choice := askUserForMode("等待新连接", "结束程序")
		if choice != 1 {
			conn.CloseWithError(0, "正常关闭")
			os.Exit(0)
		}
	}
}

func runClient(serverIP string, port, blockSize int, serverName string) {
	conn, err := quic.DialAddr(context.Background(), fmt.Sprintf("%s:%d", serverIP, port), generateTLSConfig(0, serverName), nil)
	if err != nil {
		log.Fatalf("连接服务端错误: %v", err)
	}
	log.Printf("成功连接到服务端 %s\n", serverIP)
	handleClientConnection(conn, blockSize)
}

func handleServerConnection(conn quic.Connection, blockSize int) {
	for {
		mode := askUserForMode("接收模式", "发送模式")
		var modeData [1]byte
		modeData[0] = byte(mode)
		stream, err := conn.OpenStream()
		if err != nil {
			log.Fatalf("打开流错误: %v", err)
		}
		if _, err := stream.Write(modeData[:]); err != nil {
			log.Fatalf("发送模式错误: %v", err)
		}
		if mode == 1 {
			receiveFile(stream, blockSize)
		} else {
			sendFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode("继续传输", "结束会话")
		if choice != 1 {
			os.Exit(0)
		}
	}
}

func handleClientConnection(conn quic.Connection, blockSize int) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Fatalf("接受流错误: %v", err)
		}
		var modeData [1]byte
		if _, err := stream.Read(modeData[:]); err != nil {
			log.Fatalf("接收模式错误: %v", err)
		}
		mode := modeData[0]
		if mode == 1 {
			sendFile(stream, blockSize)
		} else {
			receiveFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode("继续传输", "结束程序")
		if choice != 1 {
			conn.CloseWithError(0, "正常关闭")
			return
		}
	}
}

func getServer() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("请输入服务端地址: ")
		serverInfo, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("读取输入错误: %v\n", err)
			continue
		}
		serverInfo = strings.TrimSpace(serverInfo)
		ip := net.ParseIP(serverInfo)
		if ip == nil {
			if domainRegex.MatchString(serverInfo) {
				return serverInfo, serverInfo
			} else {
				log.Printf("请输入合法的域名或IP\n")
			}
			continue
		}
		skipChoice := askUserForMode("验证IP证书", "跳过验证")
		if skipChoice != 1 {
			return serverInfo, "skip"
		}
		return serverInfo, serverInfo
	}
}

func sendFile(stream quic.Stream, blockSize int) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入要发送的文件路径: ")
	filePath, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("读取文件路径错误: %v", err)
	}
	filePath = strings.TrimSpace(filePath)
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

func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("无法加载tls证书: %v\n", err)
	}
	return cert
}

func generateTLSConfig(mode int, serverName string) *tls.Config {
	if mode == 1 {
		return &tls.Config{
			Certificates: []tls.Certificate{
				loadTLSCertificate("server.crt", "server.key"),
			},
		}
	} else if serverName == "skip" {
		return &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         serverName,
		}
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
}
