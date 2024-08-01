package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/quic-go/quic-go"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func main() {
	version := "13"
	fmt.Printf("iFileGo V%s\n", version)
	mode := askUserForMode("服务端", "客户端")
	port := 35342
	blockSize := 64 * 1280

	if mode == 1 {
		runServer(port, blockSize)
	} else {
		serverIP, serverName := getServer()
		runClient(serverIP, port, blockSize, serverName)
	}

	fmt.Println("按任意键退出...")
	fmt.Scanln()
	os.Exit(0)
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
			return
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
			return
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
		serverInfo = strings.Trim(serverInfo, `"'[]/`)
		ip := net.ParseIP(serverInfo)
		if ip == nil {
			if domainRegex.MatchString(serverInfo) {
				return serverInfo, serverInfo
			} else {
				log.Printf("请输入合法的域名或IP\n")
			}
			continue
		}
		serverName := serverInfo
		if ip.To4() == nil && len(ip) == net.IPv6len {
			serverInfo = "[" + serverInfo + "]"
		}
		skipChoice := askUserForMode("验证IP证书", "跳过验证")
		if skipChoice != 1 {
			return serverInfo, "skip"
		}
		return serverInfo, serverName
	}
}

func sendFile(stream quic.Stream, blockSize int) {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("请输入要发送的文件路径: ")
		filePath, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("读取文件路径错误: %v", err)
			continue
		}
		filePath = strings.Trim(strings.TrimSpace(filePath), "\"")
		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf("打开文件错误: %v", err)
			continue
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatalf("获取文件信息错误: %v", err)
			continue
		}
		fileName := fileInfo.Name()
		fileSize := fileInfo.Size()

		// 发送文件名长度和文件名
		if err := binary.Write(stream, binary.BigEndian, uint8(len(fileName))); err != nil {
			log.Fatalf("发送文件名长度错误: %v", err)
			return
		}
		if err := binary.Write(stream, binary.BigEndian, []byte(fileName)); err != nil {
			log.Fatalf("发送文件名错误: %v", err)
			return
		}
		// 发送文件大小
		if err := binary.Write(stream, binary.BigEndian, fileSize); err != nil {
			log.Fatalf("发送文件大小错误: %v", err)
			return
		}

		// 创建进度条
		bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

		// 通过重复写入来发送文件内容，并更新进度条
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
			bar.Add(blockSize)
		}
		bar.Finish()
		fmt.Printf("文件 %s 发送完成\n", fileName)
		return
	}
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

	// 创建进度条
	bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

	// 创建文件
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("创建文件错误: %v", err)
	}
	defer file.Close()

	// 通过循环读取数据并更新进度条，写入文件
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
		bar.Add(n)
		receivedBytes += int64(n)
		if receivedBytes >= fileSize {
			break
		}
	}
	bar.Finish()
	fmt.Printf("接收到文件:%s, 大小:%d bytes\n", fileName, fileSize)
}

func generateRandomTLSCertificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("无法生成私钥: %v\n", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("无法生成序列号: %v\n", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Random Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("无法生成证书: %v\n", err)
	}

	certOut, err := os.Create("random_server.crt")
	if err != nil {
		log.Fatalf("无法创建证书文件: %v\n", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create("random_server.key")
	if err != nil {
		log.Fatalf("无法创建密钥文件: %v\n", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	log.Println("随机生成的TLS证书已保存为 random_server.crt 和 random_server.key")

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("无法加载TLS证书: %v,随机生成一对新的证书\n", err)
		return generateRandomTLSCertificate()
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
			InsecureSkipVerify: true,
			ServerName:         serverName,
		}
	}

	return &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         serverName,
	}
}
