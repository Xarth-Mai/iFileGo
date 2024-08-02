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

var translations = map[string]map[string]string{
	"en": {
		"version":                    "iFileGo V%s\n",
		"serverMode":                 "Server",
		"clientMode":                 "Client",
		"selectMode":                 "Select: 1 - %s, 0 - %s: ",
		"invalidChoice":              "Invalid choice, please enter 1 or 0.",
		"exitPrompt":                 "Press any key to exit...",
		"serverListening":            "Server is listening on port %d...\n",
		"connectionError":            "Error establishing connection with client: %v\n",
		"connectedToClient":          "Connected to client %s\n",
		"chooseMode":                 "Choose mode: Receive (1) or Send (0): ",
		"receiveMode":                "Receive mode",
		"sendMode":                   "Send mode",
		"continueTransfer":           "Continue transfer",
		"endSession":                 "End session",
		"continueTransmission":       "Continue transmission",
		"endProgram":                 "End program",
		"enterFilePath":              "Enter the file path to send: ",
		"filePathError":              "Error reading file path: %v",
		"fileOpenError":              "Error opening file: %v",
		"fileStatError":              "Error getting file info: %v",
		"sendFileNameLengthError":    "Error sending file name length: %v",
		"sendFileNameError":          "Error sending file name: %v",
		"sendFileSizeError":          "Error sending file size: %v",
		"sendFileContentError":       "Error sending file content: %v",
		"fileSent":                   "File %s sent successfully\n",
		"receiveFileNameLengthError": "Error receiving file name length: %v",
		"receiveFileNameError":       "Error receiving file name: %v",
		"receiveFileSizeError":       "Error receiving file size: %v",
		"createFileError":            "Error creating file: %v",
		"writeFileError":             "Error writing file content: %v",
		"fileReceived":               "Received file: %s, Size: %d bytes\n",
		"generatePrivateKeyError":    "Error generating private key: %v\n",
		"generateSerialNumberError":  "Error generating serial number: %v\n",
		"generateCertificateError":   "Error generating certificate: %v\n",
		"createCertFileError":        "Error creating certificate file: %v\n",
		"createKeyFileError":         "Error creating key file: %v\n",
		"certSaved":                  "Randomly generated TLS certificate saved as random_server.crt and random_server.key",
		"loadCertError":              "Error loading TLS certificate: %v, generating a new pair",
		"loadCertDefault":            "Loading default TLS certificate",
	},
	"zhs": {
		"version":                    "iFileGo V%s\n",
		"serverMode":                 "服务端",
		"clientMode":                 "客户端",
		"selectMode":                 "请选择:1 - %s, 0 - %s: ",
		"invalidChoice":              "无效的选择, 请输入 1 或 0.",
		"exitPrompt":                 "按任意键退出...",
		"serverListening":            "服务端正在监听端口 %d...\n",
		"connectionError":            "与客户端建立连接时出错: %v\n",
		"connectedToClient":          "与客户端 %s 建立连接\n",
		"chooseMode":                 "选择模式: 接收 (1) 或 发送 (0): ",
		"receiveMode":                "接收模式",
		"sendMode":                   "发送模式",
		"continueTransfer":           "继续传输",
		"endSession":                 "结束会话",
		"continueTransmission":       "继续传输",
		"endProgram":                 "结束程序",
		"enterFilePath":              "请输入要发送的文件路径: ",
		"filePathError":              "读取文件路径错误: %v",
		"fileOpenError":              "打开文件错误: %v",
		"fileStatError":              "获取文件信息错误: %v",
		"sendFileNameLengthError":    "发送文件名长度错误: %v",
		"sendFileNameError":          "发送文件名错误: %v",
		"sendFileSizeError":          "发送文件大小错误: %v",
		"sendFileContentError":       "发送文件内容错误: %v",
		"fileSent":                   "文件 %s 发送完成\n",
		"receiveFileNameLengthError": "接收文件名长度错误: %v",
		"receiveFileNameError":       "接收文件名错误: %v",
		"receiveFileSizeError":       "接收文件大小错误: %v",
		"createFileError":            "创建文件错误: %v",
		"writeFileError":             "写入文件内容错误: %v",
		"fileReceived":               "接收到文件: %s, 大小: %d bytes\n",
		"generatePrivateKeyError":    "无法生成私钥: %v\n",
		"generateSerialNumberError":  "无法生成序列号: %v\n",
		"generateCertificateError":   "无法生成证书: %v\n",
		"createCertFileError":        "无法创建证书文件: %v\n",
		"createKeyFileError":         "无法创建密钥文件: %v\n",
		"certSaved":                  "随机生成的TLS证书已保存为 random_server.crt 和 random_server.key",
		"loadCertError":              "无法加载TLS证书: %v, 随机生成一对新的证书",
		"loadCertDefault":            "加载默认TLS证书",
	},
}

var currentLanguage string

func main() {
	version := "14"
	initLanguage()
	fmt.Print(translate("version", version))
	mode := askUserForMode(translate("serverMode"), translate("clientMode"))
	port := 35342
	blockSize := 64 * 1280

	if mode == 1 {
		runServer(port, blockSize)
	} else {
		serverIP, serverName := getServer()
		runClient(serverIP, port, blockSize, serverName)
	}

	fmt.Println(translate("exitPrompt"))
	fmt.Scanln()
	os.Exit(0)
}

func initLanguage() {
	envVars := []string{"LANG", "LC_ALL", "LC_MESSAGES"}
	var languageCode string

	for _, envVar := range envVars {
		if lang, exists := os.LookupEnv(envVar); exists {
			parts := strings.Split(lang, "_")
			if len(parts) > 0 {
				languageCode = parts[0]
				break
			}
		}
	}

	if strings.HasPrefix(languageCode, "zh") {
		currentLanguage = "zhs"
	} else {
		currentLanguage = "en"
	}
}

func translate(key string, args ...interface{}) string {
	if val, ok := translations[currentLanguage][key]; ok {
		return fmt.Sprintf(val, args...)
	}
	if val, ok := translations["en"][key]; ok {
		return fmt.Sprintf(val, args...)
	}
	return key
}

func askUserForMode(option1, option2 string) int {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(translate("selectMode", option1, option2))
		modeStr, err := reader.ReadString('\n')
		if err != nil {
			log.Print(translate("filePathError", err))
			continue
		}
		modeStr = strings.TrimSpace(modeStr)
		mode, err := strconv.Atoi(modeStr)
		if err != nil || (mode != 0 && mode != 1) {
			log.Println(translate("invalidChoice"))
			continue
		}
		return mode
	}
}

func runServer(port, blockSize int) {
	listener, err := quic.ListenAddr(fmt.Sprintf(":%d", port), generateTLSConfig(1, "null"), nil)
	if err != nil {
		log.Fatalf(translate("connectionError", err))
	}
	log.Print(translate("serverListening", port))
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Print(translate("connectionError", err))
			continue
		}
		log.Print(translate("connectedToClient", conn.RemoteAddr().String()))
		handleServerConnection(conn, blockSize)
		choice := askUserForMode(translate("continueTransmission"), translate("endSession"))
		if choice != 1 {
			conn.CloseWithError(0, translate("endSession"))
			return
		}
	}
}

func runClient(serverIP string, port, blockSize int, serverName string) {
	conn, err := quic.DialAddr(context.Background(), fmt.Sprintf("%s:%d", serverIP, port), generateTLSConfig(0, serverName), nil)
	if err != nil {
		log.Fatalf(translate("connectionError", err))
	}
	log.Print(translate("connectedToClient", serverIP))
	handleClientConnection(conn, blockSize)
}

func handleServerConnection(conn quic.Connection, blockSize int) {
	for {
		mode := askUserForMode(translate("receiveMode"), translate("sendMode"))
		var modeData [1]byte
		modeData[0] = byte(mode)
		stream, err := conn.OpenStream()
		if err != nil {
			log.Fatalf(translate("fileOpenError", err))
		}
		if _, err := stream.Write(modeData[:]); err != nil {
			log.Fatalf(translate("fileOpenError", err))
		}
		if mode == 1 {
			receiveFile(stream, blockSize)
		} else {
			sendFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode(translate("continueTransmission"), translate("endSession"))
		if choice != 1 {
			return
		}
	}
}

func handleClientConnection(conn quic.Connection, blockSize int) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Fatalf(translate("fileOpenError", err))
		}
		var modeData [1]byte
		if _, err := stream.Read(modeData[:]); err != nil {
			log.Fatalf(translate("fileOpenError", err))
		}
		mode := modeData[0]
		if mode == 1 {
			sendFile(stream, blockSize)
		} else {
			receiveFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode(translate("continueTransmission"), translate("endProgram"))
		if choice != 1 {
			conn.CloseWithError(0, translate("endProgram"))
			return
		}
	}
}

func getServer() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(translate("enterFilePath"))
		serverInfo, err := reader.ReadString('\n')
		if err != nil {
			log.Print(translate("filePathError", err))
			continue
		}
		serverInfo = strings.TrimSpace(serverInfo)
		serverInfo = strings.Trim(serverInfo, `"'[]/`)
		ip := net.ParseIP(serverInfo)
		if ip == nil {
			if domainRegex.MatchString(serverInfo) {
				return serverInfo, serverInfo
			} else {
				log.Print(translate("invalidChoice"))
			}
			continue
		}
		serverName := serverInfo
		if ip.To4() == nil && len(ip) == net.IPv6len {
			serverInfo = "[" + serverInfo + "]"
		}
		skipChoice := askUserForMode(translate("generateCertificateError"), translate("generatePrivateKeyError"))
		if skipChoice != 1 {
			return serverInfo, "skip"
		}
		return serverInfo, serverName
	}
}

func sendFile(stream quic.Stream, blockSize int) {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(translate("enterFilePath"))
		filePath, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf(translate("filePathError", err))
			continue
		}
		filePath = strings.Trim(strings.TrimSpace(filePath), "\"")
		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf(translate("fileOpenError", err))
			continue
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatalf(translate("fileStatError", err))
			continue
		}
		fileName := fileInfo.Name()
		fileSize := fileInfo.Size()

		// 发送文件名长度和文件名
		if err := binary.Write(stream, binary.BigEndian, uint8(len(fileName))); err != nil {
			log.Fatalf(translate("sendFileNameLengthError", err))
			return
		}
		if err := binary.Write(stream, binary.BigEndian, []byte(fileName)); err != nil {
			log.Fatalf(translate("sendFileNameError", err))
			return
		}
		// 发送文件大小
		if err := binary.Write(stream, binary.BigEndian, fileSize); err != nil {
			log.Fatalf(translate("sendFileSizeError", err))
			return
		}

		// 创建进度条
		bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

		// 通过重复写入来发送文件内容，并更新进度条
		buffer := make([]byte, blockSize)
		for {
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				log.Fatalf(translate("sendFileContentError", err))
			}
			if n == 0 {
				break
			}
			if _, err := stream.Write(buffer[:n]); err != nil {
				log.Fatalf(translate("sendFileContentError", err))
			}
			bar.Add(blockSize)
		}
		bar.Finish()
		fmt.Print(translate("fileSent", fileName))
		return
	}
}

func receiveFile(stream quic.Stream, blockSize int) {
	var fileNameLength uint8
	if err := binary.Read(stream, binary.BigEndian, &fileNameLength); err != nil {
		log.Fatalf(translate("receiveFileNameLengthError", err))
	}
	fileNameBytes := make([]byte, fileNameLength)
	if _, err := stream.Read(fileNameBytes); err != nil {
		log.Fatalf(translate("receiveFileNameError", err))
	}
	fileName := string(fileNameBytes)
	var fileSize int64
	if err := binary.Read(stream, binary.BigEndian, &fileSize); err != nil {
		log.Fatalf(translate("receiveFileSizeError", err))
	}

	// 创建进度条
	bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

	// 创建文件
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf(translate("createFileError", err))
	}
	defer file.Close()

	// 通过循环读取数据并更新进度条，写入文件
	buffer := make([]byte, blockSize)
	var receivedBytes int64
	for {
		n, err := stream.Read(buffer)
		if err != nil && err != io.EOF {
			log.Fatalf(translate("receiveFileContentError", err))
		}
		if n == 0 {
			break
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			log.Fatalf(translate("writeFileError", err))
		}
		bar.Add(n)
		receivedBytes += int64(n)
		if receivedBytes >= fileSize {
			break
		}
	}
	bar.Finish()
	fmt.Print(translate("fileReceived", fileName, fileSize))
}

func generateRandomTLSCertificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf(translate("generatePrivateKeyError", err))
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf(translate("generateSerialNumberError", err))
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
		log.Fatalf(translate("generateCertificateError", err))
	}

	certOut, err := os.Create("random_server.crt")
	if err != nil {
		log.Fatalf(translate("createCertFileError", err))
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create("random_server.key")
	if err != nil {
		log.Fatalf(translate("createKeyFileError", err))
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	log.Println(translate("certSaved"))

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Print(translate("loadCertError", err))
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
