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

	i18n "github.com/Xarth-Mai/EasyI18n-Go"
	"github.com/cheggaaa/pb/v3"
	"github.com/quic-go/quic-go"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func main() {
	version := "16"
	i18n.SetCustomTranslations(EasyI18nTranslations)
	i18n.InitLanguage()
	fmt.Print(i18n.Translate("version", version))
	mode := askUserForMode(i18n.Translate("serverMode"), i18n.Translate("clientMode"))
	port := 35342
	blockSize := 64 * 1280

	if mode == 1 {
		runServer(port, blockSize)
	} else {
		serverIP, serverName := getServer()
		runClient(serverIP, port, blockSize, serverName)
	}

	fmt.Println(i18n.Translate("exitPrompt"))
	fmt.Scanln()
	os.Exit(0)
}

func askUserForMode(option1, option2 string) int {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(i18n.Translate("selectMode", option1, option2))
		modeStr, err := reader.ReadString('\n')
		if err != nil {
			log.Print(i18n.Translate("filePathError", err))
			continue
		}
		modeStr = strings.TrimSpace(modeStr)
		mode, err := strconv.Atoi(modeStr)
		if err != nil || (mode != 0 && mode != 1) {
			log.Println(i18n.Translate("invalidChoice"))
			continue
		}
		return mode
	}
}

func runServer(port, blockSize int) {
	listener, err := quic.ListenAddr(fmt.Sprintf(":%d", port), generateTLSConfig(1, "null"), nil)
	if err != nil {
		log.Fatalf(i18n.Translate("listeningError", err))
	}
	log.Print(i18n.Translate("serverListening", port))
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Print(i18n.Translate("connectionError", err))
			continue
		}
		log.Print(i18n.Translate("connectedTo", conn.RemoteAddr().String()))
		handleServerConnection(conn, blockSize)
		choice := askUserForMode(i18n.Translate("continueTransfer"), i18n.Translate("endProgram"))
		if choice != 1 {
			conn.CloseWithError(0, i18n.Translate("normalClose"))
			return
		}
	}
}

func runClient(serverIP string, port, blockSize int, serverName string) {
	conn, err := quic.DialAddr(context.Background(), fmt.Sprintf("%s:%d", serverIP, port), generateTLSConfig(0, serverName), nil)
	if err != nil {
		log.Fatalf(i18n.Translate("connectionError", err))
	}
	log.Print(i18n.Translate("connectedTo", serverIP))
	handleClientConnection(conn, blockSize)
}

func handleServerConnection(conn quic.Connection, blockSize int) {
	for {
		mode := askUserForMode(i18n.Translate("receiveMode"), i18n.Translate("sendMode"))
		var modeData [1]byte
		modeData[0] = byte(mode)
		stream, err := conn.OpenStream()
		if err != nil {
			log.Fatalf(i18n.Translate("streamOpenError", err))
		}
		if _, err := stream.Write(modeData[:]); err != nil {
			log.Fatalf(i18n.Translate("negotiateModeError", err))
		}
		if mode == 1 {
			receiveFile(stream, blockSize)
		} else {
			sendFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode(i18n.Translate("continueTransfer"), i18n.Translate("endSession"))
		if choice != 1 {
			return
		}
	}
}

func handleClientConnection(conn quic.Connection, blockSize int) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Fatalf(i18n.Translate("streamReceiveError", err))
		}
		var modeData [1]byte
		if _, err := stream.Read(modeData[:]); err != nil {
			log.Fatalf(i18n.Translate("negotiateModeError", err))
		}
		mode := modeData[0]
		if mode == 1 {
			sendFile(stream, blockSize)
		} else {
			receiveFile(stream, blockSize)
		}
		stream.Close()
		choice := askUserForMode(i18n.Translate("continueTransfer"), i18n.Translate("endProgram"))
		if choice != 1 {
			conn.CloseWithError(0, i18n.Translate("normalClose"))
			return
		}
	}
}

func getServer() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(i18n.Translate("getServerAddress"))
		serverInfo, err := reader.ReadString('\n')
		if err != nil {
			log.Print(i18n.Translate("readInputError", err))
			continue
		}
		serverInfo = strings.TrimSpace(serverInfo)
		serverInfo = strings.Trim(serverInfo, `"'[]/`)
		ip := net.ParseIP(serverInfo)
		if ip == nil {
			if domainRegex.MatchString(serverInfo) {
				return serverInfo, serverInfo
			} else {
				log.Print(i18n.Translate("invalidIP"))
			}
			continue
		}
		serverName := serverInfo
		if ip.To4() == nil && len(ip) == net.IPv6len {
			serverInfo = "[" + serverInfo + "]"
		}
		skipChoice := askUserForMode(i18n.Translate("verifyIPCrt"), i18n.Translate("skipVerify"))
		if skipChoice != 1 {
			return serverInfo, "skip"
		}
		return serverInfo, serverName
	}
}

func sendFile(stream quic.Stream, blockSize int) {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(i18n.Translate("enterFilePath"))
		filePath, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf(i18n.Translate("filePathError", err))
			continue
		}
		filePath = strings.Trim(strings.TrimSpace(filePath), "\"")
		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf(i18n.Translate("fileOpenError", err))
			continue
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatalf(i18n.Translate("fileStatError", err))
			continue
		}
		fileName := fileInfo.Name()
		fileSize := fileInfo.Size()

		// 发送文件名长度和文件名
		if err := binary.Write(stream, binary.BigEndian, uint8(len(fileName))); err != nil {
			log.Fatalf(i18n.Translate("sendFileNameLengthError", err))
			return
		}
		if err := binary.Write(stream, binary.BigEndian, []byte(fileName)); err != nil {
			log.Fatalf(i18n.Translate("sendFileNameError", err))
			return
		}
		// 发送文件大小
		if err := binary.Write(stream, binary.BigEndian, fileSize); err != nil {
			log.Fatalf(i18n.Translate("sendFileSizeError", err))
			return
		}

		// 创建进度条
		bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

		// 通过重复写入来发送文件内容，并更新进度条
		buffer := make([]byte, blockSize)
		for {
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				log.Fatalf(i18n.Translate("fileStatError", err))
			}
			if n == 0 {
				break
			}
			if _, err := stream.Write(buffer[:n]); err != nil {
				log.Fatalf(i18n.Translate("sendFileContentError", err))
			}
			bar.Add(blockSize)
		}
		bar.Finish()
		fmt.Print(i18n.Translate("fileSent", fileName))
		return
	}
}

func receiveFile(stream quic.Stream, blockSize int) {
	var fileNameLength uint8
	if err := binary.Read(stream, binary.BigEndian, &fileNameLength); err != nil {
		log.Fatalf(i18n.Translate("receiveFileNameLengthError", err))
	}
	fileNameBytes := make([]byte, fileNameLength)
	if _, err := stream.Read(fileNameBytes); err != nil {
		log.Fatalf(i18n.Translate("receiveFileNameError", err))
	}
	fileName := string(fileNameBytes)
	var fileSize int64
	if err := binary.Read(stream, binary.BigEndian, &fileSize); err != nil {
		log.Fatalf(i18n.Translate("receiveFileSizeError", err))
	}

	// 创建进度条
	bar := pb.Full.Start64(fileSize).Set(pb.Bytes, true)

	// 创建文件
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf(i18n.Translate("createFileError", err))
	}
	defer file.Close()

	// 通过循环读取数据并更新进度条，写入文件
	buffer := make([]byte, blockSize)
	var receivedBytes int64
	for {
		n, err := stream.Read(buffer)
		if err != nil && err != io.EOF {
			log.Fatalf(i18n.Translate("receiveFileContentError", err))
		}
		if n == 0 {
			break
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			log.Fatalf(i18n.Translate("writeFileError", err))
		}
		bar.Add(n)
		receivedBytes += int64(n)
		if receivedBytes >= fileSize {
			break
		}
	}
	bar.Finish()
	fmt.Print(i18n.Translate("fileReceived", fileName, fileSize))
}

func generateRandomTLSCertificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf(i18n.Translate("generatePrivateKeyError", err))
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf(i18n.Translate("generateSerialNumberError", err))
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
		log.Fatalf(i18n.Translate("generateCertificateError", err))
	}

	certOut, err := os.Create("random_server.crt")
	if err != nil {
		log.Fatalf(i18n.Translate("createCertFileError", err))
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create("random_server.key")
	if err != nil {
		log.Fatalf(i18n.Translate("createKeyFileError", err))
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	log.Println(i18n.Translate("certSaved"))

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Print(i18n.Translate("loadCertError", err))
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
