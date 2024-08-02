package main

var translations = map[string]map[string]string{
	"en": {
		"version":                    "iFileGo V%s\n",
		"selectMode":                 "Please select: 1 - %s, 0 - %s: ",
		"invalidChoice":              "Invalid choice, please enter 1 or 0.",
		"exitPrompt":                 "Press any key to exit...",
		"serverListening":            "Server listening on port %d...\n",
		"listeningError":             "Error listening on port: %v\n",
		"connectionError":            "Error establishing connection: %v\n",
		"connectedTo":                "Connected to %s\n",
		"receiveMode":                "Receive Mode",
		"sendMode":                   "Send Mode",
		"serverMode":                 "Server Mode",
		"clientMode":                 "Client Mode",
		"continueTransfer":           "Continue Transfer",
		"endSession":                 "End Session",
		"endProgram":                 "End Program",
		"enterFilePath":              "Enter the file path to send: ",
		"filePathError":              "Error reading file path: %v",
		"fileOpenError":              "Error opening file: %v",
		"negotiateModeError":         "Error negotiating transfer mode: %v",
		"streamOpenError":            "Error opening stream: %v",
		"streamReceiveError":         "Error receiving stream: %v",
		"fileStatError":              "Error getting file info: %v",
		"sendFileNameLengthError":    "Error sending file name length: %v",
		"sendFileNameError":          "Error sending file name: %v",
		"sendFileSizeError":          "Error sending file size: %v",
		"sendFileContentError":       "Error sending file content: %v",
		"fileSent":                   "File %s sent successfully\n",
		"receiveFileContentError":    "Error receiving file content: %v",
		"receiveFileNameLengthError": "Error receiving file name length: %v",
		"receiveFileNameError":       "Error receiving file name: %v",
		"receiveFileSizeError":       "Error receiving file size: %v",
		"createFileError":            "Error creating file: %v",
		"writeFileError":             "Error writing file content: %v",
		"fileReceived":               "File received: %s, size: %d bytes\n",
		"readInputError":             "Error reading input: %v\n",
		"getServerAddress":           "Enter server address: ",
		"invalidIP":                  "Please enter a valid domain or IP\n",
		"verifyIPCrt":                "Verify IP certificate",
		"skipVerify":                 "Skip verification",
		"normalClose":                "Normal Close",
		"generatePrivateKeyError":    "Unable to generate private key: %v\n",
		"generateSerialNumberError":  "Unable to generate serial number: %v\n",
		"generateCertificateError":   "Unable to generate certificate: %v\n",
		"createCertFileError":        "Unable to create certificate file: %v\n",
		"createKeyFileError":         "Unable to create key file: %v\n",
		"certSaved":                  "Randomly generated TLS certificates saved as random_server.crt and random_server.key",
		"loadCertError":              "Unable to load TLS certificate: %v. Generating a new pair of certificates",
	},
	"jp": {
		"version":                    "iFileGo V%s\n",
		"selectMode":                 "選択してください: 1 - %s, 0 - %s: ",
		"invalidChoice":              "無効な選択です。1または0を入力してください。",
		"exitPrompt":                 "任意のキーを押して終了...",
		"serverListening":            "サーバーがポート %d で待機中...\n",
		"listeningError":             "ポートの待機中にエラーが発生しました: %v\n",
		"connectionError":            "接続中にエラーが発生しました: %v\n",
		"connectedTo":                "%s に接続しました\n",
		"receiveMode":                "受信モード",
		"sendMode":                   "送信モード",
		"serverMode":                 "サーバーモード",
		"clientMode":                 "クライアントモード",
		"continueTransfer":           "転送を続ける",
		"endSession":                 "セッションを終了",
		"endProgram":                 "プログラムを終了",
		"enterFilePath":              "送信するファイルパスを入力してください: ",
		"filePathError":              "ファイルパスの読み込みエラー: %v",
		"fileOpenError":              "ファイルを開くエラー: %v",
		"negotiateModeError":         "転送モード交渉エラー: %v",
		"streamOpenError":            "ストリームのオープンエラー: %v",
		"streamReceiveError":         "ストリーム受信エラー: %v",
		"fileStatError":              "ファイル情報取得エラー: %v",
		"sendFileNameLengthError":    "ファイル名長さエラー: %v",
		"sendFileNameError":          "ファイル名エラー: %v",
		"sendFileSizeError":          "ファイルサイズエラー: %v",
		"sendFileContentError":       "ファイル内容エラー: %v",
		"fileSent":                   "ファイル %s が正常に送信されました\n",
		"receiveFileContentError":    "ファイル内容の受信エラー: %v",
		"receiveFileNameLengthError": "ファイル名長さエラー: %v",
		"receiveFileNameError":       "ファイル名エラー: %v",
		"receiveFileSizeError":       "ファイルサイズエラー: %v",
		"createFileError":            "ファイル作成エラー: %v",
		"writeFileError":             "ファイル内容書き込みエラー: %v",
		"fileReceived":               "受信したファイル: %s, サイズ: %d bytes\n",
		"readInputError":             "入力読み取りエラー: %v\n",
		"getServerAddress":           "サーバーアドレスを入力してください: ",
		"invalidIP":                  "有効なドメインまたはIPを入力してください\n",
		"verifyIPCrt":                "IP証明書の検証",
		"skipVerify":                 "検証をスキップ",
		"normalClose":                "正常に終了",
		"generatePrivateKeyError":    "プライベートキーの生成に失敗しました: %v\n",
		"generateSerialNumberError":  "シリアル番号の生成に失敗しました: %v\n",
		"generateCertificateError":   "証明書の生成に失敗しました: %v\n",
		"createCertFileError":        "証明書ファイルの作成に失敗しました: %v\n",
		"createKeyFileError":         "キーファイルの作成に失敗しました: %v\n",
		"certSaved":                  "ランダムに生成されたTLS証明書が random_server.crt と random_server.key として保存されました",
		"loadCertError":              "TLS証明書の読み込みに失敗しました: %v。新しい証明書ペアを生成しています",
	},
	"zht": {
		"version":                    "iFileGo V%s\n",
		"selectMode":                 "請選擇: 1 - %s, 0 - %s: ",
		"invalidChoice":              "無效選擇，請輸入 1 或 0。",
		"exitPrompt":                 "按任意鍵退出...",
		"serverListening":            "伺服器正在監聽端口 %d...\n",
		"listeningError":             "監聽端口錯誤: %v\n",
		"connectionError":            "建立連接時出錯: %v\n",
		"connectedTo":                "已連接至 %s\n",
		"receiveMode":                "接收模式",
		"sendMode":                   "發送模式",
		"serverMode":                 "伺服器模式",
		"clientMode":                 "客戶端模式",
		"continueTransfer":           "繼續傳輸",
		"endSession":                 "結束會話",
		"endProgram":                 "結束程序",
		"enterFilePath":              "請輸入要發送的文件路徑: ",
		"filePathError":              "讀取文件路徑錯誤: %v",
		"fileOpenError":              "打開文件錯誤: %v",
		"negotiateModeError":         "協商收發模式錯誤: %v",
		"streamOpenError":            "打開流錯誤: %v",
		"streamReceiveError":         "接收流錯誤: %v",
		"fileStatError":              "獲取文件信息錯誤: %v",
		"sendFileNameLengthError":    "發送文件名長度錯誤: %v",
		"sendFileNameError":          "發送文件名錯誤: %v",
		"sendFileSizeError":          "發送文件大小錯誤: %v",
		"sendFileContentError":       "發送文件內容錯誤: %v",
		"fileSent":                   "文件 %s 發送完成\n",
		"receiveFileContentError":    "接收文件內容錯誤: %v",
		"receiveFileNameLengthError": "接收文件名長度錯誤: %v",
		"receiveFileNameError":       "接收文件名錯誤: %v",
		"receiveFileSizeError":       "接收文件大小錯誤: %v",
		"createFileError":            "創建文件錯誤: %v",
		"writeFileError":             "寫入文件內容錯誤: %v",
		"fileReceived":               "接收到文件: %s, 大小: %d bytes\n",
		"readInputError":             "讀取輸入錯誤: %v\n",
		"getServerAddress":           "請輸入伺服器地址: ",
		"invalidIP":                  "請輸入合法的域名或IP\n",
		"verifyIPCrt":                "驗證IP證書",
		"skipVerify":                 "跳過驗證",
		"normalClose":                "正常關閉",
		"generatePrivateKeyError":    "無法生成私鑰: %v\n",
		"generateSerialNumberError":  "無法生成序列號: %v\n",
		"generateCertificateError":   "無法生成證書: %v\n",
		"createCertFileError":        "無法創建證書文件: %v\n",
		"createKeyFileError":         "無法創建密鑰文件: %v\n",
		"certSaved":                  "隨機生成的TLS證書已保存為 random_server.crt 和 random_server.key",
		"loadCertError":              "無法加載TLS證書: %v。正在生成一對新的證書",
	},
	"zhs": {
		"version":                    "iFileGo V%s\n",
		"selectMode":                 "请选择: 1 - %s, 0 - %s: ",
		"invalidChoice":              "无效的选择, 请输入 1 或 0.",
		"exitPrompt":                 "按任意键退出...",
		"serverListening":            "服务端正在监听端口 %d...\n",
		"listeningError":             "监听端口出错: %v\n",
		"connectionError":            "建立连接时出错: %v\n",
		"connectedTo":                "与 %s 建立连接\n",
		"receiveMode":                "接收模式",
		"sendMode":                   "发送模式",
		"serverMode":                 "服务端模式",
		"clientMode":                 "客户端模式",
		"continueTransfer":           "继续传输",
		"endSession":                 "结束会话",
		"endProgram":                 "结束程序",
		"enterFilePath":              "请输入要发送的文件路径: ",
		"filePathError":              "读取文件路径错误: %v",
		"fileOpenError":              "打开文件错误: %v",
		"negotiateModeError":         "协商收发模式错误: %v",
		"streamOpenError":            "打开流错误: %v",
		"streamReceiveError":         "接受流错误: %v",
		"fileStatError":              "获取文件信息错误: %v",
		"sendFileNameLengthError":    "发送文件名长度错误: %v",
		"sendFileNameError":          "发送文件名错误: %v",
		"sendFileSizeError":          "发送文件大小错误: %v",
		"sendFileContentError":       "发送文件内容错误: %v",
		"fileSent":                   "文件 %s 发送完成\n",
		"receiveFileContentError":    "接收文件内容错误: %v",
		"receiveFileNameLengthError": "接收文件名长度错误: %v",
		"receiveFileNameError":       "接收文件名错误: %v",
		"receiveFileSizeError":       "接收文件大小错误: %v",
		"createFileError":            "创建文件错误: %v",
		"writeFileError":             "写入文件内容错误: %v",
		"fileReceived":               "接收到文件: %s, 大小: %d bytes\n",
		"readInputError":             "读取输入错误: %v\n",
		"getServerAddress":           "请输入服务端地址: ",
		"invalidIP":                  "请输入合法的域名或IP\n",
		"verifyIPCrt":                "验证IP证书",
		"skipVerify":                 "跳过验证",
		"normalClose":                "正常关闭",
		"generatePrivateKeyError":    "无法生成私钥: %v\n",
		"generateSerialNumberError":  "无法生成序列号: %v\n",
		"generateCertificateError":   "无法生成证书: %v\n",
		"createCertFileError":        "无法创建证书文件: %v\n",
		"createKeyFileError":         "无法创建密钥文件: %v\n",
		"certSaved":                  "随机生成的TLS证书已保存为 random_server.crt 和 random_server.key",
		"loadCertError":              "无法加载TLS证书: %v。正在生成一对新的证书",
	},
}
