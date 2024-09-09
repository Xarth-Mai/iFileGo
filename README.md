# iFileGo

A fast and secure file transfer assistant built in Golang, leveraging the QUIC protocol.

一个基于Golang开发的快速文件传输助手，利用QUIC协议提供快速、安全的文件传输体验。

## 💡 Features

- Fast file transfer using QUIC protocol
- Secure file transfer with TLS encryption
- Easy to use with a simple command-line interface
- 使用QUIC协议快速传输文件
- 通过TLS加密实现安全文件传输
- 简单易用的命令行界面

## 🪤 Build

```bash
git clone https://github.com/Xarth-Mai/iFileGo.git
cd iFileGo
go build
```

## 📝 Usage

1. Place your TLS certificate files in the same directory as the executable, named `server.crt` and `server.key`.
- If not provided, the program will generate random certificates.
- Only the server needs this step.

2. Run it:

   ```bash
   ./iFileGo
   ```

#

1. 将TLS证书文件放在可执行文件所在目录，并命名为 `server.crt` 和 `server.key`。
- 如果不提供，程序会生成随机证书
- 只有服务端需要这步

2. 运行：

   ```bash
   ./iFileGo
   ```

## 🌐 i18n

- [x] English
- [x] 简体中文
- [x] 繁体中文
- [x] 日本語

## 🛠 License

This project is licensed under the [MPL License](https://github.com/Xarth-Mai/iFileGo#MPL-2.0-1-ov-file)