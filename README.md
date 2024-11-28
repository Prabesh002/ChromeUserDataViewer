# ChromeUserDataViewer
 A simple App to display your chrome contents using C

# Chrome Password Data Retriever

## 🔍 Project Overview

This is a C-based tool for retrieving saved login information from Google Chrome's local SQLite database. The application can extract usernames and URLs from Chrome's login database, demonstrating basic system interaction and data retrieval techniques.

**⚠️ Important Note:** This tool is for educational purposes only. Always respect privacy and legal guidelines when working with personal data.

## 🛠 Prerequisites

### Requirements
- Windows Operating System
- Microsoft Visual Studio or MinGW with C compiler
- SQLite3 library
- Windows Cryptography API

### Required Libraries
- sqlite3.h
- windows.h
- wincrypt.h

## 🚀 Compilation

### Visual Studio
1. Create a new C console project
2. Add the source file
3. Link required libraries:
   - sqlite3.lib
   - crypt32.lib

### MinGW
```bash
gcc -o chrome_data_retriever main.c -lsqlite3 -lcrypt32
```
OR if you have make installed just do

```
make
```

## 🔧 Features

- Retrieves saved login URLs
- Extracts username values
- Demonstrates Windows cryptography decryption
- Simple console-based interface

## ⚠️ Limitations

- Password decryption might not work for all Chrome versions
- No password decryption for some encrypted entries

## 🧑‍💻 How It Works

1. Locates Chrome's Login Data file in user profile
2. Connects to SQLite database
3. Queries login information
4. Attempts to decrypt password values
5. Displays retrieved data in console

## 🔒 Security and Privacy

- **Do Not** use this tool to access others' private data
- Intended for personal learning and research
- Always obtain proper consent before accessing personal information

## 📜 License

See the liscences tab

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 📞 Support

For issues or questions, please open a GitHub issue.
