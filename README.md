# Computer Network Project -- Chatroom
## Setup
1. Environment: Windows
2. navigate to the folder
3. Run the following command in each side
```shell
g++ server.cpp socket_utils.cpp ssl_utils.cpp ClientHandler.cpp -o server -lws2_32 -lssl -lcrypto
.\server.exe

g++ client.cpp socket_utils.cpp ssl_utils.cpp -o client -lws2_32 -lssl -lcrypto -lwinmm
.\client.exe
```

## Usage Guide
1. Register an account
2. Login the account
3. Logout the account
4. The next time you run the `server.exe` and `client.exe`, you can directly login the account
5. After login, you can send a message, transfer a file, stream an audio to other online clients

### Reference
- Winsocks documentation
- OpenSSL documentation
- pthreads documentation
- C++ documentation
- StackOverflow
- ChatGPT