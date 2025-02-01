#include <iostream>
#include <fstream>
#include "socket_utils.h"
#include "ssl_utils.h"
#include <pthread.h>
#include <atomic>
#include <windows.h>
#include <Mmsystem.h>

#define BUFFER_SIZE 2048

std::atomic<bool> connected(true); // Use atomic flag to control thread execution
SSL *ssl;

void fileSend()
{
    std::string file_path = receiveSecureMessage(ssl);
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        sendSecureMessage(ssl, "0");
        return;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    sendSecureMessage(ssl, std::to_string(file_size));
    // std::cout << "Size sent" << std::endl;

    char buffer[BUFFER_SIZE];
    // std::cout << "Start sending...size=" << file_size << std::endl;
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        std::string chunk(buffer, file.gcount());
        sendSecureMessage(ssl, chunk);
    }
    // std::cout << "Finished sending..." << std::endl;
    sendSecureMessage(ssl, "FILE_END");
    file.close();
}

void fileReceive()
{
    std::string file_name = receiveSecureMessage(ssl);
    std::string file_size_str = receiveSecureMessage(ssl);
    std::streamsize file_size = std::stoll(file_size_str);

    std::ofstream file(file_name, std::ios::binary);

    char buffer[BUFFER_SIZE];
    std::streamsize bytes_received = 0;

    // std::cout << "Start receiving...size=" << file_size << std::endl;
    while (bytes_received < file_size)
    {
        std::string chunk = receiveSecureMessage(ssl);
        if (chunk == "FILE_END")
        {
            sendSecureMessage(ssl, "RECEIVED_FAILED");
            file.close();
            break;
        }
        file.write(chunk.data(), chunk.size());
        bytes_received += chunk.size();
    }
    if (receiveSecureMessage(ssl) == "FILE_END")
    {
        file.close();
        // std::cout << "Received file successfully." << std::endl;
    }
}

void *receiveMessages(void *arg)
{
    while (connected)
    {
        std::string server_reply = receiveSecureMessage(ssl);
        if (!(server_reply).empty())
        {
            std::cout << server_reply << std::endl;
            if (server_reply == "Socket Disconnected.")
            {
                connected = false;
                printf("The socket is now closed. Press enter to continue. ");
                break;
            }
            else if (server_reply == "FILE_SENDING")
            {
                fileSend();
            }
            else if (server_reply == "FILE_RECEIVING")
            {
                fileReceive();
            }
            else if (server_reply == "PLAY_AUDIO")
            {
                std::string filePath = receiveSecureMessage(ssl);
                std::wstring wideFilePath(filePath.begin(), filePath.end());
                LPCWSTR sw = wideFilePath.c_str();
                PlaySound(filePath.c_str(), NULL, SND_FILENAME | SND_ASYNC);
                std::cout << "Audio streaming..." << std::endl;
            }
        }
        Sleep(50); // To avoid busy-waiting
    }
    return nullptr;
}

void *sendMessages(void *arg)
{
    char message[BUFFER_SIZE];
    while (connected)
    {
        std::cin.getline(message, BUFFER_SIZE);
        if (!connected)
        {
            break;
        }
        sendSecureMessage(ssl, message);
    }
    return nullptr;
}

int main()
{
    // Initialize Winsock & Create socket
    initOpenSSL();
    SOCKET clientSocket = createSocket();

    // Define server details
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(8888);

    connectToServer(clientSocket, server);

    SSL_CTX *ctx = createContext(false);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl = createSSL(ctx, clientSocket);
    performSSLClientHandshake(ssl);

    // Start the sending and receiving threads
    pthread_t receiveThread, sendThread;
    pthread_create(&receiveThread, nullptr, receiveMessages, nullptr);
    pthread_create(&sendThread, nullptr, sendMessages, nullptr);

    // Wait for threads to finish
    pthread_join(receiveThread, nullptr);
    pthread_join(sendThread, nullptr);

    cleanupSSL(ssl, ctx);
    closesocket(clientSocket);
    WSACleanup();
    return 0;
}