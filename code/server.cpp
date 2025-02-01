#include <iostream>
#include <queue>
#include <vector>
#include <map>
#include <pthread.h>
#include <mutex>
#include <condition_variable>
#include "ClientHandler.h"
#include "socket_utils.h"
#include "ssl_utils.h"

#define MAX_WORKERS 10

// Task Queue
std::queue<SSL *> taskQueue;
std::mutex queueMutex;
std::condition_variable taskNotifier;

std::map<std::string, SSL *> connectedClients;
std::mutex clientsMutex;

// Worker Function
void *workerFunction(void *arg)
{
    while (true)
    {
        SSL *ssl;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            taskNotifier.wait(lock, []
                              { return !taskQueue.empty(); });

            ssl = taskQueue.front();
            taskQueue.pop();
        }

        // Handle client interaction
        ClientHandler client(ssl);
        client.run(connectedClients, clientsMutex);
    }
}

// Main server initialization and task submission
SOCKET initServer(const char *host = "127.0.0.1", int port = 8888)
{
    SOCKET serverSocket = createSocket();

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(port);

    bindSocket(serverSocket, server);
    listenForConnections(serverSocket);

    return serverSocket;
}

int main()
{
    // Initialize server
    initOpenSSL();
    SSL_CTX *ctx = createContext(true);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    configureContext(ctx, "data/cert.pem", "data/key.pem");

    SOCKET serverSocket = initServer();

    // Create worker threads
    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; ++i)
    {
        pthread_create(&workers[i], nullptr, workerFunction, nullptr);
    }

    // Accept clients and assign tasks
    while (true)
    {
        SOCKET clientSocket = acceptClientConnection(serverSocket);
        SSL *ssl = createSSL(ctx, clientSocket);
        performSSLHandshake(ssl);
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            taskQueue.push(ssl);
        }
        taskNotifier.notify_one(); // Notify a worker
    }

    // Shutdown server
    closesocket(serverSocket);
    SSL_CTX_free(ctx);
    WSACleanup();
    // Join all worker threads
    for (int i = 0; i < MAX_WORKERS; ++i)
    {
        pthread_join(workers[i], nullptr);
    }
    return 0;
}