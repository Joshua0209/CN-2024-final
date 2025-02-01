#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include <string>
#include <map>
#include <mutex>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "socket_utils.h"

class ClientHandler
{
private:
    SSL *client_ssl;

    class LoginBeforePhase
    {
    private:
        SSL *client_ssl;

    public:
        LoginBeforePhase(SSL *ssl);
        std::string handle();

    private:
        void registration();
        std::tuple<int, std::string> login();
        bool usernameExists(const std::string &username);
    };

    class LoginAfterPhase
    {
    private:
        SSL *client_ssl;

    public:
        LoginAfterPhase(SSL *ssl);
        void handle(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex);

    private:
        void sendClient(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex);
        void fileTransfer(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex);
        void AudioStreaming(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex);
    };

public:
    ClientHandler(SSL *ssl);
    void run(std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex);
};

#endif
