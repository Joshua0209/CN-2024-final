#include "ClientHandler.h"
#include "ssl_utils.h"
#include <iostream>
#include <fstream>
#include <tuple>

ClientHandler::LoginBeforePhase::LoginBeforePhase(SSL *ssl) : client_ssl(ssl) {}

std::string ClientHandler::LoginBeforePhase::handle()
{
    sendSecureMessage(client_ssl, "Welcome to the application!\n");
    while (true)
    {
        sendSecureMessage(client_ssl, "Please select an option\n1) Register \n2) Login\n3) Disconnect");

        std::string client_reply = receiveSecureMessage(client_ssl);
        std::cout << "Client: " << client_reply << std::endl;

        if (client_reply == "1")
        {
            registration();
        }
        else if (client_reply == "2")
        {
            auto [success, user] = login();
            if (success == 1)
            {
                std::cout << user << " login" << std::endl;
                return user;
            }
        }
        else if (client_reply == "3")
        {
            sendSecureMessage(client_ssl, "Socket Disconnected.");
            return "";
        }
        else
        {
            sendSecureMessage(client_ssl, "Invalid input. Please try again.");
        }
    }
}

void ClientHandler::LoginBeforePhase::registration()
{
    sendSecureMessage(client_ssl, "Type your username and press Enter.");
    std::string client_reply = receiveSecureMessage(client_ssl);
    if ((client_reply).size() == 0)
    {
        sendSecureMessage(client_ssl, "Username cannot be empty. Please try again.");
    }
    else if (usernameExists(client_reply))
    {
        sendSecureMessage(client_ssl, "Username already exists. Please try again.");
    }
    else
    {
        std::ofstream user_file("./data/user.txt", std::ios::app);
        user_file << client_reply << std::endl;
        user_file.close();
        sendSecureMessage(client_ssl, "Registration successful!");
    }
}

std::tuple<int, std::string> ClientHandler::LoginBeforePhase::login()
{
    sendSecureMessage(client_ssl, "Type your username and press Enter.");
    std::string client_reply = receiveSecureMessage(client_ssl);

    if (usernameExists(client_reply))
    {
        sendSecureMessage(client_ssl, "Login successfully!");
        return {1, client_reply};
    }
    else
    {
        sendSecureMessage(client_ssl, "Username does not exist. Please register first.");
        return {0, client_reply};
    }
}

bool ClientHandler::LoginBeforePhase::usernameExists(const std::string &username)
{
    std::ifstream user_file("./data/user.txt");
    std::string line;
    while (std::getline(user_file, line))
    {
        if (line == username)
            return true;
    }
    return false;
}

ClientHandler::LoginAfterPhase::LoginAfterPhase(SSL *ssl) : client_ssl(ssl) {}

void ClientHandler::LoginAfterPhase::handle(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex)
{
    while (true)
    {
        sendSecureMessage(client_ssl, "Please choose an option\n1) Logout\n2) Send message\n3) File transfer\n4) Audio streaming");
        std::string client_reply = receiveSecureMessage(client_ssl);

        if (client_reply == "1")
        {
            sendSecureMessage(client_ssl, "You have logged out successfully.");
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                connectedClients.erase(username); // Remove user from connected clients
            }
            std::cout << username << " logout" << std::endl;
            return;
        }
        else if (client_reply == "2")
        {
            sendClient(username, connectedClients, clientsMutex);
        }
        else if (client_reply == "3")
        {
            fileTransfer(username, connectedClients, clientsMutex);
        }
        else if (client_reply == "4")
        {
            AudioStreaming(username, connectedClients, clientsMutex);
        }
        else
        {
            sendSecureMessage(client_ssl, "Invalid input. Please try again.");
        }
    }
}

void ClientHandler::LoginAfterPhase::sendClient(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex)
{
    sendSecureMessage(client_ssl, "Enter recipient username:");
    std::string recipient = receiveSecureMessage(client_ssl);

    sendSecureMessage(client_ssl, "Enter your message:");
    std::string message = receiveSecureMessage(client_ssl);

    std::lock_guard<std::mutex> lock(clientsMutex);
    if (connectedClients.find(recipient) == connectedClients.end() || username == recipient)
    {
        sendSecureMessage(client_ssl, "Recipient not found or not online.");
        return;
    }

    SSL *recipientSSL = connectedClients[recipient];
    sendSecureMessage(recipientSSL, (username + ": " + message).c_str());
    sendSecureMessage(client_ssl, "Message sent successfully.");
}

void ClientHandler::LoginAfterPhase::fileTransfer(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex)
{
    sendSecureMessage(client_ssl, "Enter recipient username:");
    std::string recipient = receiveSecureMessage(client_ssl);

    sendSecureMessage(client_ssl, "Enter file path:");
    std::string file_path = receiveSecureMessage(client_ssl);
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        if (connectedClients.find(recipient) == connectedClients.end() || username == recipient)
        {
            sendSecureMessage(client_ssl, "Recipient not found or not online.");
            return;
        }
    }

    SSL *recipientSSL = connectedClients[recipient];
    sendSecureMessage(client_ssl, "FILE_SENDING");
    sendSecureMessage(client_ssl, file_path);
    std::string file_size_str = receiveSecureMessage(client_ssl);
    std::streamsize file_size = std::stoll(file_size_str);
    if (file_size == 0)
    {
        sendSecureMessage(client_ssl, "File not found.");
        return;
    }

    // Notify recipient about file details
    sendSecureMessage(recipientSSL, "FILE_RECEIVING");
    sendSecureMessage(recipientSSL, file_path);
    sendSecureMessage(recipientSSL, std::to_string(file_size));

    std::streamsize bytes_received = 0;
    while (bytes_received < file_size)
    {
        std::string chunk = receiveSecureMessage(client_ssl);
        std::cout << chunk << std::endl;
        sendSecureMessage(recipientSSL, chunk);
        bytes_received += chunk.size();
    }
    if (receiveSecureMessage(client_ssl) == "FILE_END")
    {
        std::cout << "FILE_END" << std::endl;
        sendSecureMessage(recipientSSL, "FILE_END");
    }
    sendSecureMessage(recipientSSL, "Please choose an option\n1) Logout\n2) Send message\n3) File transfer\n4) Audio streaming");
}

void ClientHandler::LoginAfterPhase::AudioStreaming(const std::string &username, std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex)
{
    sendSecureMessage(client_ssl, "Enter recipient username:");
    std::string recipient = receiveSecureMessage(client_ssl);

    sendSecureMessage(client_ssl, "Enter streaming audio file path:");
    std::string file_path = receiveSecureMessage(client_ssl);

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        if (connectedClients.find(recipient) == connectedClients.end() || username == recipient)
        {
            sendSecureMessage(client_ssl, "Recipient not found or not online.");
            return;
        }
    }

    SSL *recipientSSL = connectedClients[recipient];
    sendSecureMessage(client_ssl, "FILE_SENDING");
    sendSecureMessage(client_ssl, file_path);
    std::string file_size_str = receiveSecureMessage(client_ssl);
    std::streamsize file_size = std::stoll(file_size_str);
    if (file_size == 0)
    {
        sendSecureMessage(client_ssl, "File not found.");
        return;
    }

    // Notify recipient about file details
    sendSecureMessage(recipientSSL, "FILE_RECEIVING");
    sendSecureMessage(recipientSSL, file_path);
    sendSecureMessage(recipientSSL, std::to_string(file_size));

    std::streamsize bytes_received = 0;
    while (bytes_received < file_size)
    {
        std::string chunk = receiveSecureMessage(client_ssl);
        std::cout << chunk << std::endl;
        sendSecureMessage(recipientSSL, chunk);
        bytes_received += chunk.size();
    }
    if (receiveSecureMessage(client_ssl) == "FILE_END")
    {
        std::cout << "FILE_END" << std::endl;
        sendSecureMessage(recipientSSL, "FILE_END");
    }
    sendSecureMessage(recipientSSL, "PLAY_AUDIO");
    sendSecureMessage(recipientSSL, file_path);
    sendSecureMessage(recipientSSL, "Please choose an option\n1) Logout\n2) Send message\n3) File transfer\n4) Audio streaming");
}

ClientHandler::ClientHandler(SSL *ssl) : client_ssl(ssl) {}

void ClientHandler::run(std::map<std::string, SSL *> &connectedClients, std::mutex &clientsMutex)
{
    LoginBeforePhase login_before_phase(client_ssl);
    LoginAfterPhase login_after_phase(client_ssl);

    while (true)
    {
        std::string username = login_before_phase.handle();
        if (username.empty())
        {
            SSL_shutdown(client_ssl);
            SSL_free(client_ssl);
            std::cout << "Client disconnected" << std::endl;
            return;
        }
        else
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients[username] = client_ssl; // Add user to connected clients
        }

        login_after_phase.handle(username, connectedClients, clientsMutex);

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients.erase(username); // Remove user after logout
        }
    }
}