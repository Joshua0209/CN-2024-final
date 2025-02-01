#include "socket_utils.h"
#include <iostream>

#define BUFFER_SIZE 2048

SOCKET createSocket()
{
    WSADATA wsa;
    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        exit(1);
    }
    printf("Winsock initialized.\n");
    std::cout << "The status: " << wsa.szSystemStatus << std::endl;

    SOCKET self_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (self_socket == INVALID_SOCKET)
    {
        printf("Could not create socket : %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    printf("Socket created.\n");
    return self_socket;
}

void bindSocket(SOCKET &server_socket, struct sockaddr_in &server)
{
    if (bind(server_socket, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        printf("Bind failed with error code : %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        exit(1);
    }
    printf("Bind done.\n");
}

void listenForConnections(SOCKET &server_socket)
{
    if (listen(server_socket, 3) == SOCKET_ERROR)
    {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        exit(1);
    }
    printf("Listening for incoming connections...\n");
}

SOCKET acceptClientConnection(SOCKET &server_socket)
{
    SOCKET client_socket = accept(server_socket, NULL, NULL);
    if (client_socket == INVALID_SOCKET)
    {
        printf("Accept failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        exit(1);
    }
    printf("Connection accepted.\n");
    return client_socket;
}

void connectToServer(SOCKET &s, struct sockaddr_in &server)
{
    if (connect(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        printf("Connection error\n");
        WSACleanup();
        exit(1);
    }
    printf("Connected to server.\n");
}

void sendPlainMessage(SOCKET &client_socket, const char *message)
{
    if (send(client_socket, message, (int)strlen(message), 0) == SOCKET_ERROR)
    {
        printf("Send failed\n");
        exit(1);
    }
}

std::string *receivePlainMessage(SOCKET &client_socket)
{
    char reply[BUFFER_SIZE];
    int reply_size = recv(client_socket, reply, BUFFER_SIZE, 0);
    if (reply_size == SOCKET_ERROR)
    {
        printf("Receive failed\n");
        exit(1);
    }
    reply[reply_size] = '\0';
    std::string *str_ptr = new std::string(reply);
    return str_ptr;
}
