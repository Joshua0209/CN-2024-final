#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <winsock2.h>
#include <string>

SOCKET createSocket();
void bindSocket(SOCKET &server_socket, struct sockaddr_in &server);
void listenForConnections(SOCKET &server_socket);
SOCKET acceptClientConnection(SOCKET &server_socket);
void connectToServer(SOCKET &s, struct sockaddr_in &server);
void sendPlainMessage(SOCKET &client_socket, const char *message);
std::string *receivePlainMessage(SOCKET &client_socket);

#endif // SOCKET_UTILS_H
