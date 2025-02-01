#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <winsock2.h>

// OpenSSL Initialization and Context Management
void initOpenSSL();
SSL_CTX *createContext(bool server);
void configureContext(SSL_CTX *ctx, const char *certPath, const char *keyPath);

// SSL Object and Handshake
SSL *createSSL(SSL_CTX *ctx, SOCKET sock);
void performSSLHandshake(SSL *ssl);
void performSSLClientHandshake(SSL *ssl);

// Secure Data Transmission
void sendSecureMessage(SSL *ssl, const std::string &message);
std::string receiveSecureMessage(SSL *ssl);

// Cleanup
void cleanupSSL(SSL *ssl, SSL_CTX *ctx);

#endif // SSL_UTILS_H
