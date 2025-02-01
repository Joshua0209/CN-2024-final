#include "ssl_utils.h"
#include <iostream>
#include <cstdlib>

#define BUFFER_SIZE 2048

// Initialize OpenSSL library
void initOpenSSL()
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
}

// Create and configure an SSL context
SSL_CTX *createContext(bool server)
{
    const SSL_METHOD *method = server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Load certificate and private key into the SSL context
void configureContext(SSL_CTX *ctx, const char *certPath, const char *keyPath)
{
    if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Create an SSL object for a specific socket
SSL *createSSL(SSL_CTX *ctx, SOCKET sock)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        std::cerr << "SSL_new failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, static_cast<int>(sock));
    return ssl;
}

// Perform SSL handshake for a server socket
void performSSLHandshake(SSL *ssl)
{
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    std::cout << "SSL Handshake successful" << std::endl;
}

// Perform SSL handshake for a client socket
void performSSLClientHandshake(SSL *ssl)
{
    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    std::cout << "SSL Client Handshake successful" << std::endl;
}

// Send a message securely via SSL
void sendSecureMessage(SSL *ssl, const std::string &message)
{
    if (SSL_write(ssl, message.c_str(), static_cast<int>(message.length())) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
}

// Receive a message securely via SSL
std::string receiveSecureMessage(SSL *ssl)
{
    char buffer[BUFFER_SIZE] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }
    return std::string(buffer, bytes);
}

// Cleanup SSL object and free context
void cleanupSSL(SSL *ssl, SSL_CTX *ctx)
{
    if (ssl)
        SSL_shutdown(ssl);
    SSL_free(ssl);

    if (ctx)
        SSL_CTX_free(ctx);
    std::cout << "SSL shutdowned" << std::endl;
}
