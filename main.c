#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define FAIL    -1

#define WIN32_LEAN_AND_MEAN

SOCKET OpenConnection(char* hostname, char* port)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    printf("\nInitializing Winsock");
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(hostname, port, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    return ConnectSocket;
}


SSL_CTX* InitCTX(void)
{
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    const SSL_METHOD* method = SSLv23_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1);
    
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        //free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        //free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else {
        printf("Info: No client certificates configured.\n");
    } 
}

void releaseSocket( SSL_CTX* ctx, int server)
{
    /* close socket */
    closesocket(server);   
    /* release context */
    SSL_CTX_free(ctx);        
    putchar('\n');
}

int main(int argc, char* argv[])
{
    printf("Initializing Connection");
    char buf[1024];
    
    SSL_library_init();
    char* hostname = "google.com";
    char* portnum = "443";

    SSL_CTX* ctx = InitCTX();
    int server = OpenConnection(hostname, portnum);
    SSL* ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */


    if (SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
        const char* cpRequestMessage = "GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/7.54.0\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
       
        /* get any certs */
        ShowCerts(ssl);   
        /* encrypt & send message */
        printf("REQUEST:\n\n%s\n",cpRequestMessage);
        SSL_write(ssl, cpRequestMessage, strlen(cpRequestMessage));  

        /* get reply & decrypt */
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        int error = SSL_get_error(ssl,bytes);
        switch (error)
        {
            case SSL_ERROR_SSL:
                puts("SSL ERROR SSL");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_SYSCALL:
                puts("SSL ERROR SYSCALL");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_WANT_ASYNC_JOB:
                puts("SSL ERROR WANT ASYNC_LOOKUP");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_WANT_ASYNC:
                puts("SSL ERROR WANT X509_LOOKUP");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_WANT_X509_LOOKUP:
                puts("SSL ERROR WANT X509_LOOKUP");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_WANT_WRITE:
                puts("SSL ERROR WANT WRITE");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_WANT_READ:
                puts("SSL ERROR WANT READ");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_ZERO_RETURN:
                puts("SSL ERROR SSL_ERROR_ZERO_RETURN");
                releaseSocket(ctx,server);
                return 1;
            case SSL_ERROR_NONE:
            default:
                break;
        }
        puts("RESPONSE\n");
        for(int i=0;i<bytes;i++){
            putchar(buf[i]);
        }
        
        /* release connection state */
        SSL_free(ssl);       
    }

    releaseSocket(ctx,server);   
    putchar('\n');
    return 0;
}