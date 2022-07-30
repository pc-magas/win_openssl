#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

int createUnixTCPCLientSocket(const char* host,unsigned int port)
{
    struct hostent *phe;
    struct servernt *pse;
    struct sockaddr_in sin;

    
}