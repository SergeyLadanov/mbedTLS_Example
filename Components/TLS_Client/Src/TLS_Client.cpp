#include "TLS_Client.hpp"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define ERROR_CREATE_THREAD -11
#define ERROR_JOIN_THREAD   -12
#define SUCCESS        0

#ifndef UNUSED
#define UNUSED(X) (void)X
#endif


void TLS_Client::error(const char *msg)
{
    perror(msg);
    exit(0);
}

char* TLS_Client::DomainIP(const char *domain)
{
    static char str_result[32] = {0};
    struct hostent *remoteHost;
    remoteHost = gethostbyname(domain);
    if (remoteHost)
    {
        sprintf(str_result, inet_ntoa(*( struct in_addr*)remoteHost->h_addr_list[0]));
        return str_result;
    }

    return nullptr;
}

int TLS_Client::Connect(const char *host, uint16_t port)
{
    int status = 0;
    struct sockaddr_in serv_addr;
    char *IP = nullptr;

    printf("Trying to connect to %s:%d...\r\n", host, port);

    Hclient.Fd = socket(AF_INET, SOCK_STREAM, 0);
    if (Hclient.Fd < 0)
	{
		error("ERROR opening socket");
	}

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    IP = DomainIP(host);

    if (!IP)
    {
        Hclient.Fd = INVALID_SOCKET;
        return -1;
    }

	serv_addr.sin_addr.s_addr = inet_addr(IP);
    serv_addr.sin_port = htons(port);

    if (connect(Hclient.Fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
        Hclient.Fd = INVALID_SOCKET;
        printf("ERROR connecting!\r\n");
        return -1;
	}
    
    pthread_mutex_init(&Hclient.Mutex, NULL);

    status = pthread_create(&ReceiveTask, NULL, [] (void *args)->void*
    {
        ClientArg *hcl = (ClientArg *) args;
        char buf[BUFFER_SIZE];
        #if defined(_WIN32) || defined(_WIN64)
        int err;
        #endif
        hcl->KeepLooping = true;
        printf("Receive thread was started\r\n");

        do
        {
            int read = recv(hcl->Fd, buf, BUFFER_SIZE, 0);

            pthread_mutex_lock(&hcl->Mutex);

            if (read == 0)
            {
                pthread_mutex_unlock(&hcl->Mutex);
                break;
            }

            if (read == SOCKET_ERROR)
            {
                #if defined(_WIN32) || defined(_WIN64)
                err = WSAGetLastError();
                if ((err != WSAENOTCONN) && (err != WSAECONNABORTED) && (err == WSAECONNRESET))
                    printf("Errore nella lettura dal client\n");
                #endif
                pthread_mutex_unlock(&hcl->Mutex);
                break;
            }

            hcl->Observer->OnTcpReceived(hcl->Self, (uint8_t *)buf, read);
            pthread_mutex_unlock(&hcl->Mutex);
        }
        while (hcl->KeepLooping);
        #if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(hcl->Fd);
        #else
        close(hcl->Fd);
        #endif
        hcl->Fd = INVALID_SOCKET;

        printf("Receive thread was stopped\r\n");

        return SUCCESS;
    }
    , &Hclient);


    if (status != 0) 
    {
        printf("main error: can't create thread, status = %d\n", status);
        exit(ERROR_CREATE_THREAD);
        return -1;
    }


    status = pthread_create(&PollTask, NULL, [] (void *args)->void*
    {
        ClientArg *hcl = (ClientArg *) args;
        printf("Poll thread was started\r\n");

        while(hcl->IsConnected())
        {
            sleep(1);
            pthread_mutex_lock(&hcl->Mutex);
            if (hcl->Observer != nullptr)
            {
                hcl->Observer->TcpPollConnectionl(hcl->Self);
            }
            
            pthread_mutex_unlock(&hcl->Mutex);
        }

        if (hcl->Observer != nullptr)
        {
            hcl->Observer->OnTcpDisconnected(hcl->Self);
        }
        hcl->KeepLooping = false;
        pthread_mutex_destroy(&hcl->Mutex);
        printf("Connection closed\r\n");
        return SUCCESS;
    }
    , &Hclient);

    if (status != 0) 
    {
        printf("main error: can't create thread, status = %d\n", status);
        exit(ERROR_CREATE_THREAD);
        return -1;
    }

    if (Hclient.Observer != nullptr)
    {
        Hclient.Observer->OnTcpConnected(this);
    }

    return status;
}

bool TLS_Client::IsConnected()
{
    return Hclient.IsConnected();
}


int TLS_Client::Send(uint8_t *data, uint32_t len)
{
    char *pbuf = (char *) data;
    int err = 0;

    do
    {
        int sent = send(Hclient.Fd, (char *) data, len, 0);
        if (sent == SOCKET_ERROR)
        {
            #if defined(_WIN32) || defined(_WIN64)
            err = WSAGetLastError();
            if ((err != WSAENOTCONN) && (err != WSAECONNABORTED) && (err == WSAECONNRESET))
            {
                printf("Errore nella scrittura verso il client");
            }
            #else
            err = -1;
            #endif
            Hclient.KeepLooping = false;
            break;
        }

        pbuf += sent;
        len -= sent;
    }
    while (len > 0);
    return err;
}