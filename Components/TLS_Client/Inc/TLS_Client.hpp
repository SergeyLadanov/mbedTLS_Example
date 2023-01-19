#ifndef __TLS_CLIENT_HPP_
#define __TLS_CLIENT_HPP_


#include <cstdint>
#include <sys/types.h>
//#include <winsock.h>
#include <cstdio>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)//Windows includes
#include <winsock.h>
#else
#include <sys/socket.h> //Add support for sockets
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <pthread.h>

#ifdef __linux__
#define INVALID_SOCKET (-1)
#define SOCKET int
#define SOCKET_ERROR (-1)
#else
typedef int socklen_t;
#endif

class TLS_Client
{
public:

    class IObserver
    {
    public:
        virtual void OnTcpReceived(TLS_Client *obj, uint8_t *buf, uint32_t len) = 0;
        virtual void OnTcpConnected(TLS_Client *obj) = 0;
        virtual void OnTcpDisconnected(TLS_Client *obj) = 0;
        virtual void TcpPollConnectionl(TLS_Client *obj) = 0;
    };

private:
    static constexpr size_t BUFFER_SIZE = 1024;

    struct ClientArg
    {
        mbedtls_net_context Context;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;

        IObserver *Observer;
        bool KeepLooping;
        pthread_mutex_t Mutex;

        TLS_Client *Self = nullptr;

        bool IsConnected()
        {
            return (Context.fd != SOCKET_ERROR);
        }
    };

    pthread_t ReceiveTask;
    pthread_t PollTask;

    ClientArg Hclient;
    

public:
    TLS_Client()
    {
        memset(&Hclient, 0, sizeof(ClientArg));
        Hclient.Context.fd = SOCKET_ERROR;
        Hclient.Self = this;

        mbedtls_net_init(&Hclient.Context);
        mbedtls_ssl_init(&Hclient.ssl);
        mbedtls_ssl_config_init(&Hclient.conf);
        mbedtls_ctr_drbg_init(&Hclient.ctr_drbg);
    }
    int Connect(const char *host, uint16_t port);
    bool IsConnected(void);
    int Send(uint8_t *data, uint32_t len);
    void BindObserver(IObserver *obj)
    {
        Hclient.Observer = obj;
    }
    void Disconnect(void)
    {
// #if defined(_WIN32) || defined(_WIN64)//Windows includes
//         closesocket(Hclient.Context.fd);
// #else
//         close(Hclient.Fd);
// #endif
        Hclient.Context.fd = SOCKET_ERROR;
        Hclient.KeepLooping = false;
    }
private:
    static char* DomainIP(const char *domain);
    static void error(const char *msg);
};

#endif