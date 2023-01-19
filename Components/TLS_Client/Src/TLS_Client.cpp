#include "TLS_Client.hpp"


#define ERROR_CREATE_THREAD -11
#define ERROR_JOIN_THREAD   -12
#define SUCCESS        0

#ifndef UNUSED
#define UNUSED(X) (void)X
#endif

#define mbedtls_printf printf
#define mbedtls_fprintf    fprintf

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}


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
    const char *pers = "ssl_client1";
    int ret;

    char port_str[16];

    snprintf(port_str, sizeof(port_str), "%d", port);


    mbedtls_entropy_init(&Hclient.entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&Hclient.ctr_drbg, mbedtls_entropy_func, &Hclient.entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }


    printf("Trying to connect to %s:%d...\r\n", host, port);

    if ((ret = mbedtls_net_connect(&Hclient.Context, host,
                                   port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
    }
    else
    {
        mbedtls_printf("Connect ok\r\n");
    }


        fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&Hclient.conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&Hclient.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&Hclient.conf, mbedtls_ctr_drbg_random, &Hclient.ctr_drbg);
    mbedtls_ssl_conf_dbg(&Hclient.conf, my_debug, stdout);

    if ((ret = mbedtls_ssl_setup(&Hclient.ssl, &Hclient.conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
    }

    if ((ret = mbedtls_ssl_set_hostname(&Hclient.ssl, host)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
    }

    mbedtls_ssl_set_bio(&Hclient.ssl, &Hclient.Context, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_handshake(&Hclient.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
        }

        status = -1;
        mbedtls_ssl_close_notify(&Hclient.ssl);
    }
    else
    {

    mbedtls_printf(" ok\n");

    
    pthread_mutex_init(&Hclient.Mutex, NULL);

    status = pthread_create(&ReceiveTask, NULL, [] (void *args)->void*
    {
        ClientArg *hcl = (ClientArg *) args;
        char buf[BUFFER_SIZE];
        #if defined(_WIN32) || defined(_WIN64)
        int err;
        #endif
        int len = 0;
        int ret = 0;
        hcl->KeepLooping = true;
        printf("Receive thread was started\r\n");

        do
        {


            len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));
            ret = mbedtls_ssl_read(&hcl->ssl, (unsigned char *) buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                hcl->KeepLooping = false;
            }
            else if (ret < 0) {
                mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
                hcl->KeepLooping = false;
            }

            else if (ret == 0) {
                mbedtls_printf("\n\nEOF\n\n");
                hcl->KeepLooping = false;
            }
            else
            {
                len = ret;
                mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

                if (hcl->Observer)
                {
                    hcl->Observer->OnTcpReceived(hcl->Self, (uint8_t *)buf, len);
                }
            }
            pthread_mutex_unlock(&hcl->Mutex);
        }
        while (hcl->KeepLooping);

        
        mbedtls_ssl_close_notify(&hcl->ssl);

        mbedtls_net_free(&hcl->Context);

        mbedtls_ssl_free(&hcl->ssl);
        mbedtls_ssl_config_free(&hcl->conf);
        mbedtls_ctr_drbg_free(&hcl->ctr_drbg);
        mbedtls_entropy_free(&hcl->entropy);

        hcl->Context.fd = SOCKET_ERROR;

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

        while(hcl->KeepLooping)
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
    int ret = 0;


    while ((ret = mbedtls_ssl_write(&Hclient.ssl, data, len)) <= 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        }
    }

    return err;
}