#include "TLS_Client.hpp"

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

TLS_Client Test;

int main(void)
{
    int len = strlen(GET_REQUEST);
    Test.Connect("ya.ru", 443);
    Test.Send((uint8_t *) GET_REQUEST, len);
    sleep(5);
    Test.Disconnect();

    return 0;
}