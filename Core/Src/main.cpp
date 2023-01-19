#include "TLS_Client.hpp"

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

TLS_Client Test;

int main(void)
{
    int len = strlen(GET_REQUEST);
    Test.Connect("ya.ru", 443);
    Test.Send((uint8_t *) GET_REQUEST, len);
    sleep(2);
    Test.Disconnect();
    sleep(2);

    return 0;
}