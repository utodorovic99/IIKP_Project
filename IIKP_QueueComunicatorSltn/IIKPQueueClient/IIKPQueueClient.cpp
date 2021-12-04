#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

#include "Networking.h"

#pragma comment(lib, "Ws2_32.lib")

NETWORKING_PARAMS* networkParams = NULL;

int main()
{
    errno = 0;
    WSAData wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
        errno = 1; return 0;
    }  // WSA Failed 

    networkParams = (NETWORKING_PARAMS*)malloc(sizeof(networkParams));
    LoadNetworkingParams(networkParams);
    free(networkParams);
    WSACleanup();
    char output=getchar();
}



