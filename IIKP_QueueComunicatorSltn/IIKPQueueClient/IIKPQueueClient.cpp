#pragma comment(lib, "Ws2_32.lib")

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

#include "Networking.h"

int main()
{
    LoadNetworkingParams();
    getchar();
}



