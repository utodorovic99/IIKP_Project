#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

#include "Networking.h"

#pragma comment(lib, "ws2_32.lib")

#pragma region IgnoreWarnings
    #pragma warning(suppress : 6387)
    #pragma warning(suppress : 6011)
    #pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
    #define MAX_MEDIATOR_BUFF_SIZE 255
#pragma endregion

NETWORKING_PARAMS* networkParams = NULL;

int main()
{
    
    WSAData wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
        printf("WSAStartup Failed\n");
        return -1;
    }
    else("WSA successfully loaded..\n");

    // Read config file
    {
        char cCurrentPath[FILENAME_MAX];
        if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
        {
            printf("NetCfg file missing, closing..\n");
            return -2;
        }
        else
            printf("Loading config data..\n");

        while (cCurrentPath[strlen(cCurrentPath) - 1] != '\\')
            cCurrentPath[strlen(cCurrentPath) - 1] = '\0';

        strcat_s(cCurrentPath, "\\Release\\NetworkCfg.txt");

        cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
        //Append config file name

        FILE* fptr = NULL;
        fopen_s(&fptr, cCurrentPath, "rb");
        if (!fptr)
        {
            printf("Opening NetCfg failed, closing..\n");
            return -2;
        }

        networkParams = (NETWORKING_PARAMS*)malloc(sizeof(networkParams));
        void* inputDataMemoryChunk = malloc(MAX_MEDIATOR_BUFF_SIZE);
        void* usedSectionEnd = NULL;

        NETWORKING_PARAMS tmpParams = LoadNetworkingParams(inputDataMemoryChunk, &fptr);

        // Ako ga procitam do kraja  pokusam fclose puca, ako procitam jednu liniju i zatvorim sve uredno.
        if (fptr != NULL)
            fclose(fptr);

            // manually realloc, realloc() would mess pointers up
            if (tmpParams.tcp_params != NULL)
            {
                networkParams->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));
                networkParams->tcp_params->listen_socket_units = tmpParams.tcp_params->listen_socket_units;
                if (tmpParams.tcp_params->listen_socket_params != NULL)
                {
                    networkParams->tcp_params->listen_socket_params = (SOCKETPARAMS*)(malloc(sizeof(SOCKETPARAMS) * networkParams->tcp_params->listen_socket_units));
                    memcpy(networkParams->tcp_params->listen_socket_params, tmpParams.tcp_params->listen_socket_params, (sizeof(SOCKETPARAMS) * networkParams->tcp_params->listen_socket_units));
                }

                networkParams->tcp_params->accept_socket_units = tmpParams.tcp_params->accept_socket_units;
                if (tmpParams.tcp_params->accept_socket_params != NULL)
                {
                    networkParams->tcp_params->accept_socket_params = (SOCKETPARAMS*)(malloc(sizeof(SOCKETPARAMS) * networkParams->tcp_params->accept_socket_units));
                    memcpy(networkParams->tcp_params->accept_socket_params, tmpParams.tcp_params->accept_socket_params, (sizeof(SOCKETPARAMS) * networkParams->tcp_params->accept_socket_units));
                }

                if (networkParams->tcp_params->accept_socket_contexts != NULL)
                {
                    networkParams->tcp_params->accept_socket_contexts = (char*)(malloc(networkParams->tcp_params->accept_socket_units));
                    memcpy(networkParams->tcp_params->accept_socket_contexts, tmpParams.tcp_params->accept_socket_contexts, networkParams->tcp_params->accept_socket_units);
                }
            }
        if (tmpParams.udp_params == NULL)
        {
            // When UDP is supported
        }
        free(inputDataMemoryChunk);
    }


    networkParams->tcp_params->Format();
    networkParams->Dispose();
    WSACleanup();
    char output=getchar();
}



