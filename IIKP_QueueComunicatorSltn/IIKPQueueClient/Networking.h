#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"

#include <direct.h>                               // Windows supported only
#define GetCurrentDir _getcwd

using namespace std;

#pragma region Data

    typedef struct SOCKET_PARAMS
    {
        unsigned short port;                      // Socket port
        unsigned address_ipv4;                    // IPv4 address                                
    } SOCKETPARAMS;

    typedef struct TCPNETWORK_PARAMS
    {
        unsigned short listen_socket_units;       // Number of listen sockets
        SOCKETPARAMS* listen_socket_params;       // Array of listen socket params

        unsigned short accept_socket_units;       // Number of accept sockets
        SOCKETPARAMS* accept_socket_params;       // Array of accept socket params
        char* accept_socket_contexts;             // Array of accept socket context roles
    } TCPNETWORK_PARAMS;

    typedef struct UDPNETWORK_PARAMS
    {
        unsigned short accept_socket_units;       // Number of accept sockets 
        SOCKETPARAMS* accept_socket_params;       // Array of accept socket params
        char* accept_socket_contexts;             // List of accept socket context roles
    } UDPNETWORK_PARAMS;
    //Note: Prefix accept used for sake of consistency, even though UDP has no listen sockets

    typedef struct NETWORKING_PARAMS
    {
        TCPNETWORK_PARAMS* tcp_params;            // Pointer to tcp_params, null if not found
        UDPNETWORK_PARAMS* udp_params;            // Pointer to udp_params, null if not found
    } NETWORKING_PARAMS;

#pragma endregion

#pragma region FunctionsDecl

    // Loads network parameters from NetworkCfg.txt
    // Returns pointer to NETWORKING_PARAMS structure (see in Data section above),
    // null if file is not found or corrupted
    void LoadNetworkingParams(NETWORKING_PARAMS** networkParams);
#pragma endregion

#pragma region FunctionsImpl
    // Initializes WinSock2 library
    // Returns true if succeeded, false otherwise.
    bool InitializeWindowsSockets()
    {
        WSADATA wsaData;
        // Initialize windows sockets library for this process
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            printf("WSAStartup failed with error: %d\n", WSAGetLastError());
            return false;
        }
        return true;
    }

    void SafeFileClose(FILE** file)
    {
        if(file != NULL && *file!=NULL)fclose(*file);
    }

    void LoadNetworkingParams(NETWORKING_PARAMS** networkParams)
    {
        *networkParams = NULL;
        char cCurrentPath[FILENAME_MAX];
        if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
            return ;

        while (cCurrentPath[strlen(cCurrentPath) - 1] != '\\')
        cCurrentPath[strlen(cCurrentPath) - 1] = '\0';

        strcat_s(cCurrentPath, "\\Release\\NetworkCfg.txt");  

        cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
        //Append config file name

        FILE* fptr = NULL;
        fopen_s(&fptr, cCurrentPath, "rb");
        if (!fptr)
            return;
        //Configuration file not found

        int buffSize = 255;
        char* buff=(char*)(malloc(buffSize));
        char* preBuff = (char*)(malloc(buffSize));
        memset(preBuff, buffSize, buffSize);
        bool isFirstLine = true;

        while (fgets(buff, buffSize, fptr))
        {
            if (strstr(buff, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                while (!strstr(buff, "#"))
                    fgets(buff, buffSize, fptr);

                //Trim Skip section ending
                unsigned clsIdx = 0;
                for (clsIdx; clsIdx < buffSize; ++clsIdx)
                {
                    if (buff[clsIdx] == EOF) return;
                    else if (buff[clsIdx] == '#')
                    {
                        ++clsIdx;
                        if (clsIdx < buffSize - 1)                  //If not end
                            sprintf(buff, "%s\0", buff + clsIdx);  //Copy everything after # in buff (trim)
                        break;
                    }
                }
            }
            else
            {
                if (strstr(buff, "%PROTOCOL"))
                else if()
            }
            
            isFirstLine = false;
            memcpy(preBuff, buff, buffSize);
        }
        free(buff);

        SafeFileClose(&fptr);      
    }

#pragma endregion


