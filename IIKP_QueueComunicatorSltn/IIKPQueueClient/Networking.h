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

    // Represents socket parameters: 
    // unsigned short port for socket port
    // unsigned address_ipv4 for IPv4 address
    typedef struct SOCKET_PARAMS
    {
        unsigned short port;                      
        unsigned address_ipv4;                                                 
    } SOCKETPARAMS;

    // Represents TCP network parameters, null if protocol not supported:
    // unsigned short listen_socket_units as number of listen sockets
    // SOCKETPARAMS* listen_socket_params as array of listen socket params
    // unsigned short accept_socket_units as number of accept sockets
    // SOCKETPARAMS* accept_socket_params as array of accept socket params
    // char* accept_socket_contexts as array of accept socket context roles
    typedef struct TCPNETWORK_PARAMS
    {
        unsigned short listen_socket_units;       
        SOCKETPARAMS* listen_socket_params;       

        unsigned short accept_socket_units;       
        SOCKETPARAMS* accept_socket_params;       
        char* accept_socket_contexts;  

        void Dispose()
        {
            if(listen_socket_params != NULL)free(listen_socket_params);
            if (accept_socket_params != NULL)free(accept_socket_params);
            if (accept_socket_contexts != NULL)free(accept_socket_contexts);
        }

    } TCPNETWORK_PARAMS;

    // Represents UDP network parameters, null if protocol not supported:
    // unsigned short accept_socket_units as number of accept sockets 
    // SOCKETPARAMS* accept_socket_params as array of accept socket params
    // char* accept_socket_contexts as list of accept socket context roles
    // Note: Prefix accept used for sake of consistency, even though UDP has no listen sockets
    typedef struct UDPNETWORK_PARAMS
    {
        unsigned short accept_socket_units;       
        SOCKETPARAMS* accept_socket_params;       
        char* accept_socket_contexts;  

        void Dispose()
        {
            if (accept_socket_params != NULL)free(accept_socket_params);
            if (accept_socket_params != NULL)free(accept_socket_params);
        }
    } UDPNETWORK_PARAMS;

    // Represents network parameters for each transport layer protocol.
    // TCPNETWORK_PARAMS* as pointer to tcp_params
    // UDPNETWORK_PARAMS* as pointer to udp_params
    typedef struct NETWORKING_PARAMS
    {
        TCPNETWORK_PARAMS* tcp_params;            
        UDPNETWORK_PARAMS* udp_params;  

        void Dispose()
        {
            if (tcp_params == NULL) { tcp_params->Dispose();  free(tcp_params); }
            if (udp_params == NULL) { udp_params->Dispose();  free(udp_params); }
        }
    } NETWORKING_PARAMS;

    // Indicates status of try-parsed socket record in NetCfg.txt
    enum SocketRecordParseErrCode { OK = 0, BAD_IP, BAD_PORTS, BAD_SERVICE };
    
#pragma endregion

#pragma region FunctionsDecl

    // Loads network parameters from NetworkCfg.txt
    // Fills NETWORKING_PARAMS structure (see in Data section above), alocates if empty
    // null if file is not found or corrupted
    void LoadNetworkingParams(NETWORKING_PARAMS* networkParams);

    // Closing file in secure manner
    void SafeFileClose(FILE** file);

    // Initializes WinSock2 library
    // Returns true if succeeded, false otherwise.
    bool InitializeWindowsSockets();

    // Skips spacings ontop of the buff, length of buffSize stoping currLoc at first non-skipable element
    void SkipSpacings(char* buff, unsigned short buffSize, int* currLoc);

#pragma endregion

#pragma region FunctionsImpl

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

    void SkipSpacings(char* buff, unsigned short buffSize, int* currLoc)
    {
        while (*currLoc < buffSize && (buff[*currLoc] == ' ' || buff[*currLoc] == '\n' || buff[*currLoc] == '\t'))++currLoc;   // Skip body spacings
    }

    SocketRecordParseErrCode ParseTCPDefRecord(char* record, int length, TCPNETWORK_PARAMS* tcpParams)
    {
        bool startTagFound, ipPartFound, portsPartFound, servicePartFound, stopTagFound = 0;
        for (int byteLoc = 0; byteLoc < length; ++byteLoc)
        {
            if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacings(&record[byteLoc], length, &byteLoc);
            if (record[byteLoc] == '$') 
            { 
                if (!startTagFound)startTagFound = true;
                else stopTagFound = true;
            }

            if(startTagFound && !ipPartFound && !portsPartFound && !servicePartFound && !stopTagFound)
            
        }


        return OK;
    }

    void LoadNetworkingParams(NETWORKING_PARAMS* networkParams)
    {

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
        if (!fptr) return; //Configuration file not found

        if (networkParams == NULL) networkParams = (NETWORKING_PARAMS*)malloc(sizeof(NETWORKING_PARAMS));

        int buffSize = 255;
        char* buff=(char*)(malloc(buffSize));
        bool isFirstLine = true;

        unsigned clsIdx = 0;
        char cutCharOldVal=0;
        while (fgets(buff, buffSize, fptr))                         //Read line by line 
        {
            if (strstr(buff, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                while (!strstr(buff, "#"))
                    if(!fgets(buff, buffSize, fptr)) return;        

                //Trim Skip section ending
                clsIdx = 0;
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
            
            // Seek % starter          
            for (clsIdx; clsIdx < buffSize; ++clsIdx)   // Seek in current line
            {
                if (clsIdx == buffSize) break;          // End of line, take another one
                else if (buff[clsIdx] == EOF) return;   // End of file
                else if (buff[clsIdx] == '%')           
                {
                    ++clsIdx;
                    unsigned short protocolFoundID = 0;
                    unsigned short skipOffset=0;
                    if (clsIdx < buffSize)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if (strstr(buff, "%PROTOCOL") && fgets(buff, buffSize, fptr))
                        {
                            skipOffset = 7;
                            cutCharOldVal = buff[7];                                //Save
                            buff[7] = '\0';                                         //Cut
                            if(!strcmp(buff, " \"TCP\":"))  protocolFoundID = 1;    //Compare
                            buff[7] = cutCharOldVal;                                //Restore
                        }
                        else if (strstr(buff, "%PROTOCO") && fgets(buff, buffSize, fptr))
                        {
                            skipOffset = 8;
                            cutCharOldVal = buff[8];
                            buff[8] = '\0';
                            if (!strcmp(buff, " L \"TCP\":")) protocolFoundID = 1;
                            buff[8] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%PROTOC") && fgets(buff, buffSize, fptr))  
                        {
                            skipOffset = 9;
                            cutCharOldVal = buff[9];
                            buff[9] = '\0';
                            if (!strcmp(buff, " OL \"TCP\":")) protocolFoundID = 1;
                            buff[9] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%PROTO") && fgets(buff, buffSize, fptr))  
                        {
                            skipOffset = 10;
                            cutCharOldVal = buff[10];
                            buff[10] = '\0';
                            if (!strcmp(buff, " COL \"TCP\":")) protocolFoundID = 1;
                            buff[10] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%PROT") && fgets(buff, buffSize, fptr))  
                        {
                            skipOffset = 11;
                            cutCharOldVal = buff[11];
                            buff[11] = '\0';
                            if (!strcmp(buff, " OCOL \"TCP\":")) protocolFoundID = 1;
                            buff[11] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%PRO") && fgets(buff, buffSize, fptr))  
                        {
                            skipOffset = 12;
                            cutCharOldVal = buff[12];
                            buff[12] = '\0';
                            if (!strcmp(buff, " TOCOL \"TCP\":")) protocolFoundID = 1;
                            buff[12] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%PR") && fgets(buff, buffSize, fptr)) 
                        {
                            skipOffset = 13;
                            cutCharOldVal = buff[13];
                            buff[13] = '\0';
                            if (!strcmp(buff, " OTOCOL \"TCP\":")) protocolFoundID = 1;
                            buff[13] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%P") && fgets(buff, buffSize, fptr)) 
                        {
                            skipOffset = 14;
                            cutCharOldVal = buff[14];
                            buff[14] = '\0';
                            if (!strcmp(buff, "ROTOCOL \"TCP\":")) protocolFoundID = 1;
                            buff[14] = cutCharOldVal;
                        }
                        else if (strstr(buff, "%") && fgets(buff, buffSize, fptr))  
                        {
                            skipOffset = 15;
                            cutCharOldVal = buff[15];
                            buff[15] = '\0';
                            if (!strcmp(buff, "PROTOCOL \"TCP\":"))  protocolFoundID = 1;
                            buff[15] = cutCharOldVal;
                        }

                        if (protocolFoundID == 1) // Has TCP params
                        {
                            if (networkParams->tcp_params) networkParams->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));   // First TCP param
                            for (int loc = skipOffset; skipOffset < buffSize; ++skipOffset)
                            {
                                SkipSpacings(&buff[loc], buffSize, &loc);
                                if (buff[loc] == EOF) { networkParams->Dispose(); return; } // Bad syntax-no closing tag

                                if (buff[loc] == '{')                                                       //Seek body start
                                {
                                    // Body detected
                                    ++loc;
                                    while (loc < buffSize && (buff[loc] == ' ' || buff[loc] == '\n' || buff[loc] == '\t')) ++loc;   // Skip body spacings

                                    if (loc >= buffSize)    // If end line -> load new line
                                    {
                                        fgets(buff, buffSize, fptr);
                                        loc = 0;
                                    }

                                    
                                    else if()
                                    

                                    break;
                                }
                            }
                        }
                    }
                }
            }

            isFirstLine = false;
        }
        free(buff);
        SafeFileClose(&fptr);      
    }

#pragma endregion


