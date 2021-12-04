#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"

#include <direct.h>                               // Windows supported only
#define GetCurrentDir _getcwd

#define REMOTE
#include <pcap.h>

using namespace std;

#pragma region Constants
    #define MAX_PORTS_PER_RECORD 8
    #define MAX_RECORD_LENGTH   255
#pragma endregion

#pragma region Data

    // Represent parsed socket-group record (see NetCfg.txt Legend section )
    //unsigned address_ipv4 as IPv4 address
    //char port_units as number of ports attached to that address hosting same service
    //unsigned short* ports as array of port numbers
    typedef struct SOCKET_GROUP_PARAMS
    {
        unsigned address_ipv4;
        char port_units;
        unsigned short* ports;
        char context_code;

        void Dispose()
        {
            if (ports != NULL)free(ports);
        }

        //Do free when done using
        void Format()
        {

            char contextStr[20];
            memset(contextStr, 0, 20);

            switch (context_code)
            {
                case 0: {sprintf_s(contextStr,"Listen Socket\0");  break; }
                case 1: {sprintf_s(contextStr, "Buffering Socket\0"); break; }
            }

            for (char loc = 0; loc < port_units; ++loc)
            {
                printf("\n%u.%u.%u.%u:%u - %s", 
                    (unsigned)(((char*)(&address_ipv4))[3]),
                    (unsigned)(((char*)(&address_ipv4))[2]),
                    (unsigned)(((char*)(&address_ipv4))[1]),
                    (unsigned)(((char*)(&address_ipv4))[0]),
                    ports[loc],
                    contextStr);
            }  
        }

    }SOCKET_GROUP_PARAMS;

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
    enum  SocketRecordParseErrCode { OK = 0, NO_IP, BAD_IP, NO_PORTS, BAD_PORTS, NO_SERVICE, BAD_SERVICE, BAD_SYNTAX, NO_OP_TAG, NO_CLS_TAG, NULL_PARAM_DETECTED };
    
#pragma endregion

#pragma region FunctionsDecl

    // Loads network parameters from NetworkCfg.txt
    // Fills NETWORKING_PARAMS structure (see in Data section above), alocates if empty
    // null if file is not found or corrupted
    void LoadNetworkingParams(NETWORKING_PARAMS* networkParams);

    // Closing file in secure manner
    void SafeFileClose(FILE* file);

    // Initializes WinSock2 library
    // Returns true if succeeded, false otherwise.
    bool InitializeWindowsSockets();

    // Skips leading spacings ontop of the buff, length of buffSize stoping currLoc at first non-skipable element
    void SkipSpacingsFront(char* buff, unsigned short buffSize, int* currLoc);

    // Skips following spacings ontop of the buff, length of buffSize stoping currLoc at first non-skipable element
    void SkipSpacingsBack(char* buff, unsigned short buffSize, int* currLoc);

    // Aquires first IPv4 address of first network adapter, check errno for success (0 if OK, other if an error occurred)
    unsigned GetApapterIP();

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

    void SafeFileClose(FILE* file)
    {
        if(file != NULL)fclose(file);
    }

    void SkipSpacingsFront(char* buff, unsigned short buffSize, int* currLoc)
    {
        while (*currLoc < buffSize && (buff[*currLoc] == ' ' ||  buff[*currLoc] == '\t'))++*currLoc;   // Skip body spacings
    }

    void SkipSpacingsBack(char* buff, unsigned short buffSize, int* currLoc)
    {
        while (*currLoc > 0 && (buff[*currLoc] == ' ' || buff[*currLoc] == '\t'))--*currLoc;   // Skip body spacings
    }

    unsigned GetApapterIP()
    {
        
        unsigned retVal = 0;

        pcap_if_t* devices; // List of network interfaces
        pcap_if_t* device;  // Network interface
        int devs = 0;          // Interface counter
        
        char errorMsg[PCAP_ERRBUF_SIZE + 1]; // Buffer for errors
        memset(errorMsg, 0, PCAP_ERRBUF_SIZE + 1);

        // Retrieve the device list of network intefaces
        if (pcap_findalldevs(&devices, errorMsg) == -1) 
            return 1;
        

        if (devs == 0)  // Pronadje 0 urejdja?
        {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return -1;
        }

        device = devices;
        retVal = ((sockaddr_in*)device->addresses->addr)->sin_addr.s_addr;

        pcap_freealldevs(devices);
        return  retVal;
    }



    SocketRecordParseErrCode ParseTCPDefRecord(char* record, int length, SOCKET_GROUP_PARAMS* socketGroupParams, int* endPtr)
    {
        char tmpIp[4];
        unsigned short portArr[MAX_PORTS_PER_RECORD];
        memset(portArr, 0, MAX_PORTS_PER_RECORD * 2);
        char portsFound = 0;
        char tmpService = 0;
        int byteLoc = 0;
        int stopLoc = 0;

        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return BAD_SYNTAX;

        if (record[byteLoc] == '$') byteLoc++;                    //Detect group record start 
        else return NO_OP_TAG;

        // Parse IP part
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return BAD_SYNTAX;

        for (stopLoc = byteLoc + 1; stopLoc < length; ++stopLoc)
            if (record[stopLoc] == '|') break;

        if (stopLoc == length) return BAD_SYNTAX;

        --stopLoc;
        if (strstr(record, ".")) // IP format
        {
            char ipStr[15];
            unsigned short tmpIpPart;
            char tmpIp[4];
            *((unsigned*)tmpIp) = 0;
            memset(ipStr, 0, 15);
            memcpy(ipStr, &record[byteLoc], stopLoc - byteLoc + 1);
            SkipSpacingsFront(&record[byteLoc], stopLoc - byteLoc + 1, &byteLoc);
            char* part = strtok(ipStr, ".");
            char tokensFound = 0;
            while (part != NULL)
            {
                ++tokensFound;
                if (tokensFound > 4) return BAD_IP;
                if (tmpIpPart = atoi(part) == 0)
                {
                    if (errno == EINVAL || errno == ERANGE || tmpIpPart > 255 || tmpIpPart < 0)
                        return BAD_IP;

                    tmpIp[tokensFound - 1] = 0;
                }
                else if (tmpIpPart != NULL)
                    {tmpIp[tokensFound - 1] = ((char*)tmpIpPart)[0];} // Take lsbyte
                else return NULL_PARAM_DETECTED;

                part = strtok(part, ".");
            }

            if (tokensFound < 4) return BAD_IP;
        }
        else                     // Symbolic format
        {
            //LH and A
            char tmpStr[4];
            *((int*)tmpStr) = 0;
            memcpy(tmpStr, &(record[byteLoc]), stopLoc - byteLoc + 1);
            SkipSpacingsFront(tmpStr, 4, &byteLoc);

            if (!strcmp(tmpStr + byteLoc, "A"))                     //Handle address Any  
                *((unsigned*)tmpStr) = GetApapterIP();
            else if (!strcmp(tmpStr + byteLoc, "LH"))               // Handle localhost
            {
                tmpIp[3] = 127;  tmpIp[2] = 0;   tmpIp[1] = 0; tmpIp[0] = 1;
            }
            else return BAD_IP;

        }

        byteLoc = byteLoc + stopLoc + 1;

        // Port/s parsing
        if (byteLoc >= length) return BAD_SYNTAX;

        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (record[byteLoc] == '|') byteLoc++;
        if (byteLoc >= length) return BAD_SYNTAX;
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return BAD_SYNTAX;

        for (stopLoc = byteLoc + 1; stopLoc < length; ++stopLoc)
            if (record[stopLoc] == '|') break;


        if (stopLoc == length)  return BAD_SYNTAX;

        --stopLoc;
        char* portStr = (char*)malloc(stopLoc - byteLoc + 1);
        memset(portStr, 0, stopLoc - byteLoc + 1);
        memcpy(portStr, record + byteLoc, stopLoc - byteLoc + 1);
        portsFound = 0;

        if (strstr(record, ","))
        {
            char* part = strtok(portStr, ",");
            int tmpPort;

            while (part != NULL)
            {
                ++portsFound;
                tmpPort = atoi(part);
                if (errno == EINVAL || errno == ERANGE || tmpPort > 65535 || tmpPort < 0)
                {
                    free(portStr);
                    return BAD_PORTS;
                }

                portArr[portsFound - 1] = tmpPort;
                part = strtok(part, ",");
            }
        }
        else { portArr[portsFound] = atoi(portStr); portsFound++; }
        free(portStr);

        if (portsFound == 0)   return BAD_PORTS;

        byteLoc = stopLoc + 2;
        if (byteLoc >= length) return BAD_SYNTAX;

        // Parsing service
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (record[byteLoc] == '|') byteLoc++;
        if (byteLoc >= length) return BAD_SYNTAX;
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return BAD_SYNTAX;

        //Seek closing Tag
        bool stopTagFound = false;
        for (stopLoc = byteLoc + 1; stopLoc < length; ++stopLoc)
            if (record[stopLoc] == '$') { stopTagFound = true; break; }

        if (!stopTagFound) return NO_CLS_TAG;

        --stopLoc;
        SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        SkipSpacingsBack(&record[byteLoc], length, &stopLoc);

        for (int loc = byteLoc; loc < stopLoc; ++loc)
        {
            if (record[loc] != '0' && record[loc] != '1' && record[loc] != '2' && record[loc] != '3' && record[loc] != '4' &&
                record[loc] != '5' && record[loc] != '6' && record[loc] != '7' && record[loc] != '8' && record[loc] != '9')
                return BAD_SERVICE;
        }

        if (socketGroupParams == NULL) return NULL_PARAM_DETECTED;
        else
        {
  
            socketGroupParams->address_ipv4 = *((unsigned*)(tmpIp));
            socketGroupParams->context_code = tmpService;
            socketGroupParams->port_units = portsFound;
            if (socketGroupParams->ports == NULL) return NULL_PARAM_DETECTED;
            else
            { 
                memset(socketGroupParams->ports, 0, portsFound * 2);
                memcpy(socketGroupParams->ports, portArr, portsFound * 2);
            }
            
         }
        *endPtr = stopLoc+1;
        return OK;
    }

    void LoadNetworkingParams(NETWORKING_PARAMS* networkParams)
    {

        char cCurrentPath[FILENAME_MAX];
        if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
            return;

        while (cCurrentPath[strlen(cCurrentPath) - 1] != '\\')
        cCurrentPath[strlen(cCurrentPath) - 1] = '\0';

        strcat_s(cCurrentPath, "\\Release\\NetworkCfg.txt");  

        cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
        //Append config file name

        FILE* fptr = NULL;
        fopen_s(&fptr, cCurrentPath, "rb");
        if (!fptr) return; //Configuration file not found

        if (networkParams == NULL) networkParams = (NETWORKING_PARAMS*)malloc(sizeof(NETWORKING_PARAMS));

        char* buff=(char*)(malloc(MAX_RECORD_LENGTH));
        char* startBuffPtr = buff;
        if (buff == NULL) return;

        int clsIdx = 0;
        char cutCharOldVal=0;
        bool lineProccessing = false;
        bool loadFlag = true;
        char* delimitPtr = NULL;
        while (true)                         //Read line by line 
        {
            if (loadFlag)
                if (!fgets(buff, MAX_RECORD_LENGTH, fptr)) { networkParams->Dispose(); free(startBuffPtr); SafeFileClose(fptr); return; }

            if (strstr(buff, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                do
                {
                    if (!fgets(buff, MAX_RECORD_LENGTH, fptr)) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose();  return; }
                    clsIdx = 0;
                }
                while (!(delimitPtr=strstr(buff, "#")));   
                ++delimitPtr;

                //Trim Skip section ending
                sprintf_s(buff, MAX_RECORD_LENGTH, "%s\0", delimitPtr);
                clsIdx = 0;
            }
            
            // Seek % starter          
            for (clsIdx; clsIdx < MAX_RECORD_LENGTH; ++clsIdx)   // Seek in current line
            {
                if (clsIdx == MAX_RECORD_LENGTH || buff[clsIdx] == '\r') break;          // End of line, take another one
                else if (buff[clsIdx] == EOF) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose(); return; }           // End of file
                else if (buff[clsIdx] == '%')           
                {
                    ++clsIdx;        
                    unsigned short protocolFoundID = 0;
                    int skipOffset = 0;
                    char* cutPtr = NULL;
                    if (clsIdx < MAX_RECORD_LENGTH)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if ((cutPtr =strstr(buff, "%PROTOCOL\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 9;
                            cutCharOldVal = buff[15];                                //Save
                            buff[15] = '\0';                                         //Cut
                            if(!strcmp(buff+skipOffset+1, "\"TCP\""))  protocolFoundID = 1;    //Compare
                            buff[15] = cutCharOldVal;                                //Restore
                            buff = buff + skipOffset + 7;
                        }
                        else if (cutPtr = strstr(buff, "%PROTOCOL"))
                        {
                            buff = cutPtr;
                            skipOffset = 9;
                            cutCharOldVal = buff[15];                                //Save
                            buff[15] = '\0';                                         //Cut
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;    //Compare
                            buff[15] = cutCharOldVal;      
                            buff = buff + skipOffset + 7;//Restore   
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PROTOCO\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 10;
                            cutCharOldVal = buff[16];
                            buff[16] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[16] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PROTOC\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 11;
                            cutCharOldVal = buff[17];
                            buff[17] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[17] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PROTO\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 12;
                            cutCharOldVal = buff[18];
                            buff[18] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[18] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PROT\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 13;
                            cutCharOldVal = buff[19];
                            buff[19] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[19] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PRO\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 14;
                            cutCharOldVal = buff[20];
                            buff[20] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[20] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%PR\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 15;
                            cutCharOldVal = buff[21];
                            buff[21] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[21] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff, "%P\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 16;
                            cutCharOldVal = buff[22];
                            buff[22] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[22] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff + clsIdx + skipOffset, "%\r")) && fgets(buff, MAX_RECORD_LENGTH, fptr))
                        {
                            buff = cutPtr;
                            skipOffset = 17;
                            cutCharOldVal = buff[23];
                            buff[23] = '\0';
                            if (!strcmp(buff + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff[23] = cutCharOldVal;
                            buff = buff + skipOffset + 7;
                            skipOffset += 7;
                        }

                        if (protocolFoundID == 1) // Has TCP params
                        {
                            printf(">>Parsing TCP<<\n");
                            if (networkParams->tcp_params) networkParams->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));   // First TCP param
                            
                            int start, stop=-1;
                            bool openBodyFound = false;

                            for (int loc = 0; loc < MAX_RECORD_LENGTH; ++loc)  // Continue searching in same line
                            {
                                if(buff[loc]=='_' || buff[loc] == '\t')
                                    SkipSpacingsFront(&buff[loc], MAX_RECORD_LENGTH, &loc);
                                if (buff[loc] == EOF) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose();  return; } // Bad syntax-no closing tag
                                if (loc >= MAX_RECORD_LENGTH || buff[loc] == '\r')    // If end line -> load new line
                                {
                                    do
                                        if (!fgets(buff, MAX_RECORD_LENGTH, fptr)) 
                                        {
                                            if (feof(fptr)) { } // Free buffer-a ili close file-a izaziva pucanje ???
                                            else { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose();}
                                            return;
                                        }
                                    while(strlen(buff)==0);
                                    loc = 0;
                                    SkipSpacingsFront(buff, MAX_RECORD_LENGTH - loc, &loc);
                                    loc = -1;   // Restarts loc to 0 after break;
                                    continue;
                                }

                                if (buff[loc] == '{')                                    // Body detected
                                {
                                    openBodyFound = true;
                                    ++loc;
                                    SkipSpacingsFront(buff + loc, MAX_RECORD_LENGTH - loc, &loc);   // Skip body spacings
                                    if (loc >= MAX_RECORD_LENGTH || buff[loc] == '\r')    // If end line -> load new line
                                    {
                                        if (!fgets(buff, MAX_RECORD_LENGTH, fptr)) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose(); return; };
                                        loc = 0;
                                        SkipSpacingsFront(buff, MAX_RECORD_LENGTH - loc, &loc);
                                        loc = -1;   // Restarts loc to 0 after break;
                                        continue;
                                    }
                                }

                                if (openBodyFound)                                                       //Seek body start
                                {
                                    bool openTagFound = false, closedTagFound= false;
                                    int findedAtLine=-1, totalLinesFromHere=0;
                                    char recordStr[MAX_RECORD_LENGTH];
                                    for (int lineLoc = loc; lineLoc < MAX_RECORD_LENGTH; ++lineLoc)  // Continue searching in same line
                                    {
                                        if (lineLoc >= MAX_RECORD_LENGTH || buff[lineLoc] == '\r')    // If end line -> load new line
                                        {
                                            if (openTagFound && !closedTagFound && findedAtLine == totalLinesFromHere)
                                            {
                                                memset(recordStr, 0, MAX_RECORD_LENGTH);
                                                memcpy(recordStr, buff + lineLoc, MAX_RECORD_LENGTH - lineLoc);
                                            }

                                            do
                                            {
                                                if (!fgets(buff, MAX_RECORD_LENGTH, fptr)) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose();   return; }
                                                else { lineLoc = 0; ++totalLinesFromHere; SkipSpacingsFront(buff, MAX_RECORD_LENGTH, &lineLoc); buff += lineLoc; }
                                            }while (lineLoc == MAX_RECORD_LENGTH);
         
                                            lineLoc = -1;  
                                            continue;
                                        }

                                        if (buff[lineLoc] == '$')   // Delimiter found
                                        {
                                            if (!openBodyFound && !closedTagFound) { openTagFound = true; start = lineLoc; ++lineLoc; findedAtLine = totalLinesFromHere; }
                                            else if (openBodyFound && !closedTagFound) { closedTagFound = true; stop = lineLoc; ++lineLoc; }
                                            
                                            if (openBodyFound && closedTagFound)
                                            {
                                                if(lineLoc>0)
                                                {
                                                    memcpy(buff, buff + lineLoc - 1, MAX_RECORD_LENGTH - lineLoc);
                                                    buff[MAX_RECORD_LENGTH - lineLoc] = '\0';
                                                }
                                                
                                                SOCKET_GROUP_PARAMS acceptParams;
                                                acceptParams.ports = (unsigned short*)malloc(MAX_PORTS_PER_RECORD);
                                                if (ParseTCPDefRecord(buff, strlen(buff), &acceptParams, &lineLoc) != OK) 
                                                { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose(); return; }

                                                if (acceptParams.ports != NULL && acceptParams.port_units < MAX_PORTS_PER_RECORD)
                                                {
                                                    unsigned short* newPtr= (unsigned short*)realloc(acceptParams.ports, acceptParams.port_units * 2);
                                                    if (newPtr != NULL) acceptParams.ports = newPtr;
                                                    
                                                }

                                                printf("\nLine parsed as: ");//#
                                                acceptParams.Format();

                                                switch (acceptParams.context_code)
                                                {
                                                    case 0: // It is a listen socket group
                                                    {
                                                        networkParams->tcp_params->listen_socket_units = acceptParams.port_units;   // How many sockets
                                                        if (networkParams->tcp_params->listen_socket_params == NULL)                // List of ther IP + PORT
                                                        {
                                                            networkParams->tcp_params->listen_socket_params = (SOCKETPARAMS*)malloc(acceptParams.port_units* sizeof(SOCKETPARAMS));
                                                            for (int loc = 0; loc < acceptParams.port_units; ++loc)
                                                            {
                                                                if (networkParams!=NULL &&
                                                                    acceptParams.address_ipv4 != NULL && 
                                                                    networkParams->tcp_params != NULL &&
                                                                    networkParams->tcp_params->listen_socket_params!= NULL &&
                                                                    networkParams->tcp_params->listen_socket_params[loc].address_ipv4 != NULL)
                                                                {
                                                                    networkParams->tcp_params->listen_socket_params[loc].address_ipv4 = acceptParams.address_ipv4;
                                                                    networkParams->tcp_params->listen_socket_params[loc].port = acceptParams.ports[loc];
                                                                }
                                                            }
                                                        }
                                                        continue; 
                                                    }
                                                    case 1: // It is an accept socket
                                                    {
                                                        networkParams->tcp_params->accept_socket_units = acceptParams.port_units;
                                                        if (networkParams->tcp_params->accept_socket_contexts == NULL)  // Hosting services codes
                                                            networkParams->tcp_params->accept_socket_contexts = (char*)malloc(acceptParams.port_units);

                                                        if (networkParams->tcp_params->accept_socket_params == NULL)
                                                        {
                                                            networkParams->tcp_params->accept_socket_params = (SOCKETPARAMS*)malloc(acceptParams.port_units * sizeof(SOCKETPARAMS));
                                                            for (int loc = 0; loc < acceptParams.port_units; ++loc)
                                                            {
                                                                if (networkParams!= NULL && 
                                                                    networkParams->tcp_params!= NULL &&
                                                                    networkParams->tcp_params->accept_socket_params!= NULL &&
                                                                    networkParams->tcp_params->accept_socket_params[loc].address_ipv4 != NULL &&
                                                                    networkParams->tcp_params->accept_socket_contexts != NULL)
                                                                {
                                                                    networkParams->tcp_params->accept_socket_params[loc].address_ipv4 = acceptParams.address_ipv4;
                                                                    networkParams->tcp_params->accept_socket_params[loc].port = acceptParams.ports[loc];
                                                                    networkParams->tcp_params->accept_socket_contexts[loc] = acceptParams.context_code;
                                                                }
                                                            }
                                                        }
                                                        continue;
                                                    }
                                                }

                                                openBodyFound = false;
                                                closedTagFound = false;
                                            }
                                        }
                                        else if (buff[lineLoc] == '}')
                                        {
                                            loc = lineLoc;
                                            openBodyFound = false;
                                            break;
                                        }
                                        else { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose(); return; }  // Emptry {}
                                    }
                                    if(openBodyFound==true) { SafeFileClose(fptr); free(startBuffPtr); networkParams->Dispose(); return; }   // No } closure
                                }
                            }
                        }
                    }
                }
            }
        }
        free(startBuffPtr);
        SafeFileClose(fptr);      
    }

#pragma endregion


