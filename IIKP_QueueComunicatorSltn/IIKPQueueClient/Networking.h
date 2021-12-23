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

#pragma region IgnoreWarnings
    #pragma warning(suppress : 6387)
    #pragma warning(suppress : 6011)
    #pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
    #define MAX_PORTS_PER_RECORD 8
    #define MAX_RECORD_LENGTH   255
#pragma endregion

#pragma region Globals
    char NetworkingErrMsg[PCAP_ERRBUF_SIZE + 1];
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
        unsigned char context_code;


        void Prepare()
        {
            ports = NULL;
        }

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
                    (unsigned)(((unsigned char*)(&address_ipv4))[3]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[2]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[1]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[0]),
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
        unsigned char* accept_socket_contexts;  

        void Prepare()
        {
            listen_socket_params = NULL;
            accept_socket_params = NULL;
            accept_socket_contexts = NULL;
        }

        void Dispose()
        {
            if(listen_socket_params != NULL)    free(listen_socket_params);
            if (accept_socket_contexts != NULL) free(accept_socket_contexts);
            if (accept_socket_params != NULL)   free(accept_socket_params);
        }

        void Format()
        {
            printf("\nTotal listen socket units:\t%hu\n", listen_socket_units);

            if (listen_socket_units > 0)
            {
                for (unsigned short loc = 0; loc < listen_socket_units; ++loc)
                    printf("\t%u.%u.%u.%u:%u\t- %s\n",
                        (unsigned)(((unsigned char*)(&((listen_socket_params[loc]).address_ipv4)))[3]),
                        (unsigned)(((unsigned char*)(&((listen_socket_params[loc]).address_ipv4)))[2]),
                        (unsigned)(((unsigned char*)(&((listen_socket_params[loc]).address_ipv4)))[1]),
                        (unsigned)(((unsigned char*)(&((listen_socket_params[loc]).address_ipv4)))[0]),
                        listen_socket_params[loc].port, 
                        "Listening Socket");
            }
            else
                printf("\t [NO DATA]");

            if (accept_socket_units > 0)
            {
                char contextStr[20];
                memset(contextStr, 0, 20);

                printf("\n");
                printf("Total accept socket units:\t%hu\n", accept_socket_units);
                for (unsigned short loc = 0; loc < accept_socket_units; ++loc)
                {
                    switch (accept_socket_contexts[loc])
                    {
                        case 1: {sprintf_s(contextStr, "Buffering Socket\0"); break; }
                    }
                    printf("\t%u.%u.%u.%u:%u\t- %s\n",
                        (unsigned)(((unsigned char*)(&((accept_socket_params[loc]).address_ipv4)))[3]),
                        (unsigned)(((unsigned char*)(&((accept_socket_params[loc]).address_ipv4)))[2]),
                        (unsigned)(((unsigned char*)(&((accept_socket_params[loc]).address_ipv4)))[1]),
                        (unsigned)(((unsigned char*)(&((accept_socket_params[loc]).address_ipv4)))[0]),
                        accept_socket_params[loc].port,
                        contextStr);
                }
            }
            else
                printf("\t [NO DATA]");

            
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
        unsigned char* accept_socket_contexts;  

        void Prepare()
        {
            accept_socket_params = NULL;
            accept_socket_contexts = NULL;
        }

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

        void Prepare()
        {
            tcp_params = NULL;
            udp_params = NULL;
        }

        void Dispose()
        {
            if (tcp_params != NULL) { tcp_params->Dispose();  free(tcp_params); }
            if (udp_params != NULL) { udp_params->Dispose();  free(udp_params); }
        }
    } NETWORKING_PARAMS;

    // Indicates status of try-parsed socket record in NetCfg.txt
    enum  SocketRecordParseErrCode { OK = 0, NO_IP, BAD_IP, NO_PORTS, BAD_PORTS, NO_SERVICE, BAD_SERVICE, BAD_SYNTAX, NO_OP_TAG, NO_CLS_TAG, NULL_PARAM_DETECTED, ADAPTER_ERR };
    
#pragma endregion

#pragma region FunctionsDecl

    // Loads network parameters from NetworkCfg.txt
    // Fills NETWORKING_PARAMS structure (see in Data section above)
    // null if file is not found or corrupted
    // void* inputDataMemoryChunk memory chunk dynamically alocated by caller
    // FILE** Config file
    NETWORKING_PARAMS LoadNetworkingParams(char* inputDataMemoryChunk, FILE** file);

    // Initializes WinSock2 library
    // Returns true if succeeded, false otherwise.
    bool InitializeWindowsSockets();

    // Aquires first IP address of first network adapter with supported addr_type of address ignoring Loopback adapter
    bool GetApapterIP(unsigned* addr, int addr_type, bool ignoreLoopback);

#pragma endregion

#pragma region HelperFunctions

    // Skips leading spacings ontop of the buff, length of buffSize stoping currLoc at first non-skipable element
    void SkipSpacingsFront(char* buff, unsigned short buffSize, int* currLoc);

    // Skips following spacings ontop of the buff, length of buffSize stoping currLoc at first non-skipable element
    void SkipSpacingsBack(char* buff, unsigned short buffSize, int* currLoc);

#pragma endregion

#pragma region HelperFunctionsImpl

    void SkipSpacingsFront(char* buff, unsigned short buffSize, int* currLoc)
    {
        while (*currLoc < buffSize && (buff[*currLoc] == ' ' || buff[*currLoc] == '\t'))++* currLoc;   // Skip body spacings
    }

    void SkipSpacingsBack(char* buff, unsigned short buffSize, int* currLoc)
    {
        while (*currLoc > 0 && (buff[*currLoc] == ' ' || buff[*currLoc] == '\t'))--* currLoc;   // Skip body spacings
    }
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

    bool GetApapterIP(unsigned* addr, int addr_type, bool ignoreLoopback)
    {
        pcap_if_t* devices = NULL;
        pcap_if_t* device = NULL;
        memset(NetworkingErrMsg, 0, PCAP_ERRBUF_SIZE + 1);

        if (pcap_findalldevs(&devices, NetworkingErrMsg) == -1)
        {
            printf("Error loading network adapters: %s", NetworkingErrMsg);
            return 1;
        }

        if (devices == NULL)
        {
            printf("Loading interfaces failed with: %s", NetworkingErrMsg);
            return false;
        }

        bool found = false;
        for (device = devices; device!= NULL; device = device->next)
        {
            if (device->description != NULL &&  
                strstr(device->description, "LOOPBACK") == NULL &&
                strstr(device->description, "loopback") == NULL &&
                strstr(device->description, "Loopback") == NULL)
            {

                pcap_addr_t* dev_addr = NULL;
                for (dev_addr = device->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
                {
                    if (dev_addr->addr->sa_family == addr_type && dev_addr->addr != NULL)
                    {
                        char tmpStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &((sockaddr_in*)dev_addr->addr)->sin_addr, tmpStr, INET_ADDRSTRLEN);
                        
                        *addr = 0;
                        char* part = strtok(tmpStr, ".");
                        int loc = 3;
                        int tmpSegment;
                        while (part != NULL)
                        {
                            if (part != ".")
                            {
                                tmpSegment = atoi(part);
                                if (errno == EINVAL || errno == ERANGE)
                                {
                                    return false;
                                }
                                ((unsigned char*)(addr))[loc] = tmpSegment;
                                --loc;
                                if (loc < 0) break;
                            }

                            part = strtok(NULL, ".");
                        }
                        found = true;
                        break;
                    }
                }

                if (found) break;
            }
            
        }
        pcap_freealldevs(devices);
        return found;
    }



    SocketRecordParseErrCode ParseTCPDefRecord(char* record, int length, SOCKET_GROUP_PARAMS* socketGroupParams, int* endPtr)
    {
        char tmpIp[4];
        unsigned short portArr[MAX_PORTS_PER_RECORD];
        memset(portArr, 0, MAX_PORTS_PER_RECORD * 2);
        unsigned char portsFound = 0;
        unsigned char tmpService = 0;
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
            *((unsigned*)tmpIp) = 0;
            memset(ipStr, 0, 15);
            memcpy(ipStr, &record[byteLoc], stopLoc - byteLoc + 1);
            SkipSpacingsFront(&record[byteLoc], stopLoc - byteLoc + 1, &byteLoc);
            char* part = strtok(ipStr, ".");
            char tokensFound = 3;
            while (part != NULL)
            {
                if (tokensFound < 0) return BAD_IP;
                tmpIpPart = atoi(part);
                
                    if (errno == EINVAL || errno == ERANGE || tmpIpPart > 255 || tmpIpPart < 0)
                        return BAD_IP;
                
                if(tmpIpPart != NULL)
                {
                    tmpIp[tokensFound] = ((unsigned char*)&tmpIpPart)[0];
                    --tokensFound;
                } // Take lsbyte
                else return NULL_PARAM_DETECTED;

                //part = strtok(part, ".");
                part = strtok(NULL, ".");
            }
        }
        else                     // Symbolic format
        {
            //LH and A
            char tmpStr[4];
            *((int*)tmpStr) = 0;
            memcpy(tmpStr, &(record[byteLoc]), stopLoc - byteLoc + 1);
            int mockLoc = 0;
            SkipSpacingsFront(tmpStr, 4, &mockLoc);

            if (!strcmp(tmpStr + mockLoc, "A"))                     //Handle address Any 
            {
                if( !GetApapterIP((unsigned*)tmpIp, AF_INET, true)) return ADAPTER_ERR;
            }
                
            else if (!strcmp(tmpStr + mockLoc, "LH"))               // Handle localhost
            {
                tmpIp[3] = 127;  tmpIp[2] = 0;   tmpIp[1] = 0; tmpIp[0] = 1;
            }
            else return BAD_IP;

        }

        byteLoc = stopLoc + 1;

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
                part = strtok(NULL, ",");
            }
        }
        else { portArr[portsFound] = atoi(portStr); portsFound++; }
        free(portStr);

        if (portsFound == 0)   return BAD_PORTS;

        byteLoc = stopLoc + 2;
        byteLoc = stopLoc + 2;
        if (byteLoc >= length) return BAD_SYNTAX;

        // Parsing service
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (record[byteLoc] == '|') byteLoc++;
        if (byteLoc >= length) return BAD_SYNTAX;
        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return BAD_SYNTAX;

        tmpService = record[byteLoc] - '0';
        if (tmpService != 0 && tmpService != 1) return BAD_SERVICE;

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

    NETWORKING_PARAMS LoadNetworkingParams(char* inputDataMemoryChunk, FILE** file)
    {

        char* usedSectionEnd = inputDataMemoryChunk;
        NETWORKING_PARAMS networkParams;
        networkParams.Prepare();

        if (file == NULL || *file == NULL) return networkParams;
        FILE* fptr = *file;

        char buff[MAX_RECORD_LENGTH];
        memset(buff, 0, MAX_RECORD_LENGTH);
        char* buff_it = buff;

        int clsIdx = 0;
        char cutCharOldVal=0;
        bool lineProccessing = false;
        bool loadFlag = true;
        char* delimitPtr = NULL;
        while (true)                         //Read line by line 
        {
            if (loadFlag)
                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return networkParams;
                

            if (strstr(buff_it, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                do
                {
                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return networkParams;

                    clsIdx = 0;
                }
                while (!(delimitPtr=strstr(buff_it, "#")));   
                ++delimitPtr;

                //Trim Skip section ending
                sprintf_s(buff_it, MAX_RECORD_LENGTH, "%s\0", delimitPtr);
                clsIdx = 0;
            }
            
            // Seek % starter          
            bool seekProto = false;
            for (clsIdx; clsIdx < MAX_RECORD_LENGTH; ++clsIdx)   // Seek in current line
            {
                if (clsIdx == MAX_RECORD_LENGTH || buff_it[clsIdx] == '\r' || buff_it[clsIdx] == '\n') break;          // End of line, take another one
                else if (buff_it[clsIdx] == EOF) return networkParams;            // End of file
                else if (buff_it[clsIdx] == '%')           
                {
                    ++clsIdx;        
                    unsigned short protocolFoundID = 0;
                    int skipOffset = 0;
                    char* cutPtr = NULL;
                    if (clsIdx < MAX_RECORD_LENGTH)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if ((cutPtr =strstr(buff_it, "%PROTOCOL\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 9;
                            cutCharOldVal = buff_it[15];                                //Save
                            buff_it[15] = '\0';                                         //Cut
                            if(!strcmp(buff_it+skipOffset+1, "\"TCP\""))  protocolFoundID = 1;    //Compare
                            buff_it[15] = cutCharOldVal;                                //Restore
                            buff_it = buff_it + skipOffset + 7;
                        }
                        else if (cutPtr = strstr(buff_it, "%PROTOCOL"))
                        {
                            buff_it = cutPtr;
                            skipOffset = 9;
                            cutCharOldVal = buff_it[15];                                //Save
                            buff_it[15] = '\0';                                         //Cut
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;    //Compare
                            buff_it[15] = cutCharOldVal;      
                            buff_it = buff_it + skipOffset + 7;//Restore   
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTOCO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 10;
                            cutCharOldVal = buff_it[16];
                            buff_it[16] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[16] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTOC\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 11;
                            cutCharOldVal = buff_it[17];
                            buff_it[17] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[17] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 12;
                            cutCharOldVal = buff_it[18];
                            buff_it[18] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[18] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROT\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 13;
                            cutCharOldVal = buff_it[19];
                            buff_it[19] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[19] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PRO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 14;
                            cutCharOldVal = buff_it[20];
                            buff_it[20] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[20] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PR\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 15;
                            cutCharOldVal = buff_it[21];
                            buff_it[21] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[21] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%P\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 16;
                            cutCharOldVal = buff_it[22];
                            buff_it[22] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[22] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it + clsIdx + skipOffset, "%\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skipOffset = 17;
                            cutCharOldVal = buff_it[23];
                            buff_it[23] = '\0';
                            if (!strcmp(buff_it + skipOffset + 1, "\"TCP\""))  protocolFoundID = 1;
                            buff_it[23] = cutCharOldVal;
                            buff_it = buff_it + skipOffset + 7;
                            skipOffset += 7;
                        }

                        if (protocolFoundID == 1) // Has TCP params
                        {
                            if (networkParams.tcp_params == NULL)
                            {
                                networkParams.tcp_params = (TCPNETWORK_PARAMS*)usedSectionEnd;          // First TCP param
                                networkParams.tcp_params->Prepare();
                                usedSectionEnd = ((char*)usedSectionEnd) + sizeof(TCPNETWORK_PARAMS);   // Allocate
                            }
                            
                            int start, stop=-1;
                            bool openBodyFound = false;

                            for (int loc = 0; loc < MAX_RECORD_LENGTH; ++loc)  // Continue searching in same line
                            {
                                if(buff_it[loc]=='_' || buff_it[loc] == '\t')
                                    SkipSpacingsFront(&buff_it[loc], MAX_RECORD_LENGTH, &loc);
                                if (buff_it[loc] == EOF)  return networkParams;  // Bad syntax-no closing tag
                                if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                                {
                                    do
                                        if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) 
                                            return networkParams;  
                                    while(strlen(buff_it)==0);
                                    loc = 0;
                                    SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
                                    loc = -1;   // Restarts loc to 0 after break;
                                    continue;
                                }

                                if (buff_it[loc] == '{')                                    // Body detected
                                {
                                    openBodyFound = true;
                                    ++loc;
                                    SkipSpacingsFront(buff_it + loc, MAX_RECORD_LENGTH - loc, &loc);   // Skip body spacings
                                    if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                                    {
                                        if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return networkParams; 
                                        loc = 0;
                                        SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
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
                                        if (lineLoc >= MAX_RECORD_LENGTH || buff_it[lineLoc] == '\r' || buff_it[lineLoc] == '\n')    // If end line -> load new line
                                        {
                                            if (openTagFound && !closedTagFound && findedAtLine == totalLinesFromHere)
                                            {
                                                memset(recordStr, 0, MAX_RECORD_LENGTH);
                                                memcpy(recordStr, buff_it + lineLoc, MAX_RECORD_LENGTH - lineLoc);
                                            }

                                            do
                                            {
                                                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return networkParams; 
                                                else { lineLoc = 0; ++totalLinesFromHere; SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH, &lineLoc); buff_it += lineLoc; }
                                            }while (lineLoc == MAX_RECORD_LENGTH);
         
                                            lineLoc = -1;  
                                            continue;
                                        }

                                        if (buff_it[lineLoc] == '$')   // Delimiter found
                                        {
                                            if (!openBodyFound && !openTagFound) { openTagFound = true; start = lineLoc; ++lineLoc; findedAtLine = totalLinesFromHere; }
                                            else if (openBodyFound && !closedTagFound) { closedTagFound = true; stop = lineLoc; ++lineLoc; }
                                            
                                            if (openBodyFound && closedTagFound)
                                            {
                                                if(lineLoc>0)
                                                {
                                                    memcpy(buff_it, buff_it + lineLoc - 1, MAX_RECORD_LENGTH - lineLoc);
                                                    buff_it[MAX_RECORD_LENGTH - lineLoc] = '\0';
                                                }                      

                                                SOCKET_GROUP_PARAMS acceptParams;
                                                acceptParams.Prepare();
                                                acceptParams.ports = (unsigned short*)usedSectionEnd;               
                                                usedSectionEnd = ((char*)usedSectionEnd) + MAX_PORTS_PER_RECORD *2;        // Allocate

                                                if (ParseTCPDefRecord(buff_it, strlen(buff_it), &acceptParams, &lineLoc) != OK) return networkParams;


                                                if (acceptParams.ports != NULL && acceptParams.port_units < MAX_PORTS_PER_RECORD)
                                                    usedSectionEnd = ((char*)usedSectionEnd) - ((MAX_PORTS_PER_RECORD - acceptParams.port_units) * 2);    // Free extra               

                                                switch (acceptParams.context_code)
                                                {
                                                    case 0: // It is a listen socket group
                                                    {
                                                        networkParams.tcp_params->listen_socket_units = acceptParams.port_units;   // How many sockets
                                                        if (networkParams.tcp_params->listen_socket_params == NULL)                // List of ther IP + PORT
                                                        {
                                                            networkParams.tcp_params->listen_socket_params = (SOCKETPARAMS*)usedSectionEnd;

                                                            usedSectionEnd = ((char*)usedSectionEnd + acceptParams.port_units * sizeof(SOCKETPARAMS));
                                                               
                                                            for (int loc = 0; loc < acceptParams.port_units; ++loc)
                                                            {
                                                                if (acceptParams.address_ipv4 != NULL && 
                                                                    networkParams.tcp_params != NULL &&
                                                                    networkParams.tcp_params->listen_socket_params!= NULL &&
                                                                    networkParams.tcp_params->listen_socket_params[loc].address_ipv4 != NULL)
                                                                {
                                                                    networkParams.tcp_params->listen_socket_params[loc].address_ipv4 = acceptParams.address_ipv4;
                                                                    networkParams.tcp_params->listen_socket_params[loc].port = acceptParams.ports[loc];
                                                                }
                                                            }
                                                        }
                                                        ++lineLoc;
                                                        openTagFound = false;
                                                        closedTagFound = false;
                                                        continue; 
                                                    }
                                                    case 1: // It is an accept socket
                                                    {
                                                        networkParams.tcp_params->accept_socket_units = acceptParams.port_units;
                                                        if (networkParams.tcp_params->accept_socket_contexts == NULL)  // Hosting services codes
                                                            networkParams.tcp_params->accept_socket_contexts = (unsigned char*)usedSectionEnd;
                                                            usedSectionEnd= ((char*)usedSectionEnd) +acceptParams.port_units;

                                                        if (networkParams.tcp_params->accept_socket_params == NULL)
                                                        {
                                                            networkParams.tcp_params->accept_socket_params = (SOCKETPARAMS*)usedSectionEnd;
                                                            usedSectionEnd = ((char*)usedSectionEnd) + acceptParams.port_units * sizeof(SOCKETPARAMS);
                                                            for (int loc = 0; loc < acceptParams.port_units; ++loc)
                                                            {
                                                                if (networkParams.tcp_params!= NULL &&
                                                                    networkParams.tcp_params->accept_socket_params!= NULL &&
                                                                    networkParams.tcp_params->accept_socket_params[loc].address_ipv4 != NULL &&
                                                                    networkParams.tcp_params->accept_socket_contexts != NULL)
                                                                {
                                                                    networkParams.tcp_params->accept_socket_params[loc].address_ipv4 = acceptParams.address_ipv4;
                                                                    networkParams.tcp_params->accept_socket_params[loc].port = acceptParams.ports[loc];
                                                                    networkParams.tcp_params->accept_socket_contexts[loc] = acceptParams.context_code;
                                                                }
                                                            }
                                                        }
                                                        ++lineLoc;
                                                        openTagFound = false;
                                                        closedTagFound = false;
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                        else if (buff_it[lineLoc] == '}')
                                        {
                                            clsIdx = lineLoc+2;     // Skip }%
                                            seekProto = true;
                                            break;
                                        }
                                    }

                                    // Puca na free startbuff_itPtr, provjeravao sam ne oslobadjam ga nigdje ranije, nije NULL i drzi staru vrijednost sa pocetka???
                                    if(openBodyFound==true)  return networkParams;    // No } closure
                                    if (seekProto) break;   // Brake
                                }
                            }
                        }
                    }
                }
            }
        }
        return networkParams;
    }

#pragma endregion


