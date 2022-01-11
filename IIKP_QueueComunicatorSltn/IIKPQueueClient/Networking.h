#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"
#include "Common.h"

#include <direct.h>             // Windows supported only
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
    #define MAX_ACCEPT_SOCKETS  20
#pragma endregion

#pragma region Globals
    char networking_err_msg[PCAP_ERRBUF_SIZE + 1];
#pragma endregion

#pragma region Data

    // Structure represents parsed socket-group record (see NetCfg.txt Legend section )
    typedef struct SOCKET_GROUP_PARAMS
    {
        unsigned address_ipv4;          // IPv4 address (each byte as address segment)
        char port_units;                // Number of ports attached to that address hosting same service
        unsigned short* ports;          // Array of port numbers
        unsigned char context_code;     // Context code of parsed record

        // Initialize all fields (remove garbage values)
        void Initialize()
        {
            ports = NULL;
        }

        // Safe dispose of allocated memory 
        bool Dispose()
        {
            if (ports != NULL) { free(ports); ports = NULL; }
            return true;
        }

        // Prints out formatted struct content
        void Format()
        {

            char contextStr[30];
            memset(contextStr, 0, 30);

            switch (context_code)
            {
                case 0: {sprintf_s(contextStr,"Listen Socket\0");  break; }
                case 1: {sprintf_s(contextStr, "Buffering Socket\0"); break; }
                case 2: {sprintf_s(contextStr, "Register Socket\0"); break; }
                case 3: {sprintf_s(contextStr, "Servicing Socket (source)\0"); break; }
                case 4: {sprintf_s(contextStr, "Servicing Socket (target)\0"); break; }
            }

            for (char loc = 0; loc < port_units; ++loc)
            {
                printf("%u.%u.%u.%u:%u\t- %s\n", 
                    (unsigned)(((unsigned char*)(&address_ipv4))[3]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[2]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[1]),
                    (unsigned)(((unsigned char*)(&address_ipv4))[0]),
                    ports[loc],
                    contextStr);
            }  
        }

    }SOCKET_GROUP_PARAMS;

    // Structure represents single socket parameter
    typedef struct SOCKET_PARAMS
    {
        unsigned short port;        // Socket port                 
        unsigned address_ipv4;      // Socket IPv4 address

        // Function formats address into standard string format 
        // char* buff - null terminated string contining formatted address (as return value)
        void FormatIP(char* buff)
        {
            memset(buff, 0, 13);
            sprintf(buff,
                "%u.%u.%u.%u\0",
                (unsigned)(((unsigned char*)(&address_ipv4))[3]),
                (unsigned)(((unsigned char*)(&address_ipv4))[2]),
                (unsigned)(((unsigned char*)(&address_ipv4))[1]),
                (unsigned)(((unsigned char*)(&address_ipv4))[0]));
        }

    } SOCKETPARAMS;


    // Structure represents TCP network parameters (on app scope), null if protocol not supported.
    typedef struct TCPNETWORK_PARAMS
    {
        unsigned short listen_socket_units;   // Number of listen sockets
        SOCKETPARAMS* listen_socket_params;   // Array of listen socket params     

        unsigned short accept_socket_units;   // Number of accept sockets    
        SOCKETPARAMS* accept_socket_params;   // Array of accept socket params
        unsigned char* accept_socket_contexts;// Array of accept socket context roles

        // Initialize all fields (remove garbage values)
        void Initialize()
        {
            listen_socket_params = NULL;
            accept_socket_params = NULL;
            accept_socket_contexts = NULL;
            accept_socket_units=0;
            listen_socket_units = 0;
        }

        // Safe dispose of allocated memory 
        bool Dispose()
        {
            if (listen_socket_params   != NULL)   {free(listen_socket_params);    listen_socket_params   = NULL;  }
            if (accept_socket_contexts != NULL)   {free(accept_socket_contexts);  accept_socket_contexts = NULL;  }
            if (accept_socket_params   != NULL)   {free(accept_socket_params);    accept_socket_params   = NULL;  }
            return true;
        }

        // Prints out formatted struct content
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
                char contextStr[30];
                memset(contextStr, 0, 30);

                printf("\n");
                printf("Total accept socket units:\t%hu\n", accept_socket_units);
                for (unsigned short loc = 0; loc < accept_socket_units; ++loc)
                {
                    switch (accept_socket_contexts[loc])
                    {
                        case 0: {sprintf_s(contextStr, "Listen Socket\0");  break; }
                        case 1: {sprintf_s(contextStr, "Buffering Socket\0"); break; }
                        case 2: {sprintf_s(contextStr, "Register Socket\0"); break; }
                        case 3: {sprintf_s(contextStr, "Servicing Socket (source)\0"); break; }
                        case 4: {sprintf_s(contextStr, "Servicing Socket (target)\0"); break; }
                    }

                    printf("\t%u.%u.%u.%u:%u   \t- %s\n",
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

    // Structure represents UDP network parameters (on app scope), null if protocol not supported:
    typedef struct UDPNETWORK_PARAMS
    {
        unsigned short accept_socket_units;      // Number of sockets   
        SOCKETPARAMS* accept_socket_params;      // Array of socket params
        unsigned char* accept_socket_contexts;   // Array of socket context roles

        // Initialize all fields (remove garbage values)
        void Initialize()
        {
            accept_socket_params = NULL;
            accept_socket_contexts = NULL;
        }

        // Safe dispose of allocated memory 
        bool Dispose()
        {
            if (accept_socket_params != NULL)   { free(accept_socket_params);    accept_socket_params = NULL;   }
            if (accept_socket_contexts != NULL) { free(accept_socket_contexts);  accept_socket_contexts = NULL; }
            return true;
        }
    } UDPNETWORK_PARAMS;

    // Structure represents network parameters for each transport layer protocol (on app scope).
    typedef struct NETWORKING_PARAMS
    {
        TCPNETWORK_PARAMS* tcp_params; // Pointer to tcp_params
        UDPNETWORK_PARAMS* udp_params; // Pointer to udp_params

        // Initialize all fields (remove garbage values)
        void Initialize()
        {
            tcp_params = NULL;
            udp_params = NULL;
        }

        // Safe dispose of allocated memory 
        bool Dispose()
        {
            if (tcp_params != NULL) { tcp_params->Dispose();  free(tcp_params); tcp_params = NULL; }
            if (udp_params != NULL) { udp_params->Dispose();  free(udp_params); udp_params = NULL;}
            return true;
        }
    } NETWORKING_PARAMS;

    // Indicates status of try-parsed socket record in NetCfg.txt
    enum  SocketRecordParseErrCode { OK = 0, NO_IP, BAD_IP, NO_PORTS, BAD_PORTS, NO_SERVICE, BAD_SERVICE, BAD_SYNTAX, NO_OP_TAG, NO_CLS_TAG, NULL_PARAM_DETECTED, ADAPTER_ERR };
    
    // Indicates context of socket unit
    enum  ServiceCode { LISTENING = 0, BUFFERING = 1, SERVICING=3};
    
#pragma endregion

#pragma region FunctionsDecl

    // Loads app. network parameters from config. file
    // FILE** file                       - pointer to network config. file
    // NETWORKING_PARAMS* network_params - Pointer to network struvture to be filled,null if file is not found or corrupted
    void LoadNetworkingParams(FILE** file, NETWORKING_PARAMS* network_params);

    // Initializes WinSock2 library
    // Returns true if succeeded, false otherwise.
    bool InitializeWindowsSockets();

    // Aquires first IP address of first network adapter with supported addr_type of address ignoring Loopback adapter
    // unsigned* addr       - IPv4 address in byte format, acts as return value
    // int addr_type        - Type of address to be considered
    // bool ignore_loopback - Ignore loopback adapter flag
    // Returns true if success, false otherwise
    bool GetApapterIP(unsigned* addr, int addr_type, bool ignore_loopback);

    // Parses TCP protocol parameters definition inside network config file
    // char* record - null terminated string of record to be parsed
    // int length   - record length
    // SOCKET_GROUP_PARAMS* socket_group_params - socket params to be filled, acts as return value
    // int* end_ptr - pointer to the end of the record (acts as return value - skip parsed record)
    SocketRecordParseErrCode ParseTCPDefRecord(char* record, int length, SOCKET_GROUP_PARAMS* socket_group_params, int* end_ptr);

#pragma endregion

#pragma region HelperFunctionsDecl

    // Skips leading buffer spacings
    // char* buff               - source string
    // unsigned short buff_size - string buffer size
    // int* curr_loc            - pointer to start from index (front), acts as return value 
    void SkipSpacingsFront(char* buff, unsigned short buff_size, int* curr_loc);

    // Skips following buffer spacings
    // char* buff               - source string
    // unsigned short buff_size - string buffer size
    // int* curr_loc            - pointer to start from index (end), acts as return value 
    void SkipSpacingsBack(char* buff, unsigned short buff_size, int* curr_loc);

#pragma endregion

#pragma region HelperFunctionsImpl

    void SkipSpacingsFront(char* buff, unsigned short buff_size, int* curr_loc)
    {
        while (*curr_loc < buff_size && (buff[*curr_loc] == ' ' || buff[*curr_loc] == '\t'))++* curr_loc;   // Skip body spacings
    }

    void SkipSpacingsBack(char* buff, unsigned short buff_size, int* curr_loc)
    {
        while (*curr_loc > 0 && (buff[*curr_loc] == ' ' || buff[*curr_loc] == '\t'))--* curr_loc;   // Skip body spacings
    }
#pragma endregion

#pragma region FunctionsImpl

    bool InitializeWindowsSockets()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            printf("WSAStartup failed with error: %d\n", WSAGetLastError());
            return false;
        }
        return true;
    }

    bool GetApapterIP(unsigned* addr, int addr_type, bool ignore_loopback)
    {
        pcap_if_t* devices = NULL;
        pcap_if_t* device = NULL;
        memset(networking_err_msg, 0, PCAP_ERRBUF_SIZE + 1);

        if (pcap_findalldevs(&devices, networking_err_msg) == -1)
        {
            printf("Error loading network adapters: %s", networking_err_msg);
            return 1;
        }

        if (devices == NULL)
        {
            printf("Loading interfaces failed with: %s", networking_err_msg);
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
                        char tmp_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &((sockaddr_in*)dev_addr->addr)->sin_addr, tmp_str, INET_ADDRSTRLEN);
                        
                        *addr = 0;
                        char* part = strtok(tmp_str, ".");
                        int loc = 3;
                        int tmp_segment;
                        while (part != NULL)
                        {
                            if (part != ".")
                            {
                                tmp_segment = atoi(part);
                                if (errno == EINVAL || errno == ERANGE)
                                {
                                    return false;
                                }
                                ((unsigned char*)(addr))[loc] = tmp_segment;
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

    SocketRecordParseErrCode ParseTCPDefRecord(char* record, int length, SOCKET_GROUP_PARAMS* socket_group_params, int* end_ptr)
    {
        char tmp_ip[4];
        unsigned short port_arr[MAX_PORTS_PER_RECORD];
        memset(port_arr, 0, MAX_PORTS_PER_RECORD * 2);
        unsigned char ports_found = 0;
        unsigned char tmp_service = 0;
        int byte_loc = 0;
        int stop_loc = 0;

        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (byte_loc >= length) return BAD_SYNTAX;

        if (record[byte_loc] == '$') byte_loc++;                    //Detect group record start 
        else return NO_OP_TAG;

        // Parse IP part
        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (byte_loc >= length) return BAD_SYNTAX;

        for (stop_loc = byte_loc + 1; stop_loc < length; ++stop_loc)
            if (record[stop_loc] == '|') break;

        if (stop_loc == length) return BAD_SYNTAX;

        --stop_loc;
        if (strstr(record, ".")) // IP format
        {
            char ipStr[15];
            unsigned short tmp_ip_part;
            *((unsigned*)tmp_ip) = 0;
            memset(ipStr, 0, 15);
            memcpy(ipStr, &record[byte_loc], stop_loc - byte_loc + 1);
            SkipSpacingsFront(&record[byte_loc], stop_loc - byte_loc + 1, &byte_loc);
            char* part = strtok(ipStr, ".");
            char tokens_found = 3;
            while (part != NULL)
            {
                if (tokens_found < 0) return BAD_IP;
                tmp_ip_part = atoi(part);
                
                    if (errno == EINVAL || errno == ERANGE || tmp_ip_part > 255 || tmp_ip_part < 0)
                        return BAD_IP;
                
                if(tmp_ip_part != NULL)
                {
                    tmp_ip[tokens_found] = ((unsigned char*)&tmp_ip_part)[0];
                    --tokens_found;
                } // Take lsbyte
                else return NULL_PARAM_DETECTED;

                //part = strtok(part, ".");
                part = strtok(NULL, ".");
            }
        }
        else                     // Symbolic format
        {
            //LH and A
            char tmp_str[4];
            *((int*)tmp_str) = 0;
            memcpy(tmp_str, &(record[byte_loc]), stop_loc - byte_loc + 1);
            int mock_loc = 0;
            SkipSpacingsFront(tmp_str, 4, &mock_loc);

            if (!strcmp(tmp_str + mock_loc, "A"))                     //Handle address Any 
            {
                if( !GetApapterIP((unsigned*)tmp_ip, AF_INET, true)) return ADAPTER_ERR;
            }
                
            else if (!strcmp(tmp_str + mock_loc, "LH"))               // Handle localhost
            {
                tmp_ip[3] = 127;  tmp_ip[2] = 0;   tmp_ip[1] = 0; tmp_ip[0] = 1;
            }
            else return BAD_IP;

        }

        byte_loc = stop_loc + 1;

        // Port/s parsing
        if (byte_loc >= length) return BAD_SYNTAX;

        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (record[byte_loc] == '|') byte_loc++;
        if (byte_loc >= length) return BAD_SYNTAX;
        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (byte_loc >= length) return BAD_SYNTAX;

        for (stop_loc = byte_loc + 1; stop_loc < length; ++stop_loc)
            if (record[stop_loc] == '|') break;


        if (stop_loc == length)  return BAD_SYNTAX;

        --stop_loc;
        char* portStr = (char*)malloc(stop_loc - byte_loc + 1);
        memset(portStr, 0, stop_loc - byte_loc + 1);
        memcpy(portStr, record + byte_loc, stop_loc - byte_loc + 1);
        ports_found = 0;

        if (strstr(record, ","))
        {
            char* part = strtok(portStr, ",");
            int tmpPort;

            while (part != NULL)
            {
                ++ports_found;
                tmpPort = atoi(part);
                if (errno == EINVAL || errno == ERANGE || tmpPort > 65535 || tmpPort < 0)
                {
                    free(portStr);
                    return BAD_PORTS;
                }

                port_arr[ports_found - 1] = tmpPort;
                part = strtok(NULL, ",");
            }
        }
        else { port_arr[ports_found] = atoi(portStr); ports_found++; }
        free(portStr);

        if (ports_found == 0)   return BAD_PORTS;

        byte_loc = stop_loc + 2;
        byte_loc = stop_loc + 2;
        if (byte_loc >= length) return BAD_SYNTAX;

        // Parsing service
        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (record[byte_loc] == '|') byte_loc++;
        if (byte_loc >= length) return BAD_SYNTAX;
        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (byte_loc >= length) return BAD_SYNTAX;

        tmp_service = record[byte_loc] - '0';
        if (tmp_service < 0 || tmp_service>4) return BAD_SERVICE;

        //Seek closing Tag
        bool stop_tag_found = false;
        for (stop_loc = byte_loc + 1; stop_loc < length; ++stop_loc)
            if (record[stop_loc] == '$') { stop_tag_found = true; break; }

        if (!stop_tag_found) return NO_CLS_TAG;

        --stop_loc;
        SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        SkipSpacingsBack(&record[byte_loc], length, &stop_loc);

        if (socket_group_params == NULL) return NULL_PARAM_DETECTED;
        else
        {
  
            socket_group_params->address_ipv4 = *((unsigned*)(tmp_ip));
            socket_group_params->context_code = tmp_service;
            socket_group_params->port_units = ports_found;
            if (socket_group_params->ports == NULL) return NULL_PARAM_DETECTED;
            else
            { 
                memset(socket_group_params->ports, 0, ports_found * 2);
                memcpy(socket_group_params->ports, port_arr, ports_found * 2);
            }
            
         }
        *end_ptr = stop_loc+1;
        return OK;
    }

    void LoadNetworkingParams(FILE** file, NETWORKING_PARAMS* network_params) {
        network_params->Initialize();

        if (file == NULL || *file == NULL) return;
        FILE* fptr = *file;
        
        char buff[MAX_RECORD_LENGTH];
        memset(buff, 0, MAX_RECORD_LENGTH);
        char* buff_it = buff;

        int cls_idx = 0;
        char cut_chr_old_val = 0;
        bool line_proccessing = false;
        bool load_flag = true;
        char* delimit_ptr = NULL;
        unsigned short total_acc_socks_found = 0;
        while (true)                         //Read line by line 
        {
            if (load_flag)
                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return;


            if (strstr(buff_it, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                do
                {
                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return;

                    cls_idx = 0;
                }                 while (!(delimit_ptr = strstr(buff_it, "#")));
                ++delimit_ptr;

                //Trim Skip section ending
                sprintf_s(buff_it, MAX_RECORD_LENGTH, "%s\0", delimit_ptr);
                cls_idx = 0;
            }

            // Seek % starter          
            bool seek_proto = false;
            for (cls_idx; cls_idx < MAX_RECORD_LENGTH; ++cls_idx)   // Seek in current line
            {
                if (cls_idx == MAX_RECORD_LENGTH || buff_it[cls_idx] == '\r' || buff_it[cls_idx] == '\n') break;          // End of line, take another one
                else if (buff_it[cls_idx] == EOF) return;            // End of file
                else if (buff_it[cls_idx] == '%')
                {
                    ++cls_idx;
                    unsigned short proto_found_id = 0;
                    int skip_offset = 0;
                    char* cutPtr = NULL;
                    if (cls_idx < MAX_RECORD_LENGTH)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if ((cutPtr = strstr(buff_it, "%PROTOCOL\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 9;
                            cut_chr_old_val = buff_it[15];                                //Save
                            buff_it[15] = '\0';                                         //Cut
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;    //Compare
                            buff_it[15] = cut_chr_old_val;                                //Restore
                            buff_it = buff_it + skip_offset + 7;
                        }
                        else if (cutPtr = strstr(buff_it, "%PROTOCOL"))
                        {
                            buff_it = cutPtr;
                            skip_offset = 9;
                            cut_chr_old_val = buff_it[15];                                //Save
                            buff_it[15] = '\0';                                         //Cut
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;    //Compare
                            buff_it[15] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;//Restore   
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTOCO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 10;
                            cut_chr_old_val = buff_it[16];
                            buff_it[16] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[16] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTOC\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 11;
                            cut_chr_old_val = buff_it[17];
                            buff_it[17] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[17] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROTO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 12;
                            cut_chr_old_val = buff_it[18];
                            buff_it[18] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[18] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PROT\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 13;
                            cut_chr_old_val = buff_it[19];
                            buff_it[19] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[19] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PRO\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 14;
                            cut_chr_old_val = buff_it[20];
                            buff_it[20] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[20] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%PR\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 15;
                            cut_chr_old_val = buff_it[21];
                            buff_it[21] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[21] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it, "%P\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 16;
                            cut_chr_old_val = buff_it[22];
                            buff_it[22] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[22] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }
                        else if ((cutPtr = strstr(buff_it + cls_idx + skip_offset, "%\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                        {
                            buff_it = cutPtr;
                            skip_offset = 17;
                            cut_chr_old_val = buff_it[23];
                            buff_it[23] = '\0';
                            if (!strcmp(buff_it + skip_offset + 1, "\"TCP\""))  proto_found_id = 1;
                            buff_it[23] = cut_chr_old_val;
                            buff_it = buff_it + skip_offset + 7;
                            skip_offset += 7;
                        }

                        if (proto_found_id == 1) // Has TCP params
                        {
                            if (network_params->tcp_params == NULL)
                            {
                                network_params->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));          // First TCP param
                                network_params->tcp_params->Initialize();
                            }

                            int start, stop = -1;
                            bool open_body_found = false;

                            for (int loc = 0; loc < MAX_RECORD_LENGTH; ++loc)  // Continue searching in same line
                            {
                                if (buff_it[loc] == '_' || buff_it[loc] == '\t')
                                    SkipSpacingsFront(&buff_it[loc], MAX_RECORD_LENGTH, &loc);
                                if (buff_it[loc] == EOF)  return;  // Bad syntax-no closing tag
                                if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                                {
                                    do
                                        if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                                            return;
                                    while (strlen(buff_it) == 0);
                                    loc = 0;
                                    SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
                                    loc = -1;   // Restarts loc to 0 after break;
                                    continue;
                                }

                                if (buff_it[loc] == '{')                                    // Body detected
                                {
                                    open_body_found = true;
                                    ++loc;
                                    SkipSpacingsFront(buff_it + loc, MAX_RECORD_LENGTH - loc, &loc);   // Skip body spacings
                                    if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                                    {
                                        if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return;
                                        loc = 0;
                                        SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
                                        loc = -1;   // Restarts loc to 0 after break;
                                        continue;
                                    }
                                }

                                if (open_body_found)                                                       //Seek body start
                                {
                                    bool open_tag_found = false, closed_tag_found = false;
                                    int finded_at_line = -1, total_lines_from_here = 0;
                                    char record_str[MAX_RECORD_LENGTH];
                                    for (int line_loc = loc; line_loc < MAX_RECORD_LENGTH; ++line_loc)  // Continue searching in same line
                                    {
                                        if (line_loc >= MAX_RECORD_LENGTH || buff_it[line_loc] == '\r' || buff_it[line_loc] == '\n')    // If end line -> load new line
                                        {
                                            if (open_tag_found && !closed_tag_found && finded_at_line == total_lines_from_here)
                                            {
                                                memset(record_str, 0, MAX_RECORD_LENGTH);
                                                memcpy(record_str, buff_it + line_loc, MAX_RECORD_LENGTH - line_loc);
                                            }

                                            do
                                            {
                                                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) return;
                                                else { line_loc = 0; ++total_lines_from_here; SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH, &line_loc); buff_it += line_loc; }
                                            } while (line_loc == MAX_RECORD_LENGTH);

                                            line_loc = -1;
                                            continue;
                                        }

                                        if (buff_it[line_loc] == '$')   // Delimiter found
                                        {
                                            if (!open_body_found && !open_tag_found) { open_tag_found = true; start = line_loc; ++line_loc; finded_at_line = total_lines_from_here; }
                                            else if (open_body_found && !closed_tag_found) { closed_tag_found = true; stop = line_loc; ++line_loc; }

                                            if (open_body_found && closed_tag_found)
                                            {
                                                if (line_loc > 0)
                                                {
                                                    memcpy(buff_it, buff_it + line_loc - 1, MAX_RECORD_LENGTH - line_loc);
                                                    buff_it[MAX_RECORD_LENGTH - line_loc] = '\0';
                                                }

                                                SOCKET_GROUP_PARAMS accept_params;
                                                accept_params.Initialize();
                                                accept_params.ports = (unsigned short*)malloc(MAX_PORTS_PER_RECORD * 2);

                                                if (ParseTCPDefRecord(buff_it, strlen(buff_it), &accept_params, &line_loc) != OK) return;

                                                printf("\n");
                                                printf("Parsed line:\n");
                                                accept_params.Format();
                                                switch (accept_params.context_code)
                                                {
                                                case 0: // It is a listen socket group
                                                {
                                                    network_params->tcp_params->listen_socket_units = accept_params.port_units;   // How many sockets
                                                    if (network_params->tcp_params->listen_socket_params == NULL)                // List of ther IP + PORT
                                                    {
                                                        network_params->tcp_params->listen_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * accept_params.port_units);
                                                        for (int loc = 0; loc < accept_params.port_units; ++loc)
                                                        {
                                                            if (network_params->tcp_params != NULL &&
                                                                network_params->tcp_params->listen_socket_params != NULL)
                                                            {
                                                                network_params->tcp_params->listen_socket_params[loc].address_ipv4 = accept_params.address_ipv4;
                                                                network_params->tcp_params->listen_socket_params[loc].port = accept_params.ports[loc];
                                                            }
                                                        }
                                                    }
                                                    ++line_loc;
                                                    open_tag_found = false;
                                                    closed_tag_found = false;
                                                    continue;
                                                }
                                                case 1: case 2: case 3: case 4: // It is an accept socket
                                                {
                                                    total_acc_socks_found += accept_params.port_units;
                                                    network_params->tcp_params->accept_socket_units = total_acc_socks_found;
                                                    if (network_params->tcp_params->accept_socket_contexts == NULL)  // Hosting services codes
                                                    {
                                                        network_params->tcp_params->accept_socket_contexts = (unsigned char*)malloc(MAX_ACCEPT_SOCKETS * 2);
                                                    }

                                                    if (network_params->tcp_params->accept_socket_params == NULL)
                                                    {
                                                        network_params->tcp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * MAX_ACCEPT_SOCKETS);
                                                    }

                                                    for (int loc = total_acc_socks_found - accept_params.port_units, innerLoc = 0; loc < total_acc_socks_found; ++loc, ++innerLoc)
                                                    {
                                                        if (network_params->tcp_params != NULL &&
                                                            network_params->tcp_params->accept_socket_params != NULL &&
                                                            network_params->tcp_params->accept_socket_contexts != NULL)
                                                        {
                                                            network_params->tcp_params->accept_socket_params[loc].address_ipv4 = accept_params.address_ipv4;
                                                            network_params->tcp_params->accept_socket_params[loc].port = accept_params.ports[innerLoc];
                                                            network_params->tcp_params->accept_socket_contexts[loc] = accept_params.context_code;
                                                        }
                                                    }

                                                    ++line_loc;
                                                    open_tag_found = false;
                                                    closed_tag_found = false;
                                                    continue;
                                                }
                                                }
                                            }
                                        }
                                        else if (buff_it[line_loc] == '}')
                                        {
                                            cls_idx = line_loc + 2;     // Skip }%
                                            seek_proto = true;
                                            break;
                                        }
                                    }

                                    // Puca na free startbuff_itPtr, provjeravao sam ne oslobadjam ga nigdje ranije, nije NULL i drzi staru vrijednost sa pocetka???
                                    if (open_body_found == true)  return;    // No } closure
                                    if (seek_proto) break;   // Brake
                                }
                            }
                        }
                    }
                }
            }
        }
        return;
    }

#pragma endregion


