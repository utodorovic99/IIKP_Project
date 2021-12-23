#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

#include "Networking.h"
#include "Buffering.h"

#pragma comment(lib, "ws2_32.lib")

#pragma region IgnoreWarnings
    #pragma warning(suppress : 6387)
    #pragma warning(suppress : 6011)
    #pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
    #define MAX_MEDIATOR_BUFF_SIZE 255
    #define MAX_SERVICE_NAME_SIZE (MAX_BUFF_NAME-10)
#pragma endregion

NETWORKING_PARAMS* networkParams = NULL;
BUFF_DESC* buffers               = NULL;
BUFF_DESC* input_buffer          = NULL;
BUFF_DESC* ack_buffer            = NULL;
BUFF_DESC* service_buffers_in    = NULL;
BUFF_DESC* service_buffers_out   = NULL;
char** serviceNames;

int main()
{
    printf("==================================================================================================\n");

    WSAData wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
        printf("WSAStartup Failed\n");
        return -1;
    }

    bool escapeFlag = false;
    switch (true) {
        case true:
        {
            char cCurrentPath[FILENAME_MAX];
            if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
            {
                printf("NetCfg file missing, closing..\n");
                break;
            }
            else
                printf("Loading network config data..\n");

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
                break;
            }

            networkParams = (NETWORKING_PARAMS*)malloc(sizeof(NETWORKING_PARAMS));
            if (networkParams == NULL) break;
            networkParams->Prepare();
            
            // Load network params
            
            char* inputDataMemoryChunk = (char*)malloc(MAX_MEDIATOR_BUFF_SIZE);    
            NETWORKING_PARAMS tmpNetworkParams = LoadNetworkingParams(inputDataMemoryChunk, &fptr);
            fclose(fptr);
            
            // Manually copy, realloc would mess pointers up
            if (tmpNetworkParams.udp_params != NULL)
            {
                networkParams->udp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmpNetworkParams.udp_params->accept_socket_units);
                if (networkParams->udp_params->accept_socket_params == NULL) break;
                memcpy(networkParams->udp_params->accept_socket_params,
                    tmpNetworkParams.udp_params->accept_socket_params,
                    sizeof(SOCKETPARAMS) * tmpNetworkParams.udp_params->accept_socket_units);

                networkParams->udp_params->accept_socket_contexts = (unsigned char*)malloc(tmpNetworkParams.udp_params->accept_socket_units);
                if (networkParams->udp_params->accept_socket_contexts==NULL) break;
                memcpy(networkParams->udp_params->accept_socket_contexts,
                    tmpNetworkParams.udp_params->accept_socket_contexts,
                    tmpNetworkParams.udp_params->accept_socket_units);    
            }

            if (tmpNetworkParams.tcp_params != NULL)
            {
                networkParams->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));
                if (networkParams->tcp_params == NULL) break;
                networkParams->tcp_params->listen_socket_units = tmpNetworkParams.tcp_params->listen_socket_units;
                networkParams->tcp_params->accept_socket_units = tmpNetworkParams.tcp_params->accept_socket_units;
                
                if (tmpNetworkParams.tcp_params->listen_socket_params != NULL)
                {
                    networkParams->tcp_params->listen_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmpNetworkParams.tcp_params->listen_socket_units);
                    if (networkParams->tcp_params->listen_socket_params == NULL) break;
                    memcpy(networkParams->tcp_params->listen_socket_params, 
                        tmpNetworkParams.tcp_params->listen_socket_params,
                            sizeof(SOCKETPARAMS) * tmpNetworkParams.tcp_params->listen_socket_units);
                }

                if (tmpNetworkParams.tcp_params->accept_socket_params != NULL)
                {
                    networkParams->tcp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmpNetworkParams.tcp_params->accept_socket_units);
                    if (networkParams->tcp_params->accept_socket_params == NULL) break;
                    memcpy(networkParams->tcp_params->accept_socket_params, 
                        tmpNetworkParams.tcp_params->accept_socket_params, 
                        tmpNetworkParams.tcp_params->accept_socket_units * sizeof(SOCKETPARAMS));

                    networkParams->tcp_params->accept_socket_contexts = (unsigned char*)malloc(tmpNetworkParams.tcp_params->accept_socket_units);
                    if (networkParams->tcp_params->accept_socket_contexts == NULL) break;
                    memcpy(networkParams->tcp_params->accept_socket_contexts,
                        tmpNetworkParams.tcp_params->accept_socket_contexts,
                        tmpNetworkParams.tcp_params->accept_socket_units);
                }
                
            }
            free(inputDataMemoryChunk);
            
            serviceNames = (char**)(malloc(sizeof(char*) * networkParams->tcp_params->accept_socket_units));
            if (serviceNames == NULL) break;

            for (int nameLoc = 0; nameLoc < networkParams->tcp_params->accept_socket_units; ++nameLoc)
            {
                serviceNames[nameLoc] = (char*)malloc(sizeof(char) * (MAX_SERVICE_NAME_SIZE + 1));
                if (serviceNames == NULL) 
                    { escapeFlag = true; break; }
            }
            if (escapeFlag) break;

            buffers = (BUFF_DESC*)(malloc(sizeof(BUFF_DESC) * (2 + networkParams->tcp_params->accept_socket_units * 2)));
            if (buffers == NULL) break;
            for (int loc = 0; loc < 2 + networkParams->tcp_params->accept_socket_units * 2; ++loc)
                (buffers + loc)->Prepare();
            
            //////////////////////////////////////MANUALLY LOADING BUFFER PARAMS//////////////////////////////////////////
            bool successFlag = false;
            cCurrentPath[FILENAME_MAX];
            if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
            {
                printf("MemCfg file missing, closing..\n");
                break;
            }
            else
                printf("Loading memory config data..\n");

            while (cCurrentPath[strlen(cCurrentPath) - 1] != '\\')
                cCurrentPath[strlen(cCurrentPath) - 1] = '\0';

            strcat_s(cCurrentPath, "\\Release\\MemCfg.txt");

            cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
            //Append config file name

            fptr = NULL;
            fopen_s(&fptr, cCurrentPath, "rb");
            if (!fptr)
            {
                printf("Opening MemCfg failed, closing..\n");
                break;
            }
            BUFF_PARAMS buffParams = LoadBufferParams(&fptr, &successFlag);
            fclose(fptr);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////
            input_buffer = &(buffers[INBUF]);

            input_buffer->context = INBUF;                                     // Allocate for single input buff
            input_buffer->capacity = buffParams.inqueue;
            input_buffer->memory = (char*)(malloc(buffers[INBUF].capacity));
            if (input_buffer->memory == NULL) break;

            input_buffer->Initialize();
            sprintf_s(input_buffer->name, "%s", "INPUT BUFF");
             
            ack_buffer = &(buffers[ACKBUF]);
            ack_buffer->context = ACKBUF;                                   
            ack_buffer->capacity = buffParams.ackqueue;
            ack_buffer->memory = (char*)(malloc(buffers[ACKBUF].capacity));
            if (ack_buffer->memory == NULL) break;

            ack_buffer->Initialize();
            sprintf_s(ack_buffer->name, "%s", "ACK BUFF");

            service_buffers_in = &(buffers[INBUF_SRV]);
            for (int acc_bufloc = 0; acc_bufloc < networkParams->tcp_params->accept_socket_units; ++acc_bufloc)
                if (((service_buffers_in + acc_bufloc)->memory = (char*)malloc(buffParams.service_in_queue)) == NULL)
                {escapeFlag = true;  break;}
                else
                {
                    (service_buffers_in + acc_bufloc)->context = INBUF_SRV;
                    (service_buffers_in + acc_bufloc)->capacity = buffParams.service_in_queue;
                    (service_buffers_in + acc_bufloc)->Initialize();
                }
            if (escapeFlag) break;
                    
            service_buffers_out = &(buffers[INBUF_SRV + networkParams->tcp_params->accept_socket_units]);
            for (int acc_bufloc = 0; acc_bufloc < networkParams->tcp_params->accept_socket_units; ++acc_bufloc)
                if (((service_buffers_out + acc_bufloc)->memory = (char*)malloc(buffParams.service_out_queue)) == NULL)
                {escapeFlag = true;  break;}
                else
                {
                    (service_buffers_out + acc_bufloc)->context = OUTBUF_SRV;
                    (service_buffers_out + acc_bufloc)->capacity= buffParams.service_out_queue;
                    (service_buffers_out + acc_bufloc)->Initialize();
                }
            if (escapeFlag) break;

            char* tmpBuff = (char*)(malloc(MAX_SERVICE_NAME_SIZE+1));
            if (tmpBuff == NULL) break;
            printf("\n\nName initial services:\n\t[TOTAL : %hu]\n\t[MAX NAME LENGTH : %d]\n\n", networkParams->tcp_params->accept_socket_units, MAX_SERVICE_NAME_SIZE);
            
            bool triggerReEnter = false;
            for (int service_bufloc = 0; service_bufloc < networkParams->tcp_params->accept_socket_units; ++service_bufloc)
            {
                memset(tmpBuff, 0, MAX_SERVICE_NAME_SIZE + 1);
                printf("Service %d: ", service_bufloc);
                gets_s(tmpBuff, MAX_SERVICE_NAME_SIZE);

                triggerReEnter = false;
                for (int usedNames = 0; usedNames < service_bufloc; usedNames++)
                {
                    if (!strcmp(tmpBuff, serviceNames[usedNames]))
                    {
                        printf("\tERROR: Name already used!\n");
                        --service_bufloc;
                        triggerReEnter = true;
                        break;
                    }
                }
                if (triggerReEnter) continue;

                memcpy(serviceNames[service_bufloc], tmpBuff, MAX_SERVICE_NAME_SIZE);
                sprintf((service_buffers_in +service_bufloc)->name, "%s|SEND BUFF", tmpBuff);
                sprintf((service_buffers_out + service_bufloc)->name, "%s|RECV BUFF", tmpBuff);
            }
            free(tmpBuff);  
        }
    }
    printf("==================================================================================================\n");
    printf("-- Network Stats --\n");
    networkParams->tcp_params->Format();
    printf("\n");
    printf("-- Buffering Stats --\n");
    printf("\tBuffer Name: %s\n", ack_buffer->name);
    printf("\tBuffer Name: %s\n", input_buffer->name);
    for (int service_bufloc = 0; service_bufloc < networkParams->tcp_params->accept_socket_units; ++service_bufloc)
    {
        printf("\tBuffer Name: %s\n", (service_buffers_in + service_bufloc)->name);
        printf("\tBuffer Name: %s\n", (service_buffers_out + service_bufloc)->name);
    }
    printf("\n");
    printf("-- Service Stats --\n");
    for (int service_bufloc = 0; service_bufloc < networkParams->tcp_params->accept_socket_units; ++service_bufloc)
        printf("\tService Name: %s\n", serviceNames[service_bufloc]);
    printf("==================================================================================================\n");

    // Dispose after break
    WSACleanup();
    networkParams->Dispose();
    free(networkParams);

    if (buffers != NULL)
    {
        input_buffer->Dispose();
        ack_buffer->Dispose();

        for (int acc_bufloc = 0; acc_bufloc < networkParams->tcp_params->accept_socket_units; ++acc_bufloc)
            (service_buffers_in + acc_bufloc)->Dispose();

        for (int acc_bufloc = 0; acc_bufloc < networkParams->tcp_params->accept_socket_units; ++acc_bufloc)
            (service_buffers_out + acc_bufloc)->Dispose();

        free(buffers);
    }
    if (serviceNames != NULL) free(serviceNames);
    
    printf("Press any key to close...");
    char output=getchar();
}



