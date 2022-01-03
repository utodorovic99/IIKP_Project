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
#include "Queueing.h"
#include "Messages.h"
#include "Common.h"
#include "protocol_headers.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996) 

#pragma region IgnoreWarnings
    #pragma warning(suppress : 6387)
    #pragma warning(suppress : 6011)
    #pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
    #define REQUEST_ACQUISITION_INTERVAL_SECS 1
    #define SOCKET_INITIALIZE_INTERVAL 2000
    #define MAX_MEDIATOR_BUFF_SIZE 255
    #define MAX_SERVICES_HOSTED 10
    #define MAX_MESSAGE_SIZE 255    
    #define MAX_INPUT_CONNS 1 
#pragma endregion

#pragma region Synchronization
    CRITICAL_SECTION disp;
#pragma endregion

#pragma region Globals
    unsigned thread_counter = 0;    // Sync-ed by dsp cs (closing thread followed by disp writing )
#pragma endregion

// Handles delta services sent by other service
void HandleDeltaServices(char* message_buff, SERVICE_NAME* service_names, SERVICE_NAME** new_services)
{  
    // Parse message to list of service strings
    char* part = strtok(message_buff, "|");
    SERVICE_NAME* tmpEl;
    while (part != NULL)
    {
        tmpEl = (SERVICE_NAME*)malloc(sizeof(SERVICE_NAME));
        tmpEl->Initialize();
        tmpEl->name = (char*)malloc(strlen(part));
        sprintf(tmpEl->name, "%s\0", part);
        tmpEl->length = strlen(tmpEl->name);
        if(tmpEl->length > MAX_SERVICE_NAME_SIZE)
        {
            tmpEl->Dispose();
            free(tmpEl);
            break;
        }
        else if(!service_names->Contains(tmpEl, service_names))
            (*new_services)->Insert(tmpEl, new_services);
           
        part = strtok(NULL, "|");
    } 
}

// Handles service messages from other service
void HandleServiceMsg()
{

}

void GenerateDeltaMsg(SETUP_MSG* msg, SERVICE_NAME* service_names)
{
    msg->Initialize();
    msg->msg_code = SERVICES_ENL;
    msg->content_size = (MAX_SERVICE_NAME_SIZE + 1) * MAX_ACCEPT_SOCKETS + (MAX_ACCEPT_SOCKETS - 1) + 1;
    msg->content = (char*)malloc(msg->content_size);
    memset(msg->content, 0, msg->content_size);
    service_names->Format(msg->content, msg->content_size, service_names->Count(service_names), service_names);
    msg->content[strlen(msg->content)] = '\0';
    msg->content_size=strlen(msg->content) + 1;

}

// Listens for service-service connections, accepts them and priviedes hosted services
// Recieves messages
DWORD WINAPI ListenSocketThr(LPVOID lpParam)
{
    EnterCriticalSection(&disp);
    printf("[THREAD LST/RECV]:\n\tThread started\n\n");
    LeaveCriticalSection(&disp);
    LISTENING_THR_PARAMS params = *((LISTENING_THR_PARAMS*)lpParam);

    SOCKET tmpSocket;
    sockaddr_in tmpAddr;

    if (bind(*(params.listen_socket_params->socket),(struct sockaddr*)params.listen_socket_params->address,sizeof(*params.listen_socket_params->address)) == SOCKET_ERROR)
    {
        EnterCriticalSection(&disp);
        printf("[THREAD LST/RECV]:\n\tListen socket bind failed with error code : %d\n\n", WSAGetLastError());
        LeaveCriticalSection(&disp);
        params.listen_socket_params->initialized = false;
        while (!*(params.end_thr_flag)) Sleep(1000);// Wait for safe shutdown
        EnterCriticalSection(&disp);
        --thread_counter;
        LeaveCriticalSection(&disp);
        return -1;
    }
    else 
        params.listen_socket_params->initialized = true;
    
    listen(*(params.listen_socket_params->socket), SOMAXCONN);
    unsigned long mode = 1;
    //Initialize FDSETs
    fd_set read_set;
    fd_set exc_set;
    FD_ZERO(&read_set);
    FD_ZERO(&exc_set);
    if (ioctlsocket(*params.listen_socket_params->socket, FIONBIO, &mode) == 0)    // Try add listen socket
    {FD_SET(*(params.listen_socket_params->socket), &read_set); FD_SET(*(params.listen_socket_params->socket), &exc_set);} // If Yes add him to the set
    else
    {
        closesocket(*params.listen_socket_params->socket);                         // If not stop executing
        *params.listen_socket_params->socket = INVALID_SOCKET;
        EnterCriticalSection(&disp);
        printf("[THREAD LST/RECV]:\n\tListening at: %s:%hu failed\n\n", inet_ntoa(params.listen_socket_params->address->sin_addr), htons(params.listen_socket_params->address->sin_port));
        LeaveCriticalSection(&disp);

        while (!*(params.end_thr_flag)) Sleep(1000);// Wait for safe shutdown
        EnterCriticalSection(&disp);
        --thread_counter;
        LeaveCriticalSection(&disp);
        return -1;
    }
    EnterCriticalSection(&disp);
    printf("[THREAD LST/RECV]:\n\tListening at: %s:%hu\n\n", inet_ntoa(params.listen_socket_params->address->sin_addr), ntohs(params.listen_socket_params->address->sin_port));
    LeaveCriticalSection(&disp);

    for (OUT_SERVICE* sub = params.subscriebers; sub != NULL; sub = sub->next)     // Add all client sockets to the set
        {FD_SET(*sub->socket, &read_set); FD_SET(*sub->socket, &exc_set);}

    timeval timeVal;
    timeVal.tv_sec = REQUEST_ACQUISITION_INTERVAL_SECS;
    timeVal.tv_usec = 0;

    int clientsAccepted = 0; 
    SETUP_MSG msg;
    GenerateDeltaMsg(&msg, params.service_names);

    int iResult;
    char message_buff[MAX_MESSAGE_SIZE];
    while (!*(params.end_thr_flag))
    {

        iResult = select(0, &read_set, NULL, &exc_set, &timeVal);
        if (iResult == SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[THREAD LST/RECV]:\n\tAn error occurred on: Select socket\n\n");
            LeaveCriticalSection(&disp);
        }
        else if (iResult > 0)
        {
            EnterCriticalSection(&disp);
            printf("[THREAD LST/RECV]:\n\tAcquisition done: %d events detected\n\n", iResult);
            LeaveCriticalSection(&disp);
            for (OUT_SERVICE* sub = params.subscriebers; sub != NULL; sub = sub->next)
            {
                if (FD_ISSET(*sub->socket, &read_set))   // Client sent something
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tMessage from: %s:%hu\n\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                    LeaveCriticalSection(&disp);
                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    recv(*sub->socket, message_buff, MAX_MESSAGE_SIZE, 0);


                    switch (message_buff[0])
                    {
                        case SERVICES_ENL: 
                        {
                            SETUP_MSG recved_msg;
                            recved_msg.Initialize();
                            recved_msg.msg_code = *((unsigned short*)message_buff);
                            recved_msg.content_size= *((unsigned*)(message_buff+2));
                            recved_msg.content = message_buff + 6;
                            SERVICE_NAME* new_names = NULL;
                            HandleDeltaServices(recved_msg.content,params.service_names, &new_names);
                            #pragma omp atomic capture
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV] Delta services:\n");
                                new_names->PrintOut(new_names);
                                printf("\n\n");
                                printf("[THREAD LST/RECV] Creating delta buffers..\n\n");
                                LeaveCriticalSection(&disp);
                                // Create delta buffers
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV] Creating delta threads..\n\n");
                                LeaveCriticalSection(&disp);
                                // Start threads                                 
                                /*BUFF_DESC* new_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                                new_buff->Initialize();
                                if (service_buffers_in == NULL) service_buffers_in = tmp_buff;
                                else service_buffers_in->Insert(tmp_buff, &service_buffers_in);

                                if ((tmp_buff->memory = (char*)malloc(buffParams.service_in_queue)) == NULL)
                                {
                                    escapeFlag = true;  break;
                                }
                                else
                                {
                                    tmp_buff->context = INBUF_SRV;
                                    tmp_buff->capacity = buffParams.service_in_queue;
                                    tmp_buff->Prepare();
                                }

                                tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                                tmp_buff->Initialize();
                                if (service_buffers_out == NULL) service_buffers_out = tmp_buff;
                                else service_buffers_out->Insert(tmp_buff, &service_buffers_out);

                                if ((tmp_buff->memory = (char*)malloc(buffParams.service_out_queue)) == NULL)
                                {
                                    escapeFlag = true;  break;
                                }
                                else
                                {
                                    tmp_buff->context = OUTBUF_SRV;
                                    tmp_buff->capacity = buffParams.service_out_queue;
                                    tmp_buff->Prepare();
                                }*/
                                // Create loader thread
                                //HANDLE_LST* load_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                //if (load_handle == NULL) { escapeFlag = true; break; }

                                //load_handle->Initialize();
                                //load_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                //threadIDs[thread_counter] = thread_counter;

                                //SERVICE_LOADER_THR_PARAMS* service_loader_thr_param = (SERVICE_LOADER_THR_PARAMS*)malloc(sizeof(SERVICE_LOADER_THR_PARAMS));
                                //service_loader_thr_param->Initialize();
                                //memcpy(service_loader_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                                //service_loader_thr_param->in_buffer = input_buffer;             // Reds from common input buffer            

                                //memset(service_name, 0, MAX_BUFF_NAME + 1);
                                //sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Writes into service send buffer (Queue Service Point of View) 
                                //service_loader_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                                //service_loader_thr_param->end_thr_flag = &thr_shudown_flag;

                                //*load_handle->handle = CreateThread(NULL, 0, &ServiceLoaderThr, service_loader_thr_param, 0, threadIDs + thread_counter);
                                //listenSocketHandles->Insert(load_handle, &listenSocketHandles);
                                //++thread_counter;

                                //// Create GC thread
                                //HANDLE_LST* GC_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                //if (GC_handle == NULL) { escapeFlag = true; break; }

                                //GC_handle->Initialize();
                                //GC_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                //threadIDs[thread_counter] = thread_counter;

                                //SERVICE_GC_THR_PARAMS* GC_thr_param = (SERVICE_GC_THR_PARAMS*)malloc(sizeof(SERVICE_GC_THR_PARAMS));
                                //GC_thr_param->Initialize();
                                //memcpy(GC_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                                //GC_thr_param->in_buffer = ack_buffer;               // Reads from common ack buffer

                                //memset(service_name, 0, MAX_BUFF_NAME + 1);
                                //sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Deletes from send buffer
                                //GC_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                                //GC_thr_param->end_thr_flag = &thr_shudown_flag;
                                //*GC_handle->handle = CreateThread(NULL, 0, &ServiceGCThr, GC_thr_param, 0, threadIDs + thread_counter);
                                //GCHandle->Insert(GC_handle, &GCHandle);
                                //++thread_counter;

                                //// Create client communication thread
                                //SOCKET_DATA* client_socket = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
                                //if (client_socket == NULL) break;
                                //client_socket->Initialize();

                                //client_socket->socket = (SOCKET*)malloc(sizeof(SOCKET));
                                //if (client_socket->socket == NULL) break;
                                //*client_socket->socket = INVALID_SOCKET;

                                //if ((*(client_socket->socket) = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
                                //{
                                //    EnterCriticalSection(&disp);
                                //    printf("An error occurred creating client buffering socket\n");
                                //    LeaveCriticalSection(&disp);
                                //}
                                //else ++validClientsSockets;

                                //client_socket->address = (sockaddr_in*)malloc(sizeof(sockaddr_in));
                                //client_socket->address->sin_family = AF_INET;
                                //networkParams->tcp_params->accept_socket_params[loc].FormatIP(ip_formatted);
                                //client_socket->address->sin_addr.s_addr = inet_addr(ip_formatted);
                                //client_socket->address->sin_port = htons(networkParams->tcp_params->accept_socket_params[loc].port);
                                //client_socket_params->Insert(client_socket, &client_socket_params);

                                //HANDLE_LST* client_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                //if (client_handle == NULL) { escapeFlag = true; break; }

                                //client_handle->Initialize();
                                //client_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                //threadIDs[thread_counter] = thread_counter;

                                //CLIENT_THR_PARAMS* client_thr_param = (CLIENT_THR_PARAMS*)malloc(sizeof(CLIENT_THR_PARAMS));
                                //client_thr_param->Initialize();
                                //memcpy(client_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                                //memset(service_name, 0, MAX_BUFF_NAME + 1);
                                //sprintf(service_name, "%s|RECV BUFF", service_names_it->name);      // Reads what comes from sockets and stores it
                                //client_thr_param->in_buffer = service_buffers_in->FindByName(service_name, service_buffers_in);

                                //memset(service_name, 0, MAX_BUFF_NAME + 1);                         // Reads what commes from mirroring and sends it trough socket
                                //sprintf(service_name, "%s|SEND BUFF", service_names_it->name);
                                //client_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                                //client_thr_param->end_thr_flag = &thr_shudown_flag;
                                //*client_handle->handle = CreateThread(NULL, 0, &ClientReqHandleThr, client_thr_param, 0, threadIDs + thread_counter);
                                //clientReqHandle->Insert(client_handle, &clientReqHandle);
                                //++thread_counter;
                                //
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV] Delta threads created\n\n");
                                LeaveCriticalSection(&disp);
                            }              
                            
                            free(new_names);
                            break; 
                        }
                        case SERVICE_MSG: 
                        {
                            HandleServiceMsg();
                            break; 
                        }
                    }
                }

                if (FD_ISSET(*sub->socket, &read_set))   // Error
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tAn error occurred communicating with service on: %s:%hu\n\n",
                        inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                    LeaveCriticalSection(&disp);

                    params.subscriebers->RemoveByRef(sub, &params.subscriebers);
                }
            }

            if (FD_ISSET(*params.listen_socket_params->socket, &read_set)) // If accept requested
            {
                // No accept if max. client number is reached.
                if (clientsAccepted >= MAX_INPUT_CONNS)
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tAccept service socket aborted: \"%d connections allowed\"\n\n", MAX_INPUT_CONNS);
                    LeaveCriticalSection(&disp);
                }
                else
                {
                    do
                    {
                        // If not Try - accept
                        int addr_len = sizeof(sockaddr_in);
                        tmpSocket = accept(*params.listen_socket_params->socket, (struct sockaddr*)&tmpAddr, &addr_len);
                        //Ignore if accept failed
                        if (tmpSocket == INVALID_SOCKET)
                        {
                            if (WSAGetLastError() == WSAEWOULDBLOCK) break;// All conns accepted
                            EnterCriticalSection(&disp);
                            printf("[THREAD LST/RECV]:\n\tAccept socket failed with error: %d\n\n", WSAGetLastError()); 
                            LeaveCriticalSection(&disp);
                            continue;
                        }
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST/RECV]:\n\tService accepted at: %s:%hu\n\n", inet_ntoa(tmpAddr.sin_addr), ntohs(tmpAddr.sin_port));
                        LeaveCriticalSection(&disp);

                        // Try set accepted client in non-blocking regime
                        if (ioctlsocket(tmpSocket, FIONBIO, &mode) == 0)
                        {
                            // If user accepted send him services hosted by you
                            char* mess=(char*)malloc(6 + msg.content_size + 1);
                            memset(mess, 0, 6 + msg.content_size + 1);
                            *((unsigned short*)mess) = msg.msg_code;
                            *((unsigned*)(mess+2)) = msg.content_size;
                            memcpy(mess + 6, msg.content, msg.content_size);

                            if (send(tmpSocket, mess, 6+msg.content_size+1, 0) != SOCKET_ERROR)
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV]:\n\tServices offer sent to accepted client\n\n");
                                LeaveCriticalSection(&disp);
                                OUT_SERVICE* sub = (OUT_SERVICE*)malloc(sizeof(OUT_SERVICE));
                                sub->Initialize();
                                sub->address=(sockaddr_in*)(malloc(sizeof(sockaddr_in)));
                                sub->socket = (SOCKET*)(malloc(sizeof(SOCKET)));

                                memcpy(sub->address, &tmpAddr, sizeof(tmpAddr));
                                memcpy(sub->socket, &tmpSocket, sizeof(tmpSocket));
                                for (unsigned loc = 0; loc < params.service_names->Count(params.service_names); ++loc)
                                    sub->service_idx[loc] = loc;    // If recieved subscriebe him to all your servives

                                params.subscriebers->Insert(sub, &params.subscriebers); // Add new when send succeeded
                            }
                            else
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV]:\n\tSending services offer to accepted client failed\n\n");
                                LeaveCriticalSection(&disp);
                                closesocket(tmpSocket);
                                tmpSocket = INVALID_SOCKET;
                            }
                        }
                        else
                        {
                            closesocket(tmpSocket);             // If not reject
                            tmpSocket = INVALID_SOCKET;
                        }
                    }while(!*(params.end_thr_flag));
                }
            }
            
        }

        FD_ZERO(&read_set);
        FD_ZERO(&exc_set);
        FD_SET(*params.listen_socket_params->socket, &read_set);
        for (OUT_SERVICE* sub = params.subscriebers; sub != NULL; sub = sub->next)     // Add all client sockets to the set
            {FD_SET(*sub->socket, &read_set); FD_SET(*sub->socket, &exc_set); }
    }
    free(msg.content);
    EnterCriticalSection(&disp);
    printf("[THREAD LST/RECV]:\n\tClosing thread..\n\n");
    --thread_counter;
    LeaveCriticalSection(&disp);
}

DWORD WINAPI ServiceLoaderThr(LPVOID lpParam)
{
    SERVICE_LOADER_THR_PARAMS params = *((SERVICE_LOADER_THR_PARAMS*)lpParam);

    EnterCriticalSection(&disp);
    printf("[THREAD %s LOAD]:\n\tThread started\n\n", params.service_name);
    LeaveCriticalSection(&disp);
    do
    {
        Sleep(1000);
    } while (!*(params.end_thr_flag));

    EnterCriticalSection(&disp);
    printf("[THREAD %s LOAD]:\n\tClosing thread..\n\n", params.service_name);
    --thread_counter;
    LeaveCriticalSection(&disp);
    return 0;
}

DWORD WINAPI ServiceGCThr(LPVOID lpParam)
{
    SERVICE_GC_THR_PARAMS params = *((SERVICE_GC_THR_PARAMS*)lpParam);
    EnterCriticalSection(&disp);
    printf("[THREAD %s GC]:\n\tThread started\n\n", params.service_name);
    LeaveCriticalSection(&disp);

    do
    {
        Sleep(1000);
    } while (!*(params.end_thr_flag));

    EnterCriticalSection(&disp);
    printf("[THREAD %s GC]:\n\tClosing thread..\n\n", params.service_name);
    --thread_counter;
    LeaveCriticalSection(&disp);
    return 0;
}

DWORD WINAPI InputHandleThr(LPVOID lpParam)
{
    INPUT_THR_PARAMS params = *((INPUT_THR_PARAMS*)lpParam);
    EnterCriticalSection(&disp);
    printf("[THREAD INPUT]:\n\tThread started\n\n");
    LeaveCriticalSection(&disp);

    do
    {
        Sleep(1000);
    } while (!*(params.end_thr_flag));

    EnterCriticalSection(&disp);
    printf("[THREAD INPUT]:\n\tClosing thread..\n\n");
    --thread_counter;
    LeaveCriticalSection(&disp);
    return 0;
}

DWORD WINAPI OutputHandleThr(LPVOID lpParam)
{
    OUTPUT_THR_PARAMS params = *((OUTPUT_THR_PARAMS*)lpParam);
    EnterCriticalSection(&disp);
    printf("[THREAD OUTPUT]:\n\tThread started\n\n");
    LeaveCriticalSection(&disp);

    do
    {
        Sleep(1000);
    } while (!*(params.end_thr_flag));

    EnterCriticalSection(&disp);
    printf("[THREAD OUTPUT]:\n\tClosing thread..\n\n");
    --thread_counter;
    LeaveCriticalSection(&disp);
    return 0;
}

DWORD WINAPI ClientReqHandleThr(LPVOID lpParam)
{
    CLIENT_THR_PARAMS params = *((CLIENT_THR_PARAMS*)lpParam);
    EnterCriticalSection(&disp);
    printf("[THREAD %s CLIENT]:\n\tThread started\n\n", params.service_name);
    LeaveCriticalSection(&disp);

    do
    {
        Sleep(1000);
    } while (!*(params.end_thr_flag));

    EnterCriticalSection(&disp);
    printf("[THREAD %s CLIENT]:\n\tClosing thread..\n\n", params.service_name);
    --thread_counter;
    LeaveCriticalSection(&disp);
    return 0;
}

bool ExposeServices(SOCKETPARAMS* targetParams, SERVICE_NAME* service_names, OUT_SERVICE* subscriebers)
{
    // Define expose message
    SETUP_MSG msg;
    GenerateDeltaMsg(&msg, service_names);

    // Describe target (mirroring servers)
    char ip_formatted[13];
    OUT_SERVICE* outService = (OUT_SERVICE*)malloc(sizeof(OUT_SERVICE));
    outService->Initialize();
    outService->address = (sockaddr_in*)malloc(sizeof(sockaddr_in));
    outService->socket = (SOCKET*)malloc(sizeof(SOCKET));
    outService->address->sin_family = AF_INET;
    targetParams->FormatIP(ip_formatted);
    outService->address->sin_addr.s_addr = inet_addr(ip_formatted);
    outService->address->sin_port = htons(targetParams->port);
    OUT_SERVICE* sub = subscriebers;
    
    // Try find
    sub = subscriebers->FindByAddr(outService, subscriebers);
    bool event_flag = 0;
    if (sub == NULL)    // Not contacted 
    {
        // Contact it
        *outService->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        EnterCriticalSection(&disp);
        printf("[EXPOSE]:\n\tSending services offer to: %s:%hu\n\n", ip_formatted, targetParams->port);
        LeaveCriticalSection(&disp);
        if (connect(*outService->socket, (SOCKADDR*)(outService->address), sizeof(*outService->address)) == SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[EXPOSE]:\n\tContacting %s:%hu failed\n\n", ip_formatted, targetParams->port);
            LeaveCriticalSection(&disp);
            closesocket(*outService->socket);
            *outService->socket = INVALID_SOCKET;
            free(outService->address);
            free(outService->socket);
            free(outService);
            return false;
        }
        else sub = outService;
    }
    else // Was contacted (free old description)
    {
        event_flag = 1;
        free(outService->address);
        free(outService->socket);
        free(outService);
    }

    char* mess = (char*)malloc(6 + msg.content_size + 1);
    memset(mess, 0, 6 + msg.content_size + 1);
    *((unsigned short*)mess) = msg.msg_code;
    *((unsigned*)(mess + 2)) = msg.content_size;
    memcpy(mess + 6, msg.content, msg.content_size);
    if (send(*sub->socket, mess, 6+msg.content_size+1, 0) != SOCKET_ERROR)
    {
        EnterCriticalSection(&disp);
        printf("[EXPOSE]:\n\tServices offer sent to %s:%hu\n\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
        LeaveCriticalSection(&disp);
        if (event_flag) // Wasn't contacted - add all services
        {
            for (unsigned loc = 0; loc < service_names->Count(service_names); ++loc)
                sub->service_idx[loc] = loc;
        }
        else            // Was contacted - add only delta services
        {
            for (unsigned loc = 0; loc < service_names->Count(service_names); ++loc)    // Iterate trough hosted services
            {
                int loc_in;
                for (loc_in = 0; sub->service_idx[loc_in] != -1 && loc_in < MAX_SERVICES_HOSTED; ++loc_in);  // Check if is delta
               
                if (loc_in < MAX_SERVICES_HOSTED && sub->service_idx[loc_in] == -1) // Is Delta
                {
                    sub->service_idx[loc_in] = loc;
                }
                else if (loc_in == MAX_SERVICES_HOSTED)
                {
                    EnterCriticalSection(&disp);
                    printf("[EXPOSE]:\n\tMaximum subscriptions for %s:%hu reached, abored ones:\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                    for (loc_in; loc < service_names->Count(service_names); ++loc)    // Continue iterating trough hosted services
                        printf("\t%s\n", service_names->At(loc, service_names)->name);
                    printf("\n");
                    LeaveCriticalSection(&disp);
                    break;
                }
            }
        }
        return true;
    }
    else //Send failed close socket and remove from list
    {
        EnterCriticalSection(&disp);
        printf("[EXPOSE]:\n\tSending services offer to %s:%hu client failed\n\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
        LeaveCriticalSection(&disp);
        closesocket(*sub->socket);
        *sub->socket = INVALID_SOCKET;
        subscriebers->RemoveByRef(sub, &subscriebers);//Disposes address and socket
        free(sub);
        return false;
    }
}

int main()
{
    // Core variables
    NETWORKING_PARAMS* networkParams    = NULL; // Contains all network data (ports, ip addresses and its function)
    BUFF_PARAMS buffParams;                     // Contains all buffer sizes
    BUFF_DESC* input_buffer             = NULL; // Buffer for incoming data
    BUFF_DESC* ack_buffer               = NULL; // Buffer for ack-ed data
    BUFF_DESC* service_buffers_in       = NULL; // Buffers for each mirror service, client reads them, service writes them ( comes from network )
    BUFF_DESC* service_buffers_out      = NULL; // Buffers for each mirror service, client writes them, service reads them ( goes to network )
    SERVICE_NAME* service_names         = NULL; // List of all service names

    SOCKET_DATA* listen_socket_params   = NULL; // Socket params for each listen socket  ( only 1 supported at the moment )
    SOCKET_DATA* service_socket_params  = NULL; // Socket params for each mirror service ( only 1 supported at the moment )
    SOCKET_DATA* client_socket_params   = NULL; // Socket params for each client using service
    HANDLE_LST* listenSocketHandles     = NULL; // Thread handle listen socket handle thread 
    HANDLE_LST* inputSocketHandle       = NULL; // Thread handle for input socket handle thread
    HANDLE_LST* outputSocketHandle      = NULL; // Thread handle for output socket handle thread
    HANDLE_LST* loaderHandle            = NULL; // Thread handle for loader thread
    HANDLE_LST* GCHandle                = NULL; // Thread handle for GC thread
    HANDLE_LST* clientReqHandle         = NULL; // Thread handle for client req. handle thead

    DWORD* threadIDs                    = NULL;
    OUT_SERVICE* subscriebers           = NULL; // Repository for mirror services (socket, addr, subscriptions)
    InitializeCriticalSection(&disp);
    bool thr_shudown_flag = false;

    printf("==================================================================================================\n");

    WSAData wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
        printf("WSAStartup Failed\n");
        return -1;
    }

    bool escapeFlag = false;    // For depth escape when shutdown is initiated
    int bufferSocketsNum = 0;
    switch (true) 
    {
        case true:
        {
            // Read Network setup
            printf("Loading network data..\n");
            char cwd[FILENAME_MAX];
            if (getcwd(cwd, sizeof(cwd)) == NULL)
            {
                printf("Error loading path\n");
                return 1;
            }

            strcat_s(cwd, "\\NetworkCfg.txt");
            cwd[sizeof(cwd) - 1] = '\0';  //Append config file name
            
            FILE* fptr = NULL;
            fopen_s(&fptr, cwd, "rb");
            if (!fptr)
            {
                printf("Opening NetCfg at %s failed, closing..\n", cwd);
                break;
            }

            networkParams = (NETWORKING_PARAMS*)malloc(sizeof(NETWORKING_PARAMS));
            if (networkParams == NULL) break;
            networkParams->Initialize();
              
            NETWORKING_PARAMS tmpNetworkParams;
            LoadNetworkingParams(&fptr, &tmpNetworkParams);
            fclose(fptr);
            printf("\nDone.\n");
            printf("==================================================================================================\n");

            // Check minimal req
            bool listenFound = false, bufferingFound = false,  serviceFound= false;
            for (int nameLoc = 0; nameLoc < tmpNetworkParams.tcp_params->accept_socket_units; ++nameLoc)
            {
                switch (tmpNetworkParams.tcp_params->accept_socket_contexts[nameLoc])
                {
                    case BUFFERING: {bufferingFound = true; break; }
                    case SERVICING: {serviceFound = true; break; }
                }
            }

            if (tmpNetworkParams.tcp_params->listen_socket_params != NULL) listenFound = true;

            if (!(listenFound && serviceFound && bufferingFound))
            {
                printf("Minimal network requirements not found:\n");
                if (!listenFound)   printf("\tListen socket not found\n");
                if (!serviceFound)  printf("\tService socket not found\n");
                if (!bufferingFound) printf("\tBuffering socket not found\n");
                printf("NOTE: Check port numbers usage!\n");
                printf("--------- PRELIMINARY DATA ---------\n");
                tmpNetworkParams.tcp_params->Format();
                printf("--------------------_---------------\n");
                break;
            }


            // For each LS unit
            for (int chk_loc = 0; chk_loc < tmpNetworkParams.tcp_params->listen_socket_units; ++chk_loc)        // For each LS unit
            {
                // Compare with other LS units
                for (int chk_ls = 0; chk_ls < tmpNetworkParams.tcp_params->listen_socket_units; ++chk_ls)       
                {
                    if (chk_loc != chk_ls &&
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_loc].address_ipv4 == tmpNetworkParams.tcp_params->listen_socket_params[chk_ls].address_ipv4 &&
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_loc].port == tmpNetworkParams.tcp_params->listen_socket_params[chk_ls].port)
                            { printf("NetworkCfg corrupted with duplicates!"); break;}
                }

                // Compare with AS units
                for (int chk_as = 0; chk_as < tmpNetworkParams.tcp_params->accept_socket_units; ++chk_as)       
                {   
                    if (chk_loc != chk_as &&
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_loc].address_ipv4 == 
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as].address_ipv4 &&

                        tmpNetworkParams.tcp_params->listen_socket_params[chk_loc].port ==
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as].port)
                    {
                        printf("NetworkCfg corrupted with duplicates!"); break;
                    }
                }
            }

            // For ach AS unit
            for (int chk_as = 0; chk_as < tmpNetworkParams.tcp_params->accept_socket_units; ++chk_as)
            {
                // Compare AS unit with other AS units
                for (int chk_as_in = 0; chk_as_in < tmpNetworkParams.tcp_params->accept_socket_units; ++chk_as_in)
                {
                    if (chk_as != chk_as &&
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as_in].address_ipv4 ==
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as].address_ipv4 &&

                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as_in].port ==
                        tmpNetworkParams.tcp_params->listen_socket_params[chk_as].port)
                    {
                        printf("NetworkCfg corrupted with duplicates!"); break;
                    }
                }
            }
            // Ignore UDP because it's not suppored at the moment
                  
            // Manually copy, realloc would mess pointers up
            if (tmpNetworkParams.udp_params != NULL)
            {
                networkParams->udp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmpNetworkParams.udp_params->accept_socket_units);
                if (networkParams->udp_params->accept_socket_params == NULL) break;
                memcpy(networkParams->udp_params->accept_socket_params,
                    tmpNetworkParams.udp_params->accept_socket_params,
                    sizeof(SOCKETPARAMS) * tmpNetworkParams.udp_params->accept_socket_units);

                networkParams->udp_params->accept_socket_contexts = (unsigned char*)malloc(tmpNetworkParams.udp_params->accept_socket_units);
                if (networkParams->udp_params->accept_socket_contexts == NULL) break;
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
            tmpNetworkParams.Dispose();

            //Load buffers configuration
            bool successFlag = false;
            printf("Loading memory data..\n\n");
            if (getcwd(cwd, sizeof(cwd)) == NULL) 
            {
                printf("Error loading path\n");
                return 1;
            }

            strcat_s(cwd, "\\MemCfg.txt");
            cwd[sizeof(cwd) - 1] = '\0';  //Append config file name
            //Append config file name

            fptr = NULL;
            fopen_s(&fptr, cwd, "rb");
            if (!fptr)
            {
                printf("Opening MemCfg at %s failed, closing..\n", cwd);
                break;
            }
            buffParams = LoadBufferParams(&fptr, &successFlag);
            if (!buffParams.Validate()) break;
            fclose(fptr);
            printf("\nDone.\n");
            printf("==================================================================================================\n");

            // Initialize input buffer
            BUFF_DESC* tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
            tmp_buff->Initialize();
            if (input_buffer == NULL) input_buffer = tmp_buff;
            else input_buffer->Insert(tmp_buff, &input_buffer);
            tmp_buff->context = INBUF;                                     // Allocate for single input buff
            tmp_buff->capacity = buffParams.inqueue;
            tmp_buff->memory = (char*)(malloc(tmp_buff->capacity));
            if (tmp_buff->memory == NULL) break;
            tmp_buff->Prepare();
            sprintf_s(input_buffer->name, "%s", "INPUT BUFF");

            // Initialize ack buffer
            tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
            tmp_buff->Initialize();
            if (ack_buffer == NULL) ack_buffer = tmp_buff;
            else ack_buffer->Insert(tmp_buff, &ack_buffer);
            tmp_buff->context = ACKBUF;
            tmp_buff->capacity = buffParams.ackqueue;
            tmp_buff->memory = (char*)(malloc(tmp_buff->capacity));
            if (tmp_buff->memory == NULL) break;
            ack_buffer->Prepare();
            sprintf_s(ack_buffer->name, "%s", "ACK BUFF");

            for (int acc_bufloc = 0; acc_bufloc < networkParams->tcp_params->accept_socket_units; ++acc_bufloc)
            {
                if (networkParams->tcp_params->accept_socket_contexts[acc_bufloc] == BUFFERING) ++bufferSocketsNum;
            }

            // Create input buffer for eah service
            for (int acc_bufloc = 0; acc_bufloc < bufferSocketsNum; ++acc_bufloc)
            {

                tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                tmp_buff->Initialize();
                if (service_buffers_in == NULL) service_buffers_in = tmp_buff;
                else service_buffers_in->Insert(tmp_buff, &service_buffers_in);

                if ((tmp_buff->memory = (char*)malloc(buffParams.service_in_queue)) == NULL)
                {
                    escapeFlag = true;  break;
                }
                else
                {
                    tmp_buff->context = INBUF_SRV;
                    tmp_buff->capacity = buffParams.service_in_queue;
                    tmp_buff->Prepare();
                }
            }
            if (escapeFlag) break;

            // Create output buffer for eah service
            for (int acc_bufloc = 0; acc_bufloc < bufferSocketsNum; ++acc_bufloc)
            {

                tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                tmp_buff->Initialize();
                if (service_buffers_out == NULL) service_buffers_out = tmp_buff;
                else service_buffers_out->Insert(tmp_buff, &service_buffers_out);

                if ((tmp_buff->memory = (char*)malloc(buffParams.service_out_queue)) == NULL)
                {
                    escapeFlag = true;  break;
                }
                else
                {
                    tmp_buff->context = OUTBUF_SRV;
                    tmp_buff->capacity = buffParams.service_out_queue;
                    tmp_buff->Prepare();
                }
            }
            if (escapeFlag) break;

            // Name initial services (configured via NetworkCfg)
            char* tmpBuff = (char*)(malloc(MAX_SERVICE_NAME_SIZE+1));
            if (tmpBuff == NULL) break;
            printf("\n\nName initial services:\n\t[TOTAL : %hu]\n\t[MAX NAME LENGTH : %d]\n\n", bufferSocketsNum, MAX_SERVICE_NAME_SIZE);
            
            bool triggerReEnter = false;
            BUFF_DESC* service_in_it = service_buffers_in;
            BUFF_DESC* service_out_it = service_buffers_out;
            SERVICE_NAME* check_it;
            for (int service_bufloc = 0; service_bufloc < bufferSocketsNum; ++service_bufloc)
            {
                memset(tmpBuff, 0, MAX_SERVICE_NAME_SIZE + 1);
                printf("Service %d: ", service_bufloc);
                gets_s(tmpBuff, MAX_SERVICE_NAME_SIZE);

                triggerReEnter = false;
                check_it = service_names;
                for (int usedNames = 0; usedNames < service_bufloc; usedNames++)    // Must be unique
                {
                    if (!strcmp(tmpBuff, check_it->name))
                    {
                        printf("\tERROR: Name already used!\n");
                        --service_bufloc;
                        triggerReEnter = true;
                        break;
                    }
                    else check_it = check_it->next;
                }
                if (triggerReEnter) continue;

                if (service_in_it == NULL || service_out_it == NULL) break;

                int len = strlen(tmpBuff) + 1;
                SERVICE_NAME* new_name = (SERVICE_NAME*)(malloc(sizeof(SERVICE_NAME)));
                new_name->Initialize();
                new_name->next = NULL;
                new_name->name = (char*)(malloc(len));
                memset(new_name->name, 0, len);
                new_name->length = len;
                memcpy(new_name->name, tmpBuff, len);
                if (service_names == NULL)  service_names = new_name;
                else
                    service_names->Insert(new_name, &service_names);
                sprintf(service_out_it->name, "%s|SEND BUFF", tmpBuff); // Connect buffers & its services
                sprintf(service_in_it->name, "%s|RECV BUFF", tmpBuff);

                service_in_it = service_in_it->next;
                service_out_it = service_out_it->next;
            }
            free(tmpBuff);  

            // Print loaded params
            printf("==================================================================================================\n");
            printf("-- Network Stats --\n");
            networkParams->tcp_params->Format();
            printf("\n");
            printf("-- Buffering Stats --\n");
            printf("\tBuffer Name: %s\n", ack_buffer->name);
            printf("\tBuffer Name: %s\n", input_buffer->name);
            
            service_in_it = service_buffers_in;
            service_out_it = service_buffers_out;
            for (int service_bufloc = 0; service_bufloc < bufferSocketsNum; ++service_bufloc)
            {
                if (service_in_it == NULL || service_out_it == NULL) break;

                printf("\tBuffer Name: %s\n", service_in_it->name);
                printf("\tBuffer Name: %s\n", service_out_it->name);

                service_in_it = service_in_it->next;
                service_out_it = service_out_it->next;
            }
            printf("\n");
            printf("-- Service Stats --\n");
            SERVICE_NAME* service_it=service_names;
            for (int service_bufloc = 0; service_bufloc < bufferSocketsNum; ++service_bufloc)
            {
                printf("\tService Name: %s\n", service_it->name);
                service_it = service_it->next;
            }         

            printf("==================================================================================================\n");
            //
        }
        printf("Starting thread initialization..\n");
        threadIDs = (DWORD*)malloc(sizeof(DWORD) * networkParams->tcp_params->listen_socket_units + MAX_SERVICES_HOSTED*3+1);
        // Create threads, assign buffers and expose sockets
        char ip_formatted[13];
        int validClientsSockets = 0;

        SERVICE_NAME* service_names_it = service_names;
        char service_name[MAX_BUFF_NAME + 1];
        for (int loc = 0; loc < networkParams->tcp_params->accept_socket_units; ++loc)  
        {   // For each buffering socket
            if (networkParams->tcp_params->accept_socket_contexts[loc] == 1)        
            {
                // Create loader thread
                HANDLE_LST* load_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (load_handle == NULL) { escapeFlag = true; break; }

                load_handle->Initialize();
                load_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                threadIDs[thread_counter] = thread_counter;

                SERVICE_LOADER_THR_PARAMS* service_loader_thr_param = (SERVICE_LOADER_THR_PARAMS*)malloc(sizeof(SERVICE_LOADER_THR_PARAMS));
                service_loader_thr_param->Initialize();
                memcpy(service_loader_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                service_loader_thr_param->in_buffer = input_buffer;             // Reds from common input buffer            

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Writes into service send buffer (Queue Service Point of View) 
                service_loader_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                service_loader_thr_param->end_thr_flag = &thr_shudown_flag;

                *load_handle->handle = CreateThread(NULL, 0, &ServiceLoaderThr, service_loader_thr_param, 0, threadIDs + thread_counter);
                listenSocketHandles->Insert(load_handle, &listenSocketHandles);
                ++thread_counter;

                // Create GC thread
                HANDLE_LST* GC_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (GC_handle == NULL) { escapeFlag = true; break; }

                GC_handle->Initialize();
                GC_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                threadIDs[thread_counter] = thread_counter;

                SERVICE_GC_THR_PARAMS* GC_thr_param = (SERVICE_GC_THR_PARAMS*)malloc(sizeof(SERVICE_GC_THR_PARAMS));
                GC_thr_param->Initialize();
                memcpy(GC_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                GC_thr_param->in_buffer = ack_buffer;               // Reads from common ack buffer

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Deletes from send buffer
                GC_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                GC_thr_param->end_thr_flag = &thr_shudown_flag;
                *GC_handle->handle = CreateThread(NULL, 0, &ServiceGCThr, GC_thr_param, 0, threadIDs + thread_counter);
                GCHandle->Insert(GC_handle, &GCHandle);
                ++thread_counter;

                // Create client communication thread
                SOCKET_DATA* client_socket = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
                if (client_socket == NULL) break;
                client_socket->Initialize();

                client_socket->socket = (SOCKET*)malloc(sizeof(SOCKET));
                if (client_socket->socket == NULL) break;
                *client_socket->socket = INVALID_SOCKET;

                if ((*(client_socket->socket) = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
                {
                    EnterCriticalSection(&disp);
                    printf("An error occurred creating client buffering socket\n");
                    LeaveCriticalSection(&disp);
                }
                else ++validClientsSockets;

                client_socket->address = (sockaddr_in*)malloc(sizeof(sockaddr_in));
                client_socket->address->sin_family = AF_INET;
                networkParams->tcp_params->accept_socket_params[loc].FormatIP(ip_formatted);
                client_socket->address->sin_addr.s_addr = inet_addr(ip_formatted);
                client_socket->address->sin_port = htons(networkParams->tcp_params->accept_socket_params[loc].port);
                client_socket_params->Insert(client_socket, &client_socket_params);

                HANDLE_LST* client_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (client_handle == NULL) { escapeFlag = true; break; }

                client_handle->Initialize();
                client_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                threadIDs[thread_counter] = thread_counter;

                CLIENT_THR_PARAMS* client_thr_param = (CLIENT_THR_PARAMS*)malloc(sizeof(CLIENT_THR_PARAMS));
                client_thr_param->Initialize();
                memcpy(client_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|RECV BUFF", service_names_it->name);      // Reads what comes from sockets and stores it
                client_thr_param->in_buffer = service_buffers_in->FindByName(service_name, service_buffers_in);

                memset(service_name, 0, MAX_BUFF_NAME + 1);                         // Reads what commes from mirroring and sends it trough socket
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);      
                client_thr_param->out_buffer = service_buffers_out->FindByName(service_name, service_buffers_out);

                client_thr_param->end_thr_flag = &thr_shudown_flag;
                *client_handle->handle = CreateThread(NULL, 0, &ClientReqHandleThr, client_thr_param, 0, threadIDs + thread_counter);
                clientReqHandle->Insert(client_handle, &clientReqHandle);
                ++thread_counter;

                service_names_it=service_names_it->next;
            }   
        }

        //Create listening sockets
        int validListenSockets = 0;
        for (int loc = 0; loc < networkParams->tcp_params->listen_socket_units; ++loc)
        {
            SOCKET_DATA* listenSocket = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
            if (listenSocket == NULL) break;
            listenSocket->Initialize();

            listenSocket->socket = (SOCKET*)malloc(sizeof(SOCKET));
            if (listenSocket->socket == NULL) break;
            *listenSocket->socket = INVALID_SOCKET;

            if ((*(listenSocket->socket) = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
            {
                EnterCriticalSection(&disp);
                printf("Ann error occurred creating listening sockets\n");
                LeaveCriticalSection(&disp);
            }
            else ++validListenSockets; 

            listenSocket->address = (sockaddr_in*)(malloc(sizeof(sockaddr_in)));

            listenSocket->address->sin_family = AF_INET;
            networkParams->tcp_params->listen_socket_params[loc].FormatIP(ip_formatted);
            listenSocket->address->sin_addr.s_addr = inet_addr(ip_formatted);
            listenSocket->address->sin_port = htons(networkParams->tcp_params->listen_socket_params[loc].port);
            listen_socket_params->Insert(listenSocket, &listen_socket_params);

            HANDLE_LST* handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
            if (handle == NULL) 
                { escapeFlag = true; break;}

            handle->Initialize();
            handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
            threadIDs[thread_counter] = thread_counter;
            LISTENING_THR_PARAMS listenSocketThr_params;
            listenSocketThr_params.Initialize();
            listenSocketThr_params.listen_socket_params = listen_socket_params;
            listenSocketThr_params.subscriebers = subscriebers;
            listenSocketThr_params.service_names = service_names;
            listenSocketThr_params.end_thr_flag = &thr_shudown_flag;
            *handle->handle = CreateThread(NULL, 0, &ListenSocketThr, &listenSocketThr_params, 0, threadIDs+thread_counter);
            ++thread_counter;
            listenSocketHandles->Insert(handle, &listenSocketHandles);
        }
        Sleep(2000);//Wait for threads to initialize
        EnterCriticalSection(&disp);
        printf("Thread initialization completed.\n");
        LeaveCriticalSection(&disp);

        if (validListenSockets == 0 || escapeFlag) break;

        validListenSockets = 0;
        for (int loc = 0; loc < networkParams->tcp_params->listen_socket_units; ++loc)
            validListenSockets += listen_socket_params->initialized;
        
        if (validListenSockets <= 0)
        { 
            EnterCriticalSection(&disp);
            printf("Ann error occurred initializing listening sockets\n"); 
            LeaveCriticalSection(&disp);
            break; 
        }
        else 
        { 
            EnterCriticalSection(&disp);
            printf("%d/%d Listening socket succesfully initialized\n", validListenSockets, networkParams->tcp_params->listen_socket_units);
            LeaveCriticalSection(&disp);
        }
        
        for (int loc = 0; loc < networkParams->tcp_params->accept_socket_units; ++loc)
        {
            if (networkParams->tcp_params->accept_socket_contexts[loc] == 3)
                ExposeServices(&(networkParams->tcp_params->accept_socket_params[loc]), service_names, subscriebers);
        }
    }   

    EnterCriticalSection(&disp);
    printf("==================================================================================================\n");
    printf("\t\t[SERVER WORKING, PRESS ANY KEY TO SHUTDOWN]\n");
    printf("==================================================================================================\n");
    LeaveCriticalSection(&disp);
    do{Sleep(500);} while (!kbhit());

    // Safe termination of threads

    thr_shudown_flag = true;
    do { Sleep(1000); } while (thread_counter > 0);
    DeleteCriticalSection(&disp);
    // Dispose after break 
    WSACleanup();

    if (subscriebers            != NULL) { subscriebers->Dispose();              free(subscriebers);           subscriebers          = NULL;}
    if (networkParams           != NULL) { networkParams->Dispose();             free(networkParams);          networkParams         = NULL;}
    if (input_buffer            != NULL) { input_buffer->Dispose();              free(input_buffer);           input_buffer          = NULL;}
    if (ack_buffer              != NULL) { ack_buffer->Dispose();                free(ack_buffer);             ack_buffer            = NULL;}
    if (service_buffers_in      != NULL) { service_buffers_in->Dispose();        free(service_buffers_in);     service_buffers_in    = NULL;}
    if (service_buffers_out     != NULL) { service_buffers_out->Dispose();       free(service_buffers_out);    service_buffers_out   = NULL;}
    if (service_names           != NULL) { service_names->Dispose();             free(service_names);          service_names         = NULL;}
    if (listen_socket_params    != NULL) { listen_socket_params->Dispose();      free(listen_socket_params);   listen_socket_params  = NULL;}
    if (service_socket_params   != NULL) { service_socket_params->Dispose();     free(service_socket_params);  service_socket_params = NULL;}
    if (client_socket_params    != NULL) { client_socket_params->Dispose();      free(client_socket_params);   client_socket_params  = NULL;}
    if (subscriebers            != NULL) { subscriebers->Dispose();              free(subscriebers);           subscriebers          = NULL;}
    if (service_buffers_in      != NULL) { service_buffers_in->Dispose();        free(service_buffers_in);     service_buffers_in    = NULL;}
    if (listen_socket_params    != NULL) { listen_socket_params->Dispose();      free(listen_socket_params);   listen_socket_params  = NULL;}
    if (listen_socket_params    != NULL) { listen_socket_params->Dispose();      free(listen_socket_params);   listen_socket_params  = NULL;}
    if (ack_buffer              != NULL) { ack_buffer->Dispose();                free(ack_buffer);             ack_buffer            = NULL;}
    if (listenSocketHandles     != NULL) { listenSocketHandles->Dispose();       free(listenSocketHandles);    listenSocketHandles   = NULL;}
    if (inputSocketHandle       != NULL) { inputSocketHandle->Dispose();         free(inputSocketHandle);      inputSocketHandle     = NULL;}
    if (outputSocketHandle      != NULL) { outputSocketHandle->Dispose();        free(outputSocketHandle);     outputSocketHandle    = NULL;}
    if (loaderHandle            != NULL) { loaderHandle->Dispose();              free(loaderHandle);           loaderHandle          = NULL;}
    if (GCHandle                != NULL) { GCHandle->Dispose();                  free(GCHandle);               GCHandle              = NULL;}
    if (clientReqHandle         != NULL) {clientReqHandle->Dispose();            free(clientReqHandle);        clientReqHandle       = NULL;}
    if (threadIDs               != NULL) {                                       free(threadIDs);              threadIDs             = NULL;}

    printf("Press any key to exit..\n");
    getchar();
    return 0;
}
