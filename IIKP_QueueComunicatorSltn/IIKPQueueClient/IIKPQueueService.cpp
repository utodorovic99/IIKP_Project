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
#include "Common.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996) 

#pragma region IgnoreWarnings
    #pragma warning(suppress : 6387)
    #pragma warning(suppress : 6011)
    #pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
    #define REQUEST_ACQUISITION_INTERVAL_SECS 1
    #define CHK_CL_AVAILABILITY_INTERVAL 500
    #define SOCKET_INITIALIZE_INTERVAL 2000
    #define MAX_MEDIATOR_BUFF_SIZE 255
    #define MAX_SERVICES_HOSTED 10
    #define MAX_MESSAGE_SIZE 255    
    #define MAX_INPUT_CONNS 1 
#pragma endregion

#pragma region Synchronization
    CRITICAL_SECTION disp;          // Sync for console output
#pragma endregion

#pragma region Globals
    int thread_counter = 0;    // Sync-ed by dsp cs (closing thread followed by disp writing )
    unsigned msg_id_cnt = 0;
    bool is_cl_acceptable = false;
#pragma endregion

#pragma region Function_Decl
    // Helper function printing basic service stats (services, buffers & their parameters)
    // SERVICE_NAME* services           - list of hosted services
    // BUFF_DESC* service_buffers_in    - list of input service buffer descriptors
    // BUFF_DESC* service_buffers_out   - list of output service buffer descriptors
    // BUFF_DESC* input_buffer          - input buffer descriptor 
    // BUFF_DESC* ack_buffer            - ack buffer descriptor
    void PrintServicesAndBuffs(SERVICE_NAME* services, BUFF_DESC* service_buffers_in, BUFF_DESC* service_buffers_out, BUFF_DESC* input_buffer, BUFF_DESC* ack_buffer);

    // Function sending service offer to sub
    // EXPOSE_PARAMS params - encapsulated expose parameters
    // OUT_SERVICE* sub     - expose message destination
    // Returns success flag
    bool ExposeServiceTo(EXPOSE_PARAMS params, OUT_SERVICE* sub);

    // Function sending service offer to all subscriebers (mirroring server)
    // EXPOSE_PARAMS params - encapsulated expose parameters
    // Returns success flag
    bool ExposeServices(EXPOSE_PARAMS params);

    // Handles delta services sent by other service
    // char* message_buff           - buffer containing recved delta message 
    // SERVICE_NAME* service_names  - hosted service names
    // SERVICE_NAME** new_services  - resulting list of new services (except hosted ones)
    void HandleDeltaServices(char* message_buff, SERVICE_NAME* service_names, SERVICE_NAME** new_services);

    // Generates delta services message (for service offer)
    // SETUP_MSG* msg               - resulting message
    // SERVICE_NAME* service_names  - hosted service names
    void GenerateDeltaServicesMsg(SETUP_MSG* msg, SERVICE_NAME* service_names);

    // Body of Service Loader Thread wich consumes common input buffer and feeds input buffer of specific service  
    // LPVOID lp_param - thread params encapsualted in SERVICE_LOADER_THR_PARAMS
    DWORD WINAPI ServiceLoaderThr(LPVOID lpParam);

    // Body of Service Garbage Collector wich consumes ack buffer and clears acked messages from service output buffers
    // LPVOID lp_param - thread params encapsualted in SERVICE_GC_THR_PARAMS
    DWORD WINAPI ServiceGCThr(LPVOID lpParam);

    // Body of Output Handle Thread wich consumes service output buffers and sends messages to mirror service
    // LPVOID lp_param - thread params encapsualted in OUTPUT_THR_PARAMS params
    DWORD WINAPI OutputHandleThr(LPVOID lpParam);

    // Body of Client Register Thread wich listens for client connection requests, proviedes them available
    // hosted services (not taken ones) and fetches connected clients to Client Request Handle Threads
    // LPVOID lp_param - thread params encapsualted in CLIENT_REGISTER_THR_PARAMS
    DWORD WINAPI ClientRegisterThr(LPVOID lpParam);

    // Body of Client Request Handle Thread wich handles Send & Revieve messages from connected client to specific service
    // Client connection is fetched from Client Register Thread when client Connects to specific service
    // LPVOID lp_param - thread params encapsualted in CLIENT_THR_PARAMS
    DWORD WINAPI ClientReqHandleThr(LPVOID lpParam);

    // Listens for service-service connections, accepts them and priviedes hosted services, recieves incoming messages
    // LPVOID lp_param - thread params encapsualted in LISTENING_THR_PARAMS
    DWORD WINAPI ServiceCommunicationThr(LPVOID lpParam);
#pragma endregion

#pragma region Function_Impl
    void PrintServicesAndBuffs(SERVICE_NAME* services, BUFF_DESC* service_buffers_in, BUFF_DESC* service_buffers_out, BUFF_DESC* input_buffer, BUFF_DESC* ack_buffer)
    {
        printf("==================================================================================================\n");
        printf("SERVICES:\n");
        services->PrintOut(services);
        printf("\n");

        printf("SERVICE IN BUFFS:\n");
        input_buffer->PrintOut(input_buffer);
        printf("\n");

        printf("SERVICE ACK BUFFS:\n");
        ack_buffer->PrintOut(ack_buffer);
        printf("\n");

        printf("CLIENT IN BUFFS:\n");
        service_buffers_in->PrintOut(service_buffers_in);
        printf("\n");

        printf("CLIENT OUT BUFFS:\n");
        service_buffers_out->PrintOut(service_buffers_out);
        printf("\n");
        printf("==================================================================================================\n");
    }
    bool ExposeServiceTo(EXPOSE_PARAMS params, OUT_SERVICE* sub)
    {
        if (send(*sub->socket, params.expose_mess_buff, 6 + params.expose_mess->content_size + 1, 0) != SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[EXPOSE]:\n\tServices offer sent to %s:%hu\n\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
            LeaveCriticalSection(&disp);

            if (ioctlsocket(*sub->socket, FIONBIO, params.nb_mode) == 0)
            {
                EnterCriticalSection(&disp);
                printf("[EXPOSE]\n\tAccepted socket %s:%hu in non-blocking mode\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                LeaveCriticalSection(&disp);

                for (unsigned loc = 0; loc < params.service_names->Count(params.service_names); ++loc)
                    sub->SubscribeTo(loc);

                sub->exposed = true;
                (*params.subscriebers)->Insert(sub, params.subscriebers);
                return true;
            }
            else
            {
                EnterCriticalSection(&disp);
                printf("[EXPOSE]\n\tSetting accepted socket %s:%hu in non-blocking mode failed\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                LeaveCriticalSection(&disp);
                closesocket(*sub->socket);
                *sub->socket = INVALID_SOCKET;
                (*params.subscriebers)->Insert(sub, params.subscriebers);
                // Keep to try later
                return false;
            }

        }
        else //Send failed close socket and remove from list
        {
            EnterCriticalSection(&disp);
            printf("[EXPOSE]:\n\tSending services offer to %s:%hu client failed\n\n", inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
            LeaveCriticalSection(&disp);
            closesocket(*sub->socket);
            *sub->socket = INVALID_SOCKET;
            (*params.subscriebers)->Insert(sub, params.subscriebers);
            return false;
        }
    }
    bool ExposeServices(EXPOSE_PARAMS params)
    {
        // Describe target (mirroring servers)
        char ip_formatted[13];
        OUT_SERVICE* out_service = (OUT_SERVICE*)malloc(sizeof(OUT_SERVICE));
        out_service->Initialize();
        out_service->address = (sockaddr_in*)malloc(sizeof(sockaddr_in));
        out_service->socket = (SOCKET*)malloc(sizeof(SOCKET));
        *out_service->socket = INVALID_SOCKET;
        out_service->address->sin_family = AF_INET;
        params.target_params->FormatIP(ip_formatted);
        out_service->address->sin_addr.s_addr = inet_addr(ip_formatted);
        out_service->address->sin_port = htons(params.target_params->port);
        out_service->exposed = false;
        OUT_SERVICE* sub;


        // Contact it
        *out_service->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        EnterCriticalSection(&disp);
        printf("[EXPOSE]:\n\tConnecting to: %s:%hu\n\n", ip_formatted, params.target_params->port);
        LeaveCriticalSection(&disp);

        if (connect(*out_service->socket, (sockaddr*)(out_service->address), sizeof(*out_service->address)) == SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[EXPOSE]:\n\tConnecting to %s:%hu failed\n\n", inet_ntoa(out_service->address->sin_addr), ntohs(out_service->address->sin_port));
            LeaveCriticalSection(&disp);
            closesocket(*out_service->socket);
            *out_service->socket = INVALID_SOCKET;
            (*params.subscriebers)->Insert(out_service, params.subscriebers);
            // Keep to try later
            return false;
        }
        else
        {
            EnterCriticalSection(&disp);
            printf("[EXPOSE]:\n\tConnected to: %s:%hu\n\n", inet_ntoa(out_service->address->sin_addr), ntohs(out_service->address->sin_port));
            LeaveCriticalSection(&disp);
            sub = out_service;
            sub->exposed = false;

            ExposeServiceTo(params, sub);
        }
    }
    void HandleDeltaServices(char* message_buff, SERVICE_NAME* service_names, SERVICE_NAME** new_services)
    {
        // Parse message to list of service strings
        char* part = strtok(message_buff, "|");
        SERVICE_NAME* tmp_el;
        while (part != NULL)
        {
            tmp_el = (SERVICE_NAME*)malloc(sizeof(SERVICE_NAME));
            tmp_el->Initialize();
            tmp_el->name = (char*)malloc(strlen(part));
            sprintf(tmp_el->name, "%s\0", part);
            tmp_el->length = strlen(tmp_el->name);
            if (tmp_el->length > MAX_SERVICE_NAME_SIZE)
            {
                tmp_el->Dispose();
                free(tmp_el);
                break;
            }
            else if (!service_names->Contains(tmp_el->name, service_names))
                (*new_services)->Insert(tmp_el, new_services);

            part = strtok(NULL, "|");
        }
    }
    void GenerateDeltaServicesMsg(SETUP_MSG* msg, SERVICE_NAME* service_names)
    {
        msg->Initialize();
        msg->msg_code = SERVICES_ENL;
        msg->content_size = (MAX_SERVICE_NAME_SIZE + 1) * MAX_ACCEPT_SOCKETS + (MAX_ACCEPT_SOCKETS - 1) + 1;
        msg->content = (char*)malloc(msg->content_size);
        memset(msg->content, 0, msg->content_size);
        service_names->Format(msg->content, msg->content_size, service_names->Count(service_names), service_names, NULL);
        msg->content[strlen(msg->content)] = '\0';
        msg->content_size = strlen(msg->content) + 1;

    }
    DWORD WINAPI ServiceLoaderThr(LPVOID lp_param)
    {
        SERVICE_LOADER_THR_PARAMS params = *((SERVICE_LOADER_THR_PARAMS*)lp_param);

        EnterCriticalSection(&disp);
        printf("[THREAD %s LOAD]:\n\tThread started\n\n", params.service_name);
        LeaveCriticalSection(&disp);
        
        char accept_messg_buff[MAX_SERVICE_NAME_SIZE + MAX_MESSAGE_SIZE + 4]; // See SERVICE_MSG structure (ignore msg code)
        struct SERVICE_MSG* service_msg = NULL;
        int cycles;
        do
        {  
            EnterCriticalSection(&disp);
            #pragma omp atomic capture 
            {
                cycles = params.in_buffer->messges_enqueued;
                while (cycles>0 && !*(params.end_thr_flag))
                {
                    memset(accept_messg_buff, 0, MAX_SERVICE_NAME_SIZE + MAX_MESSAGE_SIZE + 4);
                    params.in_buffer->Dequeue(accept_messg_buff, strlen(accept_messg_buff));
                    service_msg = (struct SERVICE_MSG*)(accept_messg_buff);
                    if (!strcmp(params.service_name, service_msg->service)) // If my service
                    {
                        printf("[THREAD %s LOAD]:\n\tMessage with MSG ID: %u enqueued in %s message buffer\n\n", service_msg->msg_id, params.service_name); // Cut service name, not needed anymore
                        params.out_buffer->Enqueue(accept_messg_buff + strlen(service_msg->service) + 1, strlen(service_msg->content) + 1 + 4);
                    }
                    else // If not push it for other thread to read
                        params.in_buffer->Enqueue(accept_messg_buff, strlen(service_msg->service)+ 1+strlen(service_msg->content)+1+ 4);  // Return for other thread to read, keep service name
                    
                    --cycles;
                };
            }
            LeaveCriticalSection(&disp);
        } while (!*(params.end_thr_flag));

        EnterCriticalSection(&disp);
        printf("[THREAD %s LOAD]:\n\tClosing thread..\n\n", params.service_name);
        --thread_counter;
        LeaveCriticalSection(&disp);
        return 0;
    }
    DWORD WINAPI ServiceGCThr(LPVOID lp_param)
    {
        SERVICE_GC_THR_PARAMS params = *((SERVICE_GC_THR_PARAMS*)lp_param);
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
    DWORD WINAPI OutputHandleThr(LPVOID lp_param)
    {
        OUTPUT_THR_PARAMS params = *((OUTPUT_THR_PARAMS*)lp_param);
        EnterCriticalSection(&disp);
        printf("[THREAD OUTPUT]:\n\tThread started\n\n");
        LeaveCriticalSection(&disp);

        struct SERVICE_MSG* msg = NULL;
        char message_buff[MAX_MESSAGE_SIZE];
        do
        {
            OUT_SERVICE* sub_it = NULL;
            for (BUFF_DESC* buff_it = params.out_buffers; buff_it != NULL; buff_it = buff_it->next) // Iterate trough buffers
            {
                memset(message_buff, 0, MAX_MESSAGE_SIZE);
                sub_it = params.dst;
                int service_loc = 0;
                int target_idx = 0;
                int cycles = buff_it->messges_enqueued;
                while(cycles>0)       // Dequeue message
                {
                    buff_it->Dequeue(message_buff, strlen(message_buff));
                    msg = (struct SERVICE_MSG*)message_buff;
                    target_idx = params.service_names->IndexOf(msg->service, params.service_names);
                    while (sub_it->service_idx[service_loc] != -1 && sub_it->service_idx[service_loc] != target_idx) ++service_loc; // Try find if he is subbed

                    // Won't iterate trough multiple subs only 1 supported at the moment
                    if (sub_it->service_idx[service_loc] != -1) // He is
                    {
                        if (send(*sub_it->socket, message_buff, 2+strlen(msg->service)+1+strlen(msg->content)+1+4, 0) != SOCKET_ERROR)                                                 // Send services offer                                
                        {
                            EnterCriticalSection(&disp);
                            printf("[THREAD OUTPUT]:\n\tSending message to service merver on %s:%hu successed\n\n",
                                inet_ntoa((*sub_it->address).sin_addr),
                                ntohs((*sub_it->address).sin_port));
                            LeaveCriticalSection(&disp);                                                                                   // Wait for Connect message
                        }
                        else
                        {
                            EnterCriticalSection(&disp);
                            printf("[THREAD OUTPUT]:\n\tSending message to service merver on %s:%hu failed\n\n",
                                inet_ntoa((*sub_it->address).sin_addr),
                                ntohs((*sub_it->address).sin_port));
                            LeaveCriticalSection(&disp);  
                            buff_it->Enqueue(message_buff, 2 + strlen(msg->service) + 1 + strlen(msg->content) + 1 + 4);                                                                                           // If failed, reject client (Dispose closes socket)
                        }
                    }
                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    --cycles;
                }
            }

        } while (!*(params.end_thr_flag));

        EnterCriticalSection(&disp);
        printf("[THREAD OUTPUT]:\n\tClosing thread..\n\n");
        --thread_counter;
        LeaveCriticalSection(&disp);
        return 0;
    }
    DWORD WINAPI ClientRegisterThr(LPVOID lp_param)
    {
        while (!is_cl_acceptable) Sleep(CHK_CL_AVAILABILITY_INTERVAL);  //Wait till deltas are created

        SERVICE_NAME* services_taken = NULL;
        SOCKET_DATA* waiting_fetch_resp = NULL;
        unsigned long nb_mode = 1;

        EnterCriticalSection(&disp);
        printf("[THREAD REGISTER]:\n\tThread started\n\n");
        LeaveCriticalSection(&disp);
        CLIENT_REGISTER_THR_PARAMS params = *((CLIENT_REGISTER_THR_PARAMS*)lp_param);

        bool block = false;
        if (bind(*(params.register_socket_params->socket), (struct sockaddr*)params.register_socket_params->address, sizeof(*params.register_socket_params->address)) == SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[THREAD REGISTER]:\n\tListen socket bind failed with error code : %d, witing safe shutdown\n\n", WSAGetLastError());
            LeaveCriticalSection(&disp);
            params.register_socket_params->initialized = false;
            block = true;
        }
        else
        {
            if (ioctlsocket(*(params.register_socket_params->socket), FIONBIO, &nb_mode) == 0)
            {
                EnterCriticalSection(&disp);
                printf("[THREAD LST / RECV]\n\tListen socket %s:%hu in non-blocking mode\n\n", 
                    inet_ntoa(params.register_socket_params->address->sin_addr), 
                    ntohs(params.register_socket_params->address->sin_port));
                LeaveCriticalSection(&disp);
            }
            else
            {
                EnterCriticalSection(&disp);
                printf("[THREAD LST / RECV]\n\tSetting listen socket %s:%hu in non-blocking mode failed\n\n", 
                    inet_ntoa(params.register_socket_params->address->sin_addr), 
                    ntohs(params.register_socket_params->address->sin_port));
                LeaveCriticalSection(&disp);
                closesocket(*(params.register_socket_params->socket));
                *(params.register_socket_params->socket) = INVALID_SOCKET;
                *(params.register_socket_params->socket) = false;
                block = true;
            }
        }

        if (block)
        {
            while (!*(params.end_thr_flag)) Sleep(1000);// Wait for safe shutdown
            EnterCriticalSection(&disp);
            --thread_counter;
            LeaveCriticalSection(&disp);
            return -1;
        }

        params.register_socket_params->initialized = true;

        listen(*(params.register_socket_params->socket), MAX_SERVICES_HOSTED * 2);
        unsigned long mode = 1;

        fd_set read_set;
        fd_set exc_set;

        timeval time_val;
        time_val.tv_sec = REQUEST_ACQUISITION_INTERVAL_SECS;
        time_val.tv_usec = 0;

        int i_result;

        int addr_len;
        bool block_flag = false;

        char message_buff[MAX_MESSAGE_SIZE];
        int bytes_rec;

        SOCKET_DATA* to_rem_pend = NULL;
        bool rem_happened;
        do
        {
            if (to_rem_pend != NULL) to_rem_pend->Dispose();

            FD_ZERO(&read_set);
            FD_ZERO(&exc_set);

            FD_SET(*(params.register_socket_params->socket), &read_set);
            FD_SET(*(params.register_socket_params->socket), &exc_set);

            for (SOCKET_DATA* pending_it = waiting_fetch_resp; pending_it != NULL; pending_it = pending_it->next)
            {
                FD_SET(*(pending_it->socket), &read_set);
                FD_SET(*(pending_it->socket), &exc_set);
            }

            i_result = select(0, &read_set, NULL, &exc_set, &time_val);
            if (i_result == SOCKET_ERROR)
            {
                EnterCriticalSection(&disp);
                printf("[THREAD REGISTER]:\n\tAn error occurred on: Select socket\n\n");
                LeaveCriticalSection(&disp);
            }
            else if (i_result > 0)
            {
                if (FD_ISSET(*(params.register_socket_params->socket), &read_set))      // Has accept req happened
                {
                    SOCKET_DATA* new_sock_params = (SOCKET_DATA*)malloc(sizeof(SOCKET_PARAMS));
                    new_sock_params->Initialize();
                    new_sock_params->address = (sockaddr_in*)(malloc(sizeof(sockaddr_in)));
                    new_sock_params->socket = (SOCKET*)malloc(sizeof(SOCKET));

                    *new_sock_params->socket = socket(AF_INET, SOCK_STREAM, 0);
                    if (*new_sock_params->socket == INVALID_SOCKET)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD REGISTER]:\n\tAn error occurred on preparing accept socket, waiting safe shutdown\n\n");
                        LeaveCriticalSection(&disp);
                        block_flag = true;

                    }
                    else
                    {
                        if ((*new_sock_params->socket = accept(*(params.register_socket_params->socket), (struct sockaddr*)new_sock_params->address, &addr_len)) == INVALID_SOCKET)      // Accept
                            block_flag = true;
                        else
                        {
                            EnterCriticalSection(&disp);
                            printf("[THREAD REGISTER]:\n\tClient accepted at %s:%hu\n\n",
                                inet_ntoa((*new_sock_params->address).sin_addr),
                                ntohs((*new_sock_params->address).sin_port));
                            LeaveCriticalSection(&disp);

                            char services_conn_params[MAX_SERVICE_NAME_SIZE * MAX_SERVICES_HOSTED * 2 + MAX_SERVICES_HOSTED];
                            memset(services_conn_params, 0, MAX_SERVICE_NAME_SIZE * MAX_SERVICES_HOSTED * 2 + MAX_SERVICES_HOSTED);
                            params.service_names->Format(                                                   // Expose everything except taken services
                                services_conn_params,
                                MAX_SERVICE_NAME_SIZE * MAX_SERVICES_HOSTED * 2 + MAX_SERVICES_HOSTED,
                                params.service_names->Count(params.service_names),
                                params.service_names,
                                services_taken);

                            if (send(*new_sock_params->socket, services_conn_params, strlen(services_conn_params), 0) != SOCKET_ERROR)                                                 // Send services offer                                
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD REGISTER]:\n\tServices offer sent to %s:%hu\n\n",
                                    inet_ntoa((*new_sock_params->address).sin_addr),
                                    ntohs((*new_sock_params->address).sin_port));
                                LeaveCriticalSection(&disp);
                                waiting_fetch_resp->Insert(new_sock_params, &waiting_fetch_resp);   

                            }
                            else
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD REGISTER]:\n\tSending services offer to %s:%hu failed\n\n",
                                    inet_ntoa((*new_sock_params->address).sin_addr),
                                    ntohs((*new_sock_params->address).sin_port));
                                LeaveCriticalSection(&disp);
                                new_sock_params->Dispose();                                                                                                                             // If failed, reject client (Dispose closes socket)
                            }
                        }
                    }

                    if (block_flag)                                                                                                                                                     // If creating sockets failed block here till safe shutdown
                    {
                        new_sock_params->DisposeSelf();
                        free(new_sock_params);
                        EnterCriticalSection(&disp);
                        printf("[THREAD REGISTER]:\n\tClosing thread...\n\n");
                        --thread_counter;
                        LeaveCriticalSection(&disp);
                        while (!params.end_thr_flag) { Sleep(1000); }
                        return -1;
                    }


                }

                if (FD_ISSET(*(params.register_socket_params->socket), &exc_set))                                                                                                       // Check for errors
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD REGISTER]:\n\tAn error occurred at %s:%hu\n\n", inet_ntoa(params.register_socket_params->address->sin_addr), ntohs(params.register_socket_params->address->sin_port));
                    LeaveCriticalSection(&disp);
                }

                for (SOCKET_DATA* pending_it = waiting_fetch_resp; pending_it != NULL; )                                   // Check if connect is sent
                {
                    rem_happened = false;
                    if (FD_ISSET(*(pending_it->socket), &read_set))
                    {
                        memset(message_buff, 0, MAX_MESSAGE_SIZE);
                        bytes_rec = recv(*(pending_it->socket), message_buff, MAX_MESSAGE_SIZE, 0);                                                     // Client Connect(char* service_name)
                        if (bytes_rec > 0)
                        {
                            SERVICE_NAME* chk_name = (SERVICE_NAME*)(malloc(sizeof(SERVICE_NAME)));
                            chk_name->Initialize();
                            chk_name->name = (char*)(malloc(strlen(message_buff) + 1));
                            sprintf(chk_name->name, "%s\0", message_buff);

                            if (params.service_names->Contains(chk_name->name, params.service_names) && !services_taken->Contains(chk_name->name, services_taken))  // Check if exists and is free
                            {

                                if (send(*(pending_it->socket), "ACK\0", strlen("ACK\0"), 0) != SOCKET_ERROR)                                           // Confirm connect to client
                                {
                                    EnterCriticalSection(&disp);
                                    printf("[THREAD REGISTER]:\n\tClient %s:%hu connected to %s service\n\n",
                                        inet_ntoa(params.register_socket_params->address->sin_addr),
                                        ntohs(params.register_socket_params->address->sin_port),
                                        chk_name->name);
                                    LeaveCriticalSection(&disp);
                                    services_taken->Insert(chk_name, &services_taken);                                                                  // When ACK sent take tervice
                                    int target_service = params.service_names->IndexOf(chk_name->name, params.service_names);
                                    SOCKET_DATA* target_service_params = params.client_socket_params->At(target_service, params.client_socket_params);  // Fetch socket & addr params for ClientCommunication 
                                    target_service_params->address = pending_it->address;
                                    target_service_params->socket = pending_it->socket;
                                    SOCKET_DATA* to_rem = pending_it;
                                    FD_CLR(*to_rem->socket, &read_set);
                                    FD_CLR(*to_rem->socket, &exc_set);
                                    pending_it = pending_it->next;
                                    to_rem->Detach(&waiting_fetch_resp, to_rem);
                                    rem_happened = true;
                                    params.accept_triggers[target_service] = true;                         // Invoke thread start working on fetched socket
                                }
                                else                                                                                                                    // Failed: Remove client
                                {
                                    EnterCriticalSection(&disp);
                                    printf("[THREAD REGISTER]:\n\tSending service connect ACK to %s:%hu failed\n\n",
                                        inet_ntoa(params.register_socket_params->address->sin_addr),
                                        ntohs(params.register_socket_params->address->sin_port));
                                    LeaveCriticalSection(&disp);

                                    chk_name->Dispose();
                                    to_rem_pend->Insert(pending_it, &to_rem_pend);                                                                     // Rem after iterate
                                }
                            }
                            else
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD REGISTER]:\n\tConnecting client %s:%hu to %s service failed, service taken or not exists\n\n",
                                    inet_ntoa(params.register_socket_params->address->sin_addr),
                                    ntohs(params.register_socket_params->address->sin_port),
                                    chk_name->name);
                                chk_name->Dispose();
                                LeaveCriticalSection(&disp);

                                if (send(*(pending_it->socket), "NACK\0", strlen("NACK\0"), 0) != SOCKET_ERROR)
                                {
                                    EnterCriticalSection(&disp);
                                    printf("[THREAD REGISTER]:\n\tSending service connect NACK to %s:%hu success\n\n",
                                        inet_ntoa(params.register_socket_params->address->sin_addr),
                                        ntohs(params.register_socket_params->address->sin_port));
                                    LeaveCriticalSection(&disp);
                                }
                                else                                                                                                                   // Connect ack failed, remove client
                                {
                                    EnterCriticalSection(&disp);
                                    printf("[THREAD REGISTER]:\n\tSending service connect NACK to %s:%hu failed\n\n",
                                        inet_ntoa(params.register_socket_params->address->sin_addr),
                                        ntohs(params.register_socket_params->address->sin_port));
                                    LeaveCriticalSection(&disp);

                                    to_rem_pend->Insert(pending_it, &to_rem_pend);

                                }
                            }
                        }
                    }

                    if (pending_it != NULL && FD_ISSET(*(pending_it->socket), &exc_set))
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD REGISTER]:\n\tAn errorr occurred on %s:%hu failed\n\n",
                            inet_ntoa(params.register_socket_params->address->sin_addr),
                            ntohs(params.register_socket_params->address->sin_port));
                        LeaveCriticalSection(&disp);
                        to_rem_pend->Insert(pending_it, &to_rem_pend);
                    }

                    if (pending_it!= NULL && !rem_happened)
                        pending_it = pending_it->next;
                }
            }
        } while (!*params.end_thr_flag);

        EnterCriticalSection(&disp);
        printf("[THREAD REGISTER]:\n\tClosing thread register...\n\n");
        --thread_counter;
        LeaveCriticalSection(&disp);
    }
    DWORD WINAPI ClientReqHandleThr(LPVOID lp_param)
    {
        CLIENT_THR_PARAMS params = *((CLIENT_THR_PARAMS*)lp_param);
        EnterCriticalSection(&disp);
        printf("[THREAD %s CLIENT]:\n\tThread started\n\n", params.service_name);
        LeaveCriticalSection(&disp);

        do
        {
            while (!*params.accept_trigger)
            {
                Sleep(REQUEST_ACQUISITION_INTERVAL_SECS); // Sleep until  Accepted in ClientRegisterThr fetch client
                if (*params.end_thr_flag)
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD %s CLIENT]:\n\tClosing thread...\n\n", params.service_name);
                    --thread_counter;
                    LeaveCriticalSection(&disp);
                    return 1;
                }
            }
            *params.accept_trigger = false;

            EnterCriticalSection(&disp);
            printf("[THREAD %s CLIENT]:\n\tClient %s:%hu fetched to service thread\n\n",
                params.service_name,
                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                ntohs(params.socket_data_accepted->address->sin_port));
            LeaveCriticalSection(&disp);

            int addr_len = 0;
            char message_buff[MAX_MESSAGE_SIZE];
            int bytes_rec;
            int cycles = 0;
            bool send_failed;
            do
            {
                EnterCriticalSection(&disp);
                printf("[THREAD %s CLIENT]:\n\tBatch Dequeue for %s:%hu:\n\n",
                    params.service_name,
                    inet_ntoa(params.socket_data_accepted->address->sin_addr),
                    ntohs(params.socket_data_accepted->address->sin_port));
                LeaveCriticalSection(&disp);

                memset(message_buff, 0, MAX_MESSAGE_SIZE);
                #pragma omp atomic capture  // Send batch in atomic region
                {
                    EnterCriticalSection(&disp);    // Single lock because inside atomic region
                    cycles = params.out_buffer->messges_enqueued;
                    send_failed = false;
                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    while (cycles > 0 && params.out_buffer->Dequeue(message_buff, strlen(message_buff)))                                                                              // Send buffered messages when client connected
                    {

                        if (send(*params.socket_data_accepted->socket, message_buff, strlen(message_buff), 0) != SOCKET_ERROR)
                            printf("[THREAD %s CLIENT]:\n\tBatch message successfully sent\n\n", params.service_name);
                        else
                        {
                            printf("[THREAD %s CLIENT]:\n\tBatch message send failed\n\n", params.service_name);                                  // If failec keep if channel reopens later
                            params.out_buffer->Enqueue(message_buff, strlen(message_buff) + 1);
                            send_failed = true;
                        }
                        memset(message_buff, 0, MAX_MESSAGE_SIZE);
                        --cycles;
                    }

                    if (!send_failed)
                    {
                        if (send(*params.socket_data_accepted->socket, "BEND\0", strlen("BEND\0"), 0) != SOCKET_ERROR)                      // When done send BEND (Batch End)
                        {
                            printf("[THREAD %s CLIENT]:\n\tBatch of buffered data seuccessfully sent. BEND sent to %s:%hu\n\n",
                                params.service_name,
                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                ntohs(params.socket_data_accepted->address->sin_port));

                        }
                        else
                        {
                            printf("[THREAD %s CLIENT]:\n\tBatch of buffered data seuccessfully sent. Sending BEND to %s:%hu failed\n\n",   // If not close and wait for another accept
                                params.service_name,
                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                ntohs(params.socket_data_accepted->address->sin_port));
                            LeaveCriticalSection(&disp);
                            closesocket(*params.socket_data_accepted->socket);
                            *params.socket_data_accepted->socket = INVALID_SOCKET;
                            LeaveCriticalSection(&disp);
                            continue;
                        }
                    }
                    else
                    {
                        printf("[THREAD %s CLIENT]:\n\tClient %s:%hu failed disconnected\n\n",   // If not close and wait for another accept
                            params.service_name,
                            inet_ntoa(params.socket_data_accepted->address->sin_addr),
                            ntohs(params.socket_data_accepted->address->sin_port));
                        closesocket(*params.socket_data_accepted->socket);
                        *params.socket_data_accepted->socket = INVALID_SOCKET;
                        *params.accept_trigger = false;
                        break;
                    }
                    LeaveCriticalSection(&disp);
                }


                unsigned long mode = 1;

                fd_set read_set;
                fd_set exc_set;

                timeval time_val;
                time_val.tv_sec = REQUEST_ACQUISITION_INTERVAL_SECS;
                time_val.tv_usec = 0;

                int i_result;
                while (!*(params.end_thr_flag))
                {
                    FD_ZERO(&read_set);
                    FD_ZERO(&exc_set);

                    FD_SET(*params.socket_data_accepted->socket, &read_set);
                    FD_SET(*params.socket_data_accepted->socket, &exc_set);

                    // Check if Send is requested
                    i_result = select(0, &read_set, NULL, &exc_set, &time_val);
                    if (i_result == SOCKET_ERROR)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD %s CLIENT]:\n\tAn error occurred on: Select socket\n\n", params.service_name);
                        LeaveCriticalSection(&disp);
                    }
                    else if (i_result > 0)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD %s CLIENT]:\n\tAcquisition done: %d events detected\n\n", params.service_name, i_result);
                        LeaveCriticalSection(&disp);

                        if (FD_ISSET(*params.socket_data_accepted->socket, &read_set))   // Client sent something
                        {
                            memset(message_buff, 0, MAX_MESSAGE_SIZE);
                            bytes_rec = recv(*params.socket_data_accepted->socket, message_buff, MAX_MESSAGE_SIZE, 0);
                            if (bytes_rec <= 0)
                            {

                                EnterCriticalSection(&disp);
                                printf("[THREAD %s CLIENT]:\n\tRecv failed on %s:%hu, closing socket\n\n",
                                    params.service_name,
                                    inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                    ntohs(params.socket_data_accepted->address->sin_port));
                                LeaveCriticalSection(&disp);
                                closesocket(*params.socket_data_accepted->socket);
                                *params.socket_data_accepted->socket = INVALID_SOCKET;

                                printf("[THREAD %s CLIENT]:\n\tClient %s:%hu failed disconnected\n\n",   // If not close and wait for another accept
                                    params.service_name,
                                    inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                    ntohs(params.socket_data_accepted->address->sin_port));
                                *params.accept_trigger = false;
                                break;
                            }

                            if (bytes_rec > 0)
                            {
                                switch (*((unsigned short*)message_buff))
                                {
                                case CLIENT_ENQ:
                                {
                                    CLIENT_MSG_ENQ* recv_msg = (CLIENT_MSG_ENQ*)message_buff;
                                    recv_msg->content = message_buff + 4;

                                    EnterCriticalSection(&disp);
                                    printf("[THREAD %s CLIENT]:\n\tEnqueue request from %s:%hu, MSGID: %u\n\t%s\n\n",
                                        params.service_name,
                                        inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                        ntohs(params.socket_data_accepted->address->sin_port),
                                        recv_msg->msg_id,
                                        recv_msg->content);
                                    LeaveCriticalSection(&disp);

                                    unsigned short code = SERVICE_MSG;
                                    unsigned size=4+ strlen(params.service_name)+1+strlen(recv_msg->content)+1+4;
                                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                                    memcpy(message_buff, &size, 4);
                                    memcpy(message_buff+2, (char*)&code, 2);
                                    memcpy(message_buff+2 + 2, params.service_name, strlen(params.service_name));
                                    memcpy(message_buff+2 + 2 + strlen(params.service_name) + 1, recv_msg->content, strlen(recv_msg->content));
                                    memcpy(message_buff+2 + 2 + strlen(params.service_name) + 1 + strlen(recv_msg->content) + 1, &msg_id_cnt, 4);
                                    ++msg_id_cnt;

                                    if (params.in_buffer->Enqueue(message_buff, 2 + strlen(params.service_name) + 1 + strlen(recv_msg->content) + 1 + 4))     // Try Enqueue for mirroring
                                    {
                                        if (send(*params.socket_data_accepted->socket, "ACK\0", strlen("ACK\0"), 0) != SOCKET_ERROR)    // If OK send ack
                                        {
                                            printf("[THREAD %s CLIENT]:\n\tEnqueue request for MSGID: %u successed, ACK sent to %s:%hu\n\n",
                                                params.service_name,
                                                recv_msg->msg_id,
                                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                                ntohs(params.socket_data_accepted->address->sin_port));
                                            LeaveCriticalSection(&disp);
                                        }
                                        else
                                        {
                                            printf("[THREAD %s CLIENT]:\n\tEnqueue request successed, sending ACK to %s:%hu failed\n\n",
                                                params.service_name,
                                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                                ntohs(params.socket_data_accepted->address->sin_port));
                                            LeaveCriticalSection(&disp);
                                            closesocket(*params.socket_data_accepted->socket);
                                            *params.socket_data_accepted->socket = INVALID_SOCKET;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        if (send(*params.socket_data_accepted->socket, "NACK\0", strlen("NACK\0"), 0) != SOCKET_ERROR)   // if NOK send nack
                                        {
                                            printf("[THREAD %s CLIENT]:\n\tEnqueue request failed, NACK sent to %s:%hu\n\n",
                                                params.service_name,
                                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                                ntohs(params.socket_data_accepted->address->sin_port));
                                            LeaveCriticalSection(&disp);
                                        }
                                        else
                                        {
                                            printf("[THREAD %s CLIENT]:\n\tEnqueue request failed, sending NACK to %s:%hu failed\n\n",
                                                params.service_name,
                                                inet_ntoa(params.socket_data_accepted->address->sin_addr),
                                                ntohs(params.socket_data_accepted->address->sin_port));
                                            LeaveCriticalSection(&disp);
                                            closesocket(*params.socket_data_accepted->socket);
                                            *params.socket_data_accepted->socket = INVALID_SOCKET;
                                            break;
                                        }
                                    }

                                    break;
                                }
                                }
                            }
                        }
                    }

                    //#pragma omp atomic capture  // Send what is buffered
                    //{
                    //    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    //    EnterCriticalSection(&disp);    // Single lock because inside atomic region
                    //    while (params.out_buffer->Dequeue(message_buff + 2, strlen(message_buff + 2)))
                    //    {
                    //        //Send

                    //        memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    //    }
                    //    LeaveCriticalSection(&disp);
                    //}
                }

                Sleep(1000);
            } while (!*(params.end_thr_flag));
        } while (!*params.accept_trigger && !*params.end_thr_flag);

        EnterCriticalSection(&disp);
        printf("[THREAD %s CLIENT]:\n\tClosing thread..\n\n", params.service_name);
        --thread_counter;
        LeaveCriticalSection(&disp);
        return 0;
    }
    DWORD WINAPI ServiceCommunicationThr(LPVOID lpParam)
    {
        EnterCriticalSection(&disp);
        printf("[THREAD LST/RECV]:\n\tThread started\n\n");
        LeaveCriticalSection(&disp);
        LISTENING_THR_PARAMS params = *((LISTENING_THR_PARAMS*)lpParam);

        SOCKET tmpSocket;
        sockaddr_in tmpAddr;
        unsigned long nb_mode = 1;

        if (bind(*(params.listen_socket_params->socket), (struct sockaddr*)params.listen_socket_params->address, sizeof(*params.listen_socket_params->address)) == SOCKET_ERROR)
        {
            EnterCriticalSection(&disp);
            printf("[THREAD LST/RECV]:\n\tListen socket bind failed with error code : %d, witing safe shutdown\n\n", WSAGetLastError());
            LeaveCriticalSection(&disp);
            params.listen_socket_params->initialized = false;
            while (!*(params.end_thr_flag)) Sleep(1000);// Wait for safe shutdown
            EnterCriticalSection(&disp);
            --thread_counter;
            LeaveCriticalSection(&disp);
            return -1;
        }

        if(ioctlsocket(*(params.listen_socket_params->socket), FIONBIO, &nb_mode) == 0)
        {
            EnterCriticalSection(&disp);
            printf("[THREAD LST / RECV]\n\tListen socket %s:%hu in non-blocking mode\n\n", inet_ntoa(params.listen_socket_params->address->sin_addr), ntohs(params.listen_socket_params->address->sin_port));
            LeaveCriticalSection(&disp);
        }
        else
        {
            EnterCriticalSection(&disp);
            printf("[THREAD LST / RECV]\n\tSetting listen socket %s:%hu in non-blocking mode failed\n\n", inet_ntoa(params.listen_socket_params->address->sin_addr), ntohs(params.listen_socket_params->address->sin_port));
            closesocket(*params.listen_socket_params->socket);
            *params.listen_socket_params->socket = INVALID_SOCKET;
            params.listen_socket_params->initialized = false;
            while (!*(params.end_thr_flag)) Sleep(1000);// Wait for safe shutdown
            EnterCriticalSection(&disp);
            --thread_counter;
            LeaveCriticalSection(&disp);
            return -1;
        }
        params.listen_socket_params->initialized = true;

        listen(*(params.listen_socket_params->socket), SOMAXCONN);

        fd_set read_set;
        fd_set exc_set;

        timeval time_val;
        time_val.tv_sec = REQUEST_ACQUISITION_INTERVAL_SECS;
        time_val.tv_usec = 0;
        int i_result;

        EnterCriticalSection(&disp);
        printf("[THREAD LST/RECV]:\n\tListening at: %s:%hu\n\n", inet_ntoa(params.listen_socket_params->address->sin_addr), ntohs(params.listen_socket_params->address->sin_port));
        LeaveCriticalSection(&disp);

        int addr_len = sizeof(sockaddr_in);
        bool event_flag = false;
        OUT_SERVICE* sub_new = (OUT_SERVICE*)malloc(sizeof(OUT_SERVICE));
        int bytes_rec = 0;
        bool re_init_flag = false;
        MSG_ACK_PND* pending_acks_pnd = NULL;

        do
        {
            if (re_init_flag)
            {
                EnterCriticalSection(&disp);
                printf("[THREAD LST/RECV]:\n\tService was out of range, trying reconnect\n\n");
                LeaveCriticalSection(&disp);

                EXPOSE_PARAMS exp_params;
                exp_params.target_params = params.reinit_sock_data;
                exp_params.service_names = *params.service_names;
                exp_params.subscriebers = params.subscriebers;
                exp_params.nb_mode = &nb_mode;
                exp_params.expose_mess_buff = params.expose_mess_buff;
                exp_params.expose_mess = params.expose_mess;
                ExposeServices(exp_params);
                re_init_flag = false;
            }


            while (!*(params.end_thr_flag))    // Need success accept
            {
                if (!(*params.subscriebers)->exposed) // Check only first
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tWaiting for accept\n\n");
                    LeaveCriticalSection(&disp);

                    // Do not block for safe shutdown
                    do
                    {
                        if (*params.end_thr_flag)
                        {
                            EnterCriticalSection(&disp);
                            printf("[THREAD LST/RECV]:\n\tClosing thread...\n\n");
                            --thread_counter;
                            LeaveCriticalSection(&disp);
                            return 1;
                        }

                        FD_ZERO(&read_set);
                        FD_SET(*params.listen_socket_params->socket, &read_set);

                        i_result = select(0, &read_set, NULL, NULL, &time_val);             // Event happened?
                    } while (!FD_ISSET(*params.listen_socket_params->socket, &read_set));   // On listen socket?

                    tmpSocket = accept(*params.listen_socket_params->socket, (struct sockaddr*)&tmpAddr, &addr_len);
                    FD_ZERO(&read_set);
                    if (tmpSocket == INVALID_SOCKET)
                    {
                        
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST/RECV]:\n\tAccept socket failed with error: %d, waiting for safe shutdown\n\n", WSAGetLastError());
                        --thread_counter;
                        LeaveCriticalSection(&disp);
                        do { Sleep(1000); } while (!*params.end_thr_flag);    // Cooldown
                    }
                    else
                    {
                        sub_new->Initialize();
                        sub_new->address = (sockaddr_in*)(malloc(sizeof(sockaddr_in)));
                        sub_new->socket = (SOCKET*)(malloc(sizeof(SOCKET)));
                        sub_new->exposed = false;

                        memcpy(sub_new->address, &tmpAddr, sizeof(tmpAddr));
                        memcpy(sub_new->socket, &tmpSocket, sizeof(tmpSocket));
                        break;
                    }
                }
                else                                                                          // Already has him trough Expose
                {
                    sub_new = *params.subscriebers;
                    break;
                }

            }

            if (!sub_new->exposed)
            {
                EnterCriticalSection(&disp);
                printf("[THREAD LST / RECV]:\n\tConnected to: %s:%hu\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                LeaveCriticalSection(&disp);

                if (send(*sub_new->socket, params.expose_mess_buff, 6 + params.expose_mess->content_size + 1, 0) != SOCKET_ERROR)
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST / RECV]:\n\tServices offer sent to %s:%hu\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                    LeaveCriticalSection(&disp);

                    if (ioctlsocket(*sub_new->socket, FIONBIO, &nb_mode) == 0)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST / RECV]\n\tAccepted socket %s:%hu in non-blocking mode\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                        LeaveCriticalSection(&disp);
                        sub_new->exposed = true;
                        event_flag = true;
                        (*params.subscriebers)->Insert(sub_new, params.subscriebers);
                    }
                    else
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST / RECV]\n\tSetting accepted socket %s:%hu in non-blocking mode failed\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                        LeaveCriticalSection(&disp);
                        closesocket(*sub_new->socket);
                        sub_new->exposed = false;
                        shutdown(*sub_new->socket, 2);
                        *sub_new->socket = INVALID_SOCKET;
                    }
                }
                else //Send failed close socket and remove from list
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST / RECV]:\n\tSending services offer to %s:%hu client failed\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                    LeaveCriticalSection(&disp);
                    closesocket(*sub_new->socket);
                    *sub_new->socket = INVALID_SOCKET;
                    sub_new->exposed = false;
                }


                for (unsigned loc = 0; loc < (*params.service_names)->Count(*params.service_names); ++loc)
                {
                    if (loc < MAX_SERVICES_HOSTED && sub_new->service_idx[loc] == -1) // Is Delta
                        sub_new->SubscribeTo(loc);

                    else if (loc == MAX_SERVICES_HOSTED)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST / RECV]:\n\tMaximum subscriptions for %s:%hu reached:\n\n", inet_ntoa(sub_new->address->sin_addr), ntohs(sub_new->address->sin_port));
                        LeaveCriticalSection(&disp);
                        break;
                    }
                }
            }

            FD_ZERO(&read_set);
            FD_ZERO(&exc_set);

            FD_SET(*sub_new->socket, &read_set);
            FD_SET(*sub_new->socket, &exc_set);

            char message_buff[MAX_MESSAGE_SIZE];
            struct MSG_ACK_PND* pending_ack_it;
            while (!*(params.end_thr_flag))
            {

                // Try send faield acks
                pending_ack_it = pending_acks_pnd;
                while (pending_ack_it != NULL)
                {
                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    memcpy(message_buff, (char*)&pending_ack_it->ack, 6);
                    memcpy(message_buff + 6, pending_ack_it->ack->service, strlen(pending_ack_it->ack->service));
                    if (send(*pending_ack_it->reciever->socket, message_buff, 6 + strlen(pending_ack_it->ack->service) + 1, 0) != SOCKET_ERROR)
                    {
                        EnterCriticalSection(&disp);
                        printf("[THREAD LST/RECV]:\n\tRe-send of failed ack for MSG ID: %u succeded\n\n", pending_ack_it->ack->msg_id);
                        LeaveCriticalSection(&disp);
                        MSG_ACK_PND* to_rem = pending_ack_it;
                        pending_ack_it = pending_ack_it->next;
                        to_rem->Remove(to_rem, &pending_acks_pnd);
                    }
                    pending_ack_it->next;
                };

                i_result = select(0, &read_set, NULL, &exc_set, &time_val);
                if (i_result == SOCKET_ERROR)
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tAn error occurred on: Select socket\n\n");
                    LeaveCriticalSection(&disp);
                }
                else if (i_result > 0)
                {
                    EnterCriticalSection(&disp);
                    printf("[THREAD LST/RECV]:\n\tAcquisition done: %d events detected\n\n", i_result);
                    LeaveCriticalSection(&disp);
                    for (OUT_SERVICE* sub = *(params.subscriebers); sub != NULL; sub = sub->next)
                    {
                        // Listen & Already contacted me 
                        if (FD_ISSET(*sub->socket, &read_set))   // Client sent something
                        {
                            memset(message_buff, 0, MAX_MESSAGE_SIZE);
                            bytes_rec = recv(*sub->socket, message_buff, MAX_MESSAGE_SIZE, 0);
                            if (bytes_rec <= 0)
                            {
                                closesocket(*sub->socket);
                                *sub->socket = INVALID_SOCKET;
                                sub->exposed = false;
                                re_init_flag = true;
                                break;
                            }

                            if (bytes_rec > 0)
                            {
                                EnterCriticalSection(&disp);
                                printf("[THREAD LST/RECV]:\n\tMessage from: %s:%hu, %d bytes recieved\n\n",
                                    inet_ntoa(sub->address->sin_addr),
                                    ntohs(sub->address->sin_port),
                                    bytes_rec);
                                LeaveCriticalSection(&disp);

                                HANDLE_LST** client_req_handle;		// For client connections thread
                                HANDLE_LST** loader_handle;			// For loader threads
                                HANDLE_LST** GC_handle;				// For GC threads

                                switch (message_buff[0])
                                {
                                case SERVICES_ENL:
                                {
                                    SETUP_MSG recved_msg;
                                    recved_msg.Initialize();
                                    recved_msg.msg_code = *((unsigned short*)message_buff);
                                    recved_msg.content_size = *((unsigned*)(message_buff + 2));
                                    recved_msg.content = message_buff + 6;
                                    SERVICE_NAME* new_names = NULL;
                                    HandleDeltaServices(recved_msg.content, *params.service_names, &new_names);

                                    #pragma omp atomic capture
                                    {
                                        EnterCriticalSection(&disp);
                                        printf("[THREAD LST/RECV] Delta services:\n");
                                        if (new_names == NULL) printf("\tNONE");
                                        else                   new_names->PrintOut(new_names);
                                        printf("\n\n");
                                        // Single disp lock because of atomic region
                                        // Create delta buffers
                                        SERVICE_NAME* new_names_it = new_names;
                                        int new_service_loc = (*params.service_names)->Count(*params.service_names);
                                        bool is_inserted;
                                        unsigned service_idx = (*params.service_names)->Count(*params.service_names);
                                        while (new_names_it != NULL)
                                        {
                                            is_inserted = false;
                                            BUFF_DESC* new_send_buff;
                                            BUFF_DESC* new_recv_buff;

                                            switch (true)
                                            {
                                            case(true):
                                            {
                                                printf("[THREAD LST/RECV] Creating delta buffers for %s:\n\n", new_names_it->name);

                                                new_send_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                                                new_send_buff->Initialize();

                                                if ((new_send_buff->memory = (char*)malloc(params.buff_params->service_in_queue)) == NULL)
                                                {
                                                    printf("[THREAD LST/RECV] Memory shortage on creating delta buffers.\n\n");
                                                    new_send_buff->Dispose();
                                                    new_send_buff = NULL;
                                                    break;
                                                }
                                                else
                                                {
                                                    new_send_buff->context = INBUF_SRV;
                                                    new_send_buff->capacity = params.buff_params->service_in_queue;
                                                    new_send_buff->name = (char*)malloc(strlen(new_names_it->name) + strlen("|SEND BUFF\0") + 1);
                                                    new_send_buff->Prepare();

                                                    sprintf(new_send_buff->name, "%s|SEND BUFF", new_names_it->name);

                                                    if (*params.service_buffers_in == NULL) *params.service_buffers_in = new_send_buff;
                                                    else (*(params.service_buffers_in))->Insert(new_send_buff, params.service_buffers_in);

                                                    printf("[THREAD LST/RECV] Buffer: %s successfully created.\n\n", new_send_buff->name);
                                                }

                                                new_recv_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                                                new_recv_buff->Initialize();

                                                if ((new_recv_buff->memory = (char*)malloc(params.buff_params->service_out_queue)) == NULL)
                                                {
                                                    printf("[THREAD LST/RECV] Memory shortage on creating delta buffers.\n\n");
                                                    new_recv_buff->Dispose();
                                                    new_recv_buff = NULL;
                                                    break;
                                                }
                                                else
                                                {
                                                    new_recv_buff->context = OUTBUF_SRV;
                                                    new_recv_buff->capacity = params.buff_params->service_out_queue;
                                                    new_recv_buff->name = (char*)malloc(strlen(new_names_it->name) + strlen("|RECV BUFF\0") + 1);
                                                    new_recv_buff->Prepare();
                                                    sprintf(new_recv_buff->name, "%s|RECV BUFF\0", new_names_it->name);

                                                    if (*params.service_buffers_out == NULL) *params.service_buffers_out = new_recv_buff;
                                                    else (*(params.service_buffers_out))->Insert(new_recv_buff, params.service_buffers_out);

                                                    printf("[THREAD LST/RECV] Buffer: %s successfully created.\n\n", new_recv_buff->name);
                                                }
                                                printf("[THREAD LST/RECV] DONE\n\n");

                                                printf("[THREAD LST/RECV] Creating delta threads for %s:\n\n", new_names_it->name);
                                                // Start threads                                 
                                                //Create loader thread
                                                HANDLE_LST* load_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                                if (load_handle == NULL)
                                                {
                                                    printf("[THREAD LST/RECV] Memory shortage on creating delta threads.\n\n");
                                                    break;
                                                }

                                                load_handle->Initialize();
                                                load_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                                params.threadIDs[thread_counter] = thread_counter;

                                                SERVICE_LOADER_THR_PARAMS* service_loader_thr_param = (SERVICE_LOADER_THR_PARAMS*)malloc(sizeof(SERVICE_LOADER_THR_PARAMS));
                                                service_loader_thr_param->Initialize();
                                                memcpy(service_loader_thr_param->service_name, new_names_it->name, strlen(new_names_it->name));

                                                service_loader_thr_param->in_buffer = *params.input_buffer;             // Reds from common input buffer             
                                                service_loader_thr_param->out_buffer = new_send_buff;

                                                service_loader_thr_param->end_thr_flag = params.end_thr_flag;

                                                *load_handle->handle = CreateThread(NULL, 0, &ServiceLoaderThr, service_loader_thr_param, 0, params.threadIDs + thread_counter);
                                                (*params.loader_handle)->Insert(load_handle, params.loader_handle);
                                                ++thread_counter;

                                                // Create GC thread
                                                HANDLE_LST* GC_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                                if (GC_handle == NULL)
                                                {
                                                    printf("[THREAD LST/RECV] Memory shortage on creating delta threads.\n\n");
                                                    break;
                                                }

                                                GC_handle->Initialize();
                                                GC_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                                params.threadIDs[thread_counter] = thread_counter;

                                                SERVICE_GC_THR_PARAMS* GC_thr_param = (SERVICE_GC_THR_PARAMS*)malloc(sizeof(SERVICE_GC_THR_PARAMS));
                                                GC_thr_param->Initialize();
                                                memcpy(GC_thr_param->service_name, new_names_it->name, strlen(new_names_it->name));

                                                GC_thr_param->in_buffer = *params.ack_buffer;               // Reads from common ack buffer

                                                GC_thr_param->out_buffer = new_send_buff;

                                                GC_thr_param->end_thr_flag = params.end_thr_flag;
                                                *GC_handle->handle = CreateThread(NULL, 0, &ServiceGCThr, GC_thr_param, 0, params.threadIDs + thread_counter);
                                                (*params.GC_handle)->Insert(GC_handle, params.GC_handle);
                                                ++thread_counter;

                                                // Create client communication thread
                                                SOCKET_DATA* client_socket = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
                                                if (client_socket == NULL) break;
                                                client_socket->Initialize();

                                                HANDLE_LST* client_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                                                if (client_handle == NULL)
                                                {
                                                    printf("[THREAD LST/RECV] Memory shortage on creating delta threads.\n\n");
                                                    break;
                                                }

                                                client_handle->Initialize();
                                                client_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                                                params.threadIDs[thread_counter] = thread_counter;

                                                CLIENT_THR_PARAMS* client_thr_param = (CLIENT_THR_PARAMS*)malloc(sizeof(CLIENT_THR_PARAMS));
                                                client_thr_param->Initialize();
                                                memcpy(client_thr_param->service_name, new_names_it->name, strlen(new_names_it->name));

                                                client_thr_param->in_buffer = new_recv_buff;
                                                client_thr_param->out_buffer = new_send_buff;
                                                client_thr_param->accept_trigger = &(params.accept_triggers[service_idx]);    // Index of service wich would later be inserted at MARKER: #1
                                                ++service_idx;

                                                client_thr_param->end_thr_flag = params.end_thr_flag;
                                                client_thr_param->socket_data_accepted = (*params.client_socket_params)->At(service_idx , *params.client_socket_params);
                                                *client_handle->handle = CreateThread(NULL, 0, &ClientReqHandleThr, client_thr_param, 0, params.threadIDs + thread_counter);
                                                (*params.client_req_handle)->Insert(client_handle, params.client_req_handle);
                                                (*params.client_socket_params)->Insert(client_socket, params.client_socket_params);
                                                ++thread_counter;

                                                printf("[THREAD LST/RECV] Done.\n\n");
                                                SERVICE_NAME* to_add = (SERVICE_NAME*)malloc(sizeof(SERVICE_NAME));
                                                to_add->Initialize();
                                                to_add->name = (char*)malloc(strlen(new_names_it->name) + 1);
                                                sprintf(to_add->name, "%s\0", new_names_it->name);
                                                to_add->length = new_names_it->length;

                                                SERVICE_NAME* new_ptr = new_names_it->next;
                                                (*params.service_names)->Insert(to_add, params.service_names);    // Ad as new service. MARKER:#1
                                                new_names_it = new_ptr;

                                                sub->SubscribeTo(new_service_loc);
                                                ++new_service_loc;
                                                is_inserted = true;
                                                break;
                                            }
                                            }

                                            if (!is_inserted)
                                                new_names_it = new_names_it->next;
                                        }


                                        if (!sub->exposed)
                                        {
                                            GenerateDeltaServicesMsg(params.expose_mess, *params.service_names);

                                            unsigned long nb_mode = 1;
                                            EXPOSE_PARAMS exp_params;
                                            exp_params.target_params = NULL;
                                            exp_params.service_names = *params.service_names;
                                            exp_params.subscriebers = params.subscriebers;
                                            exp_params.nb_mode = &nb_mode;
                                            exp_params.expose_mess_buff = params.expose_mess_buff;
                                            exp_params.expose_mess = params.expose_mess;
                                            LeaveCriticalSection(&disp);
                                            if (ExposeServiceTo(exp_params, sub)) sub->exposed = true;
                                            EnterCriticalSection(&disp);
                                        }

                                        if (new_names != NULL)
                                        {
                                            new_names->Dispose();
                                            free(new_names);
                                        }
                                        PrintServicesAndBuffs(*params.service_names, *params.service_buffers_in, *params.service_buffers_out, *params.input_buffer, *params.ack_buffer);
                                        is_cl_acceptable = true;
                                        LeaveCriticalSection(&disp);
                                    }
                                    break;
                                }
                                case SERVICE_MSG:   // Message sent by mirroring server
                                {
                                    struct SERVICE_MSG* msg = (struct SERVICE_MSG*)(message_buff);
                                    printf("[THREAD LST/RECV]:\n\tService message from: %s:%hu, target service: %s \n\n",
                                        inet_ntoa(sub->address->sin_addr),
                                        ntohs(sub->address->sin_port),
                                        msg->content);

                                    
                                    SERVICE_NAME* service_name =(*params.service_names)->Find(msg->service, *params.service_names);
                                    struct MSG_NACK msg_nack;
                                    if (service_name == NULL)
                                    {
                                        // Send NACK if failed
                                        printf("[THREAD LST/RECV]:\n\t Target Service not found, MSG ID: %u \n\n", msg->msg_id);
                                        msg_nack.Initialize();
                                        msg_nack.msg_code = MSG_NACK;
                                        msg_nack.msg_id = msg->msg_id;
                                        msg_nack.error = (char*)malloc(strlen("Invalid service name: \0") + strlen(msg->service) + 1);
                                        memset(msg_nack.error, 0, strlen("Invalid service name: \0") + strlen(msg->service) + 1);
                                        sprintf(msg_nack.error, "Invalid service name: %s\0", msg->service);

                                        memset(message_buff, 0, MAX_MESSAGE_SIZE);
                                        memcpy(message_buff, (char*)&msg_nack, 6);
                                        memcpy(message_buff + 6, msg_nack.error, strlen(msg_nack.error));

                                        if (send(*sub->socket, message_buff, 6 + strlen(msg_nack.error) + 1, 0) != SOCKET_ERROR)
                                        {
                                            printf("[THREAD LST/RECV]:\n\t NACK for MSG ID: %u successfully sent \n\n", msg->msg_id);
                                        }
                                        msg_nack.Dispose();
                                        // Ignore if not sent, pending send supported only for ACKS
                                    }
                                    else
                                    {
                                        if((*params.input_buffer)->Enqueue(((char*)msg) + 2, strlen(msg->service) + 1 + strlen(msg->content) + 1 + 4)) // If message is handled OK, send ACK (+2 - cut msg code)
                                        {
                                            struct MSG_ACK* msg_ack;
                                            msg_ack = (struct MSG_ACK*)malloc(sizeof(struct MSG_ACK));
                                            msg_ack->Initialize();
                                            msg_ack->msg_code = MSG_ACK;
                                            msg_ack->msg_id = msg->msg_id;
                                            msg_ack->service = (char*)malloc(strlen(msg->service)+1);
                                            sprintf(msg_ack->service, "s\0", msg->service);

                                            memset(message_buff, 0, MAX_MESSAGE_SIZE);
                                            memcpy(message_buff, (char*)&msg_ack, 6);
                                            memcpy(message_buff + 6, msg_ack->service, strlen(msg_ack->service));
                                            if (send(*sub->socket, message_buff, 6 + strlen(msg_ack->service) + 1, 0) != SOCKET_ERROR)
                                            {
                                                printf("[THREAD LST/RECV]:\n\t ACK for MSG ID: %u successfully sent \n\n", msg->msg_id);
                                                msg_ack->Dispose();
                                                free(msg_ack);
                                            }
                                            else
                                            {
                                                // Store if channel recovers later
                                                printf("[THREAD LST/RECV]:\n\t ACK for MSG ID: %u send failed \n\n", msg->msg_id);
                                                MSG_ACK_PND* msg_ack_pnd = (MSG_ACK_PND*)malloc(sizeof(MSG_ACK_PND));
                                                msg_ack_pnd->Initialize();
                                                msg_ack_pnd->ack = msg_ack;
                                                msg_ack_pnd->reciever = sub;
                                                msg_ack_pnd->Insert(msg_ack_pnd, &pending_acks_pnd);
                                            }
                                        }
                                        
                                    }
                                    break;
                                }
                                case MSG_NACK:  // Sending service message failed
                                {
                                    struct MSG_NACK* msg_nack = (struct MSG_NACK*)message_buff;
                                    printf("[THREAD LST/RECV]:\n\t Sending message with MSG OD: %u failed with error: %s\n\n", 
                                        msg_nack->msg_id, 
                                        msg_nack->error == NULL ? "not specified" : msg_nack->error);
                                    break;
                                }
                                case MSG_ACK:   // Sending service message succesfull
                                {
                                    struct MSG_ACK* msg_ack = (struct MSG_ACK*)message_buff;
                                    msg_ack->next = NULL;
                                    printf("[THREAD LST/RECV]:\n\t Sending message with MSG OD: %u succeeded\n\n",msg_ack->msg_id);
                                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                                    memcpy(message_buff, ((char*)&msg_ack)+2, 4+strlen(msg_ack->service));              // Ignore MSG code to save memory
                                    (*params.ack_buffer)->Enqueue(message_buff, 4 + strlen(msg_ack->service));          // Enqueue for GCThread
                                    msg_ack->Dispose();
                                    break;
                                }

                                }
                            }

                        }

                        if (FD_ISSET(*sub->socket, &exc_set))   // Error
                        {
                            EnterCriticalSection(&disp);
                            printf("[THREAD LST/RECV]:\n\tAn error: %d occurred communicating with service on: %s:%hu\n\n",
                                WSAGetLastError(), inet_ntoa(sub->address->sin_addr), ntohs(sub->address->sin_port));
                            LeaveCriticalSection(&disp);

                            closesocket(*sub->socket);
                            *sub->socket = INVALID_SOCKET;
                            sub->exposed = false;
                            re_init_flag = true;
                            break;
                        }
                    }
                    if (re_init_flag) break;
                }

                FD_ZERO(&read_set);
                FD_ZERO(&exc_set);

                FD_SET(*sub_new->socket, &read_set);
                FD_SET(*sub_new->socket, &exc_set);

                if (re_init_flag) break;
            }

        } while (!*params.end_thr_flag);

        EnterCriticalSection(&disp);
        printf("[THREAD LST/RECV]:\n\tClosing thread..\n\n");
        --thread_counter;
        LeaveCriticalSection(&disp);
    }
#pragma endregion


int main()
{
    // Core variables
    NETWORKING_PARAMS* network_params   = NULL; // Contains all network data (ports, ip addresses and its function)
    BUFF_PARAMS buff_params;                     // Contains all buffer sizes
    BUFF_DESC* input_buffer             = NULL;  // Buffer for incoming data
    BUFF_DESC* ack_buffer               = NULL;  // Buffer for ack-ed data
    BUFF_DESC* service_buffs_in         = NULL;  // Buffers for each mirror service, client reads them, service writes them ( comes from network )
    BUFF_DESC* service_buffs_out        = NULL;  // Buffers for each mirror service, client writes them, service reads them ( goes to network )
    SERVICE_NAME* service_names         = NULL; // List of all service names

    SOCKET_DATA* listen_socks_params    = NULL; // Socket params for each listen socket  ( only 1 supported at the moment )
    SOCKET_DATA* service_sock_params    = NULL; // Socket params for each mirror service ( only 1 supported at the moment )
    SOCKET_DATA* client_sock_params     = NULL; // Socket params for each client using service
    HANDLE_LST* listen_sock_handles     = NULL; // Thread handle listen socket handle thread 
    HANDLE_LST* input_sock_handle       = NULL; // Thread handle for input socket handle thread
    HANDLE_LST* output_sock_handle      = NULL; // Thread handle for output socket handle thread
    HANDLE_LST* loader_handle           = NULL; // Thread handle for loader thread
    HANDLE_LST* GC_handle               = NULL; // Thread handle for GC thread
    HANDLE_LST* client_req_handle       = NULL; // Thread handle for client req. handle thead

    DWORD* thread_IDs                   = NULL; // Array of thread IDs
    OUT_SERVICE* subscriebers           = NULL; // Repository for mirror services (socket, addr, subscriptions)
    InitializeCriticalSection(&disp);
    bool thr_shudown_flag = false;              // Common thread shutdown flag
    unsigned long nb_mode = 1;                  // Socket block/nb mode
    char* mess      = NULL;                     // Expose message buff
    SETUP_MSG* msg  = NULL;                     // Expose message

    printf("==================================================================================================\n");

    WSAData wsa_data;
    if (WSAStartup(MAKEWORD(1, 1), &wsa_data) != 0)
    {
        printf("WSAStartup Failed\n");
        return -1;
    }

    bool escape_flag = false;    // For depth escape when shutdown is initiated
    int buffer_socks_num = 0;
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

            network_params = (NETWORKING_PARAMS*)malloc(sizeof(NETWORKING_PARAMS));
            if (network_params == NULL) break;
            network_params->Initialize();
              
            NETWORKING_PARAMS tmp_network_params;
            LoadNetworkingParams(&fptr, &tmp_network_params);   // Load network configuration parameters
            fclose(fptr);
            printf("\nDone.\n");
            printf("==================================================================================================\n");

            // Check minimal req
            bool listen_found = false, buffering_found = false,  service_found= false;
            for (int nameLoc = 0; nameLoc < tmp_network_params.tcp_params->accept_socket_units; ++nameLoc)
            {
                switch (tmp_network_params.tcp_params->accept_socket_contexts[nameLoc])
                {
                    case BUFFERING: {buffering_found = true; break; }
                    case SERVICING: {service_found   = true; break; }
                }
            }

            if (tmp_network_params.tcp_params->listen_socket_params != NULL) listen_found = true;

            if (!(listen_found && service_found && buffering_found))
            {
                printf("Minimal network requirements not found:\n");
                if (!listen_found)    printf("\tListen socket not found\n");
                if (!service_found)   printf("\tService socket not found\n");
                if (!buffering_found) printf("\tBuffering socket not found\n");
                printf("NOTE: Check port numbers usage!\n");
                printf("--------- PRELIMINARY DATA ---------\n");
                tmp_network_params.tcp_params->Format();
                printf("------------------------------------\n");
                break;
            }


            // For each LS unit
            for (int chk_loc = 0; chk_loc < tmp_network_params.tcp_params->listen_socket_units; ++chk_loc)        // For each LS unit
            {
                // Compare with other LS units
                for (int chk_ls = 0; chk_ls < tmp_network_params.tcp_params->listen_socket_units; ++chk_ls)       
                {
                    if (chk_loc != chk_ls &&
                        tmp_network_params.tcp_params->listen_socket_params[chk_loc].address_ipv4 == tmp_network_params.tcp_params->listen_socket_params[chk_ls].address_ipv4 &&
                        tmp_network_params.tcp_params->listen_socket_params[chk_loc].port == tmp_network_params.tcp_params->listen_socket_params[chk_ls].port)
                            { printf("NetworkCfg corrupted with duplicates!"); break;}
                }

                // Compare with AS units
                for (int chk_as = 0; chk_as < tmp_network_params.tcp_params->accept_socket_units; ++chk_as)       
                {   
                    if (chk_loc != chk_as &&
                        tmp_network_params.tcp_params->listen_socket_params[chk_loc].address_ipv4 == 
                        tmp_network_params.tcp_params->listen_socket_params[chk_as].address_ipv4 &&

                        tmp_network_params.tcp_params->listen_socket_params[chk_loc].port ==
                        tmp_network_params.tcp_params->listen_socket_params[chk_as].port)
                    {
                        printf("NetworkCfg corrupted with duplicates!"); break;
                    }
                }
            }

            // For ach AS unit
            for (int chk_as = 0; chk_as < tmp_network_params.tcp_params->accept_socket_units; ++chk_as)
            {
                // Compare AS unit with other AS units
                for (int chk_as_in = 0; chk_as_in < tmp_network_params.tcp_params->accept_socket_units; ++chk_as_in)
                {
                    if (chk_as != chk_as &&
                        tmp_network_params.tcp_params->listen_socket_params[chk_as_in].address_ipv4 ==
                        tmp_network_params.tcp_params->listen_socket_params[chk_as].address_ipv4 &&

                        tmp_network_params.tcp_params->listen_socket_params[chk_as_in].port ==
                        tmp_network_params.tcp_params->listen_socket_params[chk_as].port)
                    {
                        printf("NetworkCfg corrupted with duplicates!"); break;
                    }
                }
            }
            // Ignore UDP because it's not suppored at the moment
                  
            // Manually copy, realloc would mess pointers up
            if (tmp_network_params.udp_params != NULL)
            {
                network_params->udp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmp_network_params.udp_params->accept_socket_units);
                if (network_params->udp_params->accept_socket_params == NULL) break;
                memcpy(network_params->udp_params->accept_socket_params,
                    tmp_network_params.udp_params->accept_socket_params,
                    sizeof(SOCKETPARAMS) * tmp_network_params.udp_params->accept_socket_units);

                network_params->udp_params->accept_socket_contexts = (unsigned char*)malloc(tmp_network_params.udp_params->accept_socket_units);
                if (network_params->udp_params->accept_socket_contexts == NULL) break;
                memcpy(network_params->udp_params->accept_socket_contexts,
                    tmp_network_params.udp_params->accept_socket_contexts,
                    tmp_network_params.udp_params->accept_socket_units);
            }

            if (tmp_network_params.tcp_params != NULL)
            {
                network_params->tcp_params = (TCPNETWORK_PARAMS*)malloc(sizeof(TCPNETWORK_PARAMS));
                if (network_params->tcp_params == NULL) break;
                network_params->tcp_params->listen_socket_units = tmp_network_params.tcp_params->listen_socket_units;
                network_params->tcp_params->accept_socket_units = tmp_network_params.tcp_params->accept_socket_units;

                if (tmp_network_params.tcp_params->listen_socket_params != NULL)
                {
                    network_params->tcp_params->listen_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmp_network_params.tcp_params->listen_socket_units);
                    if (network_params->tcp_params->listen_socket_params == NULL) break;
                    memcpy(network_params->tcp_params->listen_socket_params,
                        tmp_network_params.tcp_params->listen_socket_params,
                        sizeof(SOCKETPARAMS) * tmp_network_params.tcp_params->listen_socket_units);
                }

                if (tmp_network_params.tcp_params->accept_socket_params != NULL)
                {
                    network_params->tcp_params->accept_socket_params = (SOCKETPARAMS*)malloc(sizeof(SOCKETPARAMS) * tmp_network_params.tcp_params->accept_socket_units);
                    if (network_params->tcp_params->accept_socket_params == NULL) break;
                    memcpy(network_params->tcp_params->accept_socket_params,
                        tmp_network_params.tcp_params->accept_socket_params,
                        tmp_network_params.tcp_params->accept_socket_units * sizeof(SOCKETPARAMS));

                    network_params->tcp_params->accept_socket_contexts = (unsigned char*)malloc(tmp_network_params.tcp_params->accept_socket_units);
                    if (network_params->tcp_params->accept_socket_contexts == NULL) break;
                    memcpy(network_params->tcp_params->accept_socket_contexts,
                        tmp_network_params.tcp_params->accept_socket_contexts,
                        tmp_network_params.tcp_params->accept_socket_units);
                }

            }
            tmp_network_params.Dispose();

            //Load buffers configuration
            bool success_flag = false;
            printf("Loading memory data..\n\n");
            if (getcwd(cwd, sizeof(cwd)) == NULL) 
            {
                printf("Error loading path\n");
                return 1;
            }

            strcat_s(cwd, "\\MemCfg.txt");
            cwd[sizeof(cwd) - 1] = '\0';  //Append config file name

            fptr = NULL;
            fopen_s(&fptr, cwd, "rb");
            if (!fptr)
            {
                printf("Opening MemCfg at %s failed, closing..\n", cwd);
                break;
            }
            buff_params = LoadBufferParams(&fptr, &success_flag); // Load buffering parameters (buffer sizes)
            if (!buff_params.Validate()) break;
            fclose(fptr);
            printf("\nDone.\n");
            printf("==================================================================================================\n");

            // Initialize input buffer
            BUFF_DESC* tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
            tmp_buff->Initialize();
            tmp_buff->context = INBUF;                                     // Allocate for single input buff
            tmp_buff->capacity = buff_params.inqueue;
            tmp_buff->memory = (char*)(malloc(tmp_buff->capacity));
            tmp_buff->name = (char*)(malloc(MAX_BUFF_NAME + 1));
            if (tmp_buff->memory == NULL || tmp_buff->name == NULL) break;
            tmp_buff->Prepare();
            memcpy(tmp_buff->name,"INPUT BUFF\0", strlen("INPUT BUFF\0") + 1);
            if (input_buffer == NULL) input_buffer = tmp_buff;
            else input_buffer->Insert(tmp_buff, &input_buffer);

            // Initialize ack buffer
            tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
            tmp_buff->Initialize();
            tmp_buff->context = ACKBUF;
            tmp_buff->capacity = buff_params.ackqueue;
            tmp_buff->memory = (char*)(malloc(tmp_buff->capacity));
            tmp_buff->name = (char*)(malloc(MAX_BUFF_NAME + 1));
            if (tmp_buff->memory == NULL || tmp_buff->name == NULL) break;
            tmp_buff->Prepare();
            memcpy(tmp_buff->name, "ACK BUFF\0", strlen("ACK BUFF\0") + 1);
            if (tmp_buff == NULL) ack_buffer = tmp_buff;
            else ack_buffer->Insert(tmp_buff, &ack_buffer);

            for (int acc_bufloc = 0; acc_bufloc < network_params->tcp_params->accept_socket_units; ++acc_bufloc)
            {
                if (network_params->tcp_params->accept_socket_contexts[acc_bufloc] == BUFFERING) ++buffer_socks_num;
            }

            // Create input buffer for each service
            for (int acc_bufloc = 0; acc_bufloc < buffer_socks_num; ++acc_bufloc)
            {

                tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                tmp_buff->Initialize();

                if ((tmp_buff->memory = (char*)malloc(buff_params.service_in_queue)) == NULL)
                {
                    escape_flag = true;  break;
                }
                else
                {
                    tmp_buff->context = INBUF_SRV;
                    tmp_buff->capacity = buff_params.service_in_queue;
                    tmp_buff->Prepare();

                    if (service_buffs_in == NULL) service_buffs_in = tmp_buff;
                    else service_buffs_in->Insert(tmp_buff, &service_buffs_in);
                }
            }
            if (escape_flag) break;

            // Create output buffer for each service
            for (int acc_bufloc = 0; acc_bufloc < buffer_socks_num; ++acc_bufloc)
            {

                tmp_buff = (BUFF_DESC*)malloc(sizeof(BUFF_DESC));
                tmp_buff->Initialize();

                if ((tmp_buff->memory = (char*)malloc(buff_params.service_out_queue)) == NULL)
                {
                    escape_flag = true;  break;
                }
                else
                {
                    tmp_buff->context = OUTBUF_SRV;
                    tmp_buff->capacity = buff_params.service_out_queue;
                    tmp_buff->Prepare();

                    if (service_buffs_out == NULL) service_buffs_out = tmp_buff;
                    else service_buffs_out->Insert(tmp_buff, &service_buffs_out);
                }
            }
            if (escape_flag) break;

            // Name initial services (configured via NetworkCfg)
            char* tmp_buff_c = (char*)(malloc(MAX_SERVICE_NAME_SIZE+1));
            if (tmp_buff == NULL) break;
            printf("\n\nName initial services:\n\t[TOTAL : %hu]\n\t[MAX NAME LENGTH : %d]\n\n", buffer_socks_num, MAX_SERVICE_NAME_SIZE);
            
            bool trigger_renter = false;
            BUFF_DESC* service_in_it = service_buffs_in;
            BUFF_DESC* service_out_it = service_buffs_out;
            SERVICE_NAME* check_it;
            for (int service_bufloc = 0; service_bufloc < buffer_socks_num; ++service_bufloc)
            {
                memset(tmp_buff_c, 0, MAX_SERVICE_NAME_SIZE + 1);
                printf("Service %d: ", service_bufloc);
                gets_s(tmp_buff_c, MAX_SERVICE_NAME_SIZE);

                trigger_renter = false;
                check_it = service_names;
                for (int used_names = 0; used_names < service_bufloc; used_names++)    // Must be unique
                {
                    if (!strcmp(tmp_buff_c, check_it->name))
                    {
                        printf("\tERROR: Name already used!\n");
                        --service_bufloc;
                        trigger_renter = true;
                        break;
                    }
                    else check_it = check_it->next;
                }
                if (trigger_renter) continue;

                if (service_in_it == NULL || service_out_it == NULL) break;

                int len = strlen(tmp_buff_c) + 1;
                SERVICE_NAME* new_name = (SERVICE_NAME*)(malloc(sizeof(SERVICE_NAME)));
                new_name->Initialize();
                new_name->next = NULL;
                new_name->name = (char*)(malloc(len));
                memset(new_name->name, 0, len);
                new_name->length = len;
                memcpy(new_name->name, tmp_buff_c, len);
                if (service_names == NULL)  service_names = new_name;
                else
                    service_names->Insert(new_name, &service_names);
                service_in_it->name = (char*)(malloc(strlen(tmp_buff_c)+strlen("|SEND BUFF\0") + 1));
                service_out_it->name = (char*)(malloc(strlen(tmp_buff_c) + strlen("|SEND BUFF\0") + 1));
                sprintf(service_out_it->name, "%s|SEND BUFF\0", tmp_buff_c); // Connect buffers & its services
                sprintf(service_in_it->name, "%s|RECV BUFF\0", tmp_buff_c);

                service_in_it = service_in_it->next;
                service_out_it = service_out_it->next;
            }
            free(tmp_buff_c);

            // Print loaded params
            printf("==================================================================================================\n");
            printf("-- Network Stats --\n");
            network_params->tcp_params->Format();
            printf("\n");
            printf("-- Buffering Stats --\n");
            printf("\tBuffer Name: %s\n", ack_buffer->name);
            printf("\tBuffer Name: %s\n", input_buffer->name);
            
            service_in_it = service_buffs_in;
            service_out_it = service_buffs_out;
            for (int service_bufloc = 0; service_bufloc < buffer_socks_num; ++service_bufloc)
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
            for (int service_bufloc = 0; service_bufloc < buffer_socks_num; ++service_bufloc)
            {
                printf("\tService Name: %s\n", service_it->name);
                service_it = service_it->next;
            }         

            printf("==================================================================================================\n");
            //
        }

        printf("Starting thread initialization..\n");
        // Total threads = listen_socket_units + (max_services_hosted *(2=1 set on host one on mirror))*(3=loader+ client_in+client_out)+(2=single_ack_thread+single output handle) 
        thread_IDs = (DWORD*)malloc(sizeof(DWORD) * (network_params->tcp_params->listen_socket_units + (MAX_SERVICES_HOSTED*2)*3+2));  
        // Create threads, assign buffers and expose sockets
        char ip_formatted[13];
        int validClientsSockets = 0;

        //As mailbox for connect fetching
        for (int loc = 0; loc < MAX_SERVICES_HOSTED * 2; ++loc)
        {
            SOCKET_DATA* new_data = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
            new_data->Initialize();
            new_data->Insert(new_data, &client_sock_params);
        }

        SERVICE_NAME* service_names_it = service_names;
        char service_name[MAX_BUFF_NAME + 1];
        bool* accept_triggers = (bool*)(malloc(sizeof(bool) * MAX_SERVICES_HOSTED * 2));   
        for (int loc = 0; loc < MAX_SERVICES_HOSTED * 2; ++loc) accept_triggers[loc] = false;
        for (int loc = 0; loc < network_params->tcp_params->accept_socket_units; ++loc)  
        {   // For each buffering socket
            if (network_params->tcp_params->accept_socket_contexts[loc] == 1)        
            {
                // Create loader thread
                HANDLE_LST* load_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (load_handle == NULL) { escape_flag = true; break; }

                load_handle->Initialize();
                load_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                thread_IDs[thread_counter] = thread_counter;

                SERVICE_LOADER_THR_PARAMS* service_loader_thr_param = (SERVICE_LOADER_THR_PARAMS*)malloc(sizeof(SERVICE_LOADER_THR_PARAMS));
                service_loader_thr_param->Initialize();
                memcpy(service_loader_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                service_loader_thr_param->in_buffer = input_buffer;             // Reds from common input buffer            

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Writes into service send buffer (Queue Service Point of View) 
                service_loader_thr_param->out_buffer = service_buffs_out->FindByName(service_name, service_buffs_out);

                service_loader_thr_param->end_thr_flag = &thr_shudown_flag;

                *load_handle->handle = CreateThread(NULL, 0, &ServiceLoaderThr, service_loader_thr_param, 0, thread_IDs + thread_counter);
                listen_sock_handles->Insert(load_handle, &loader_handle);
                ++thread_counter;

                // Create GC thread
                HANDLE_LST* GC_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (GC_handle == NULL) { escape_flag = true; break; }

                GC_handle->Initialize();
                GC_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                thread_IDs[thread_counter] = thread_counter;

                SERVICE_GC_THR_PARAMS* GC_thr_param = (SERVICE_GC_THR_PARAMS*)malloc(sizeof(SERVICE_GC_THR_PARAMS));
                GC_thr_param->Initialize();
                memcpy(GC_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                GC_thr_param->in_buffer = ack_buffer;               // Reads from common ack buffer

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);  // Deletes from send buffer
                GC_thr_param->out_buffer = service_buffs_out->FindByName(service_name, service_buffs_out);

                GC_thr_param->end_thr_flag = &thr_shudown_flag;
                *GC_handle->handle = CreateThread(NULL, 0, &ServiceGCThr, GC_thr_param, 0, thread_IDs + thread_counter);
                GC_handle->Insert(GC_handle, &GC_handle);
                ++thread_counter;

                // Create client communication thread
                SOCKET_DATA* client_socket = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
                if (client_socket == NULL) break;
                client_socket->Initialize();

                HANDLE_LST* client_handle = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
                if (client_handle == NULL) { escape_flag = true; break; }

                client_handle->Initialize();
                client_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
                thread_IDs[thread_counter] = thread_counter;

                CLIENT_THR_PARAMS* client_thr_param = (CLIENT_THR_PARAMS*)malloc(sizeof(CLIENT_THR_PARAMS));
                client_thr_param->Initialize();
                memcpy(client_thr_param->service_name, service_names_it->name, strlen(service_names_it->name));

                memset(service_name, 0, MAX_BUFF_NAME + 1);
                sprintf(service_name, "%s|RECV BUFF", service_names_it->name);      // Reads what comes from sockets and stores it
                client_thr_param->in_buffer = service_buffs_in->FindByName(service_name, service_buffs_in);

                memset(service_name, 0, MAX_BUFF_NAME + 1);                         // Reads what commes from mirroring and sends it trough socket
                sprintf(service_name, "%s|SEND BUFF", service_names_it->name);      
                client_thr_param->out_buffer = service_buffs_out->FindByName(service_name, service_buffs_out);
                client_thr_param->accept_trigger = &(accept_triggers[loc]);         // Needed for fetch awakening (same index as service name)

                client_thr_param->end_thr_flag = &thr_shudown_flag;
                client_thr_param->socket_data_accepted = client_sock_params->At(loc, client_sock_params);
                *client_handle->handle = CreateThread(NULL, 0, &ClientReqHandleThr, client_thr_param, 0, thread_IDs + thread_counter);
                client_req_handle->Insert(client_handle, &client_req_handle);
                client_sock_params->Insert(client_socket, &client_sock_params);
                ++thread_counter;

                service_names_it=service_names_it->next;
            }   
        }

        // Sleep till initial threads created
        do { Sleep(1000); } while (thread_counter < network_params->tcp_params->accept_socket_units *  + 2);

        //Try Expose before accepting on listen socket
        SETUP_MSG* msg = (SETUP_MSG*)malloc(sizeof(SETUP_MSG)); // Would use for listen socket too
        GenerateDeltaServicesMsg(msg, service_names);

        char* mess = (char*)malloc(6 + msg->content_size + 1);
        memset(mess, 0, 6 + msg->content_size + 1);
        *((unsigned short*)mess) = msg->msg_code;
        *((unsigned*)(mess + 2)) = msg->content_size;
        memcpy(mess + 6, msg->content, msg->content_size);

        // Expose services
        int target_loc = -1;
        for (int loc = 0; loc < network_params->tcp_params->accept_socket_units; ++loc)
        {
            if (network_params->tcp_params->accept_socket_contexts[loc] == 3)
            {
                target_loc = loc;

                EXPOSE_PARAMS exp_params;
                exp_params.target_params = &(network_params->tcp_params->accept_socket_params[loc]);
                exp_params.service_names = service_names;
                exp_params.subscriebers = &subscriebers;
                exp_params.nb_mode = &nb_mode;
                exp_params.expose_mess_buff = mess;
                exp_params.expose_mess = msg;
                ExposeServices(exp_params);
            }
        }

        //Crate output handle
        OUTPUT_THR_PARAMS* output_thr_params = (OUTPUT_THR_PARAMS*)malloc(sizeof(OUTPUT_THR_PARAMS));
        output_thr_params->Initialize();
        output_thr_params->end_thr_flag = &thr_shudown_flag;
        output_thr_params->out_buffers = service_buffs_out;
        output_thr_params->dst = subscriebers;
        output_thr_params->service_names = service_names;

        HANDLE_LST* output_thr_handle = (HANDLE_LST*)malloc(sizeof(HANDLE));
        output_thr_handle->handle = (HANDLE*)malloc(sizeof(HANDLE));
        *output_thr_handle->handle = CreateThread(NULL, 0, &OutputHandleThr, output_thr_params, 0, thread_IDs + thread_counter); 
        output_thr_handle->Insert(output_thr_handle, &output_sock_handle);
        ++thread_counter;

        //Create listening sockets
        int valid_lst_socks = 0;

        //For service to service communication (inter-mirroring communication)
        SOCKET_DATA* listen_socket_service = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
        if (listen_socket_service == NULL) break;
        listen_socket_service->Initialize();

        listen_socket_service->socket = (SOCKET*)malloc(sizeof(SOCKET));
        if (listen_socket_service->socket == NULL) break;
        *listen_socket_service->socket = INVALID_SOCKET;

        if ((*(listen_socket_service->socket) = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            EnterCriticalSection(&disp);
            printf("Ann error occurred creating listening sockets\n");
            LeaveCriticalSection(&disp);
        }
        else ++valid_lst_socks; 

        listen_socket_service->address = (sockaddr_in*)(malloc(sizeof(sockaddr_in)));

        listen_socket_service->address->sin_family = AF_INET;
        network_params->tcp_params->listen_socket_params[0].FormatIP(ip_formatted);
        listen_socket_service->address->sin_addr.s_addr = inet_addr(ip_formatted);
        listen_socket_service->address->sin_port = htons(network_params->tcp_params->listen_socket_params[0].port);
        listen_socks_params->Insert(listen_socket_service, &listen_socks_params);

        HANDLE_LST* handle_service_lst = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
        if (handle_service_lst == NULL)
            { escape_flag= true; break;}

        handle_service_lst->Initialize();
        handle_service_lst->handle = (HANDLE*)malloc(sizeof(HANDLE));
        thread_IDs[thread_counter] = thread_counter;

        LISTENING_THR_PARAMS listenSocketThr_params;
        listenSocketThr_params.Initialize();
        listenSocketThr_params.listen_socket_params = listen_socks_params;
        listenSocketThr_params.subscriebers         = &subscriebers;
        listenSocketThr_params.service_names        = &service_names;
        listenSocketThr_params.end_thr_flag         = &thr_shudown_flag;
        listenSocketThr_params.buff_params          = &buff_params;
        listenSocketThr_params.service_buffers_in   = &service_buffs_in;
        listenSocketThr_params.service_buffers_out  = &service_buffs_out;
        listenSocketThr_params.input_buffer         = &input_buffer;
        listenSocketThr_params.ack_buffer           = &ack_buffer;
        listenSocketThr_params.client_req_handle    = &client_req_handle;
        listenSocketThr_params.loader_handle        = &loader_handle;
        listenSocketThr_params.GC_handle            = &GC_handle;
        listenSocketThr_params.threadIDs            = thread_IDs;
        listenSocketThr_params.client_socket_params = &client_sock_params;    
        listenSocketThr_params.expose_mess          = msg;
        listenSocketThr_params.expose_mess_buff     = mess;
        listenSocketThr_params.reinit_sock_data     = &(network_params->tcp_params->accept_socket_params[target_loc]);
        listenSocketThr_params.accept_triggers      = accept_triggers; 

        *handle_service_lst->handle = CreateThread(NULL, 0, &ServiceCommunicationThr, &listenSocketThr_params, 0, thread_IDs+thread_counter);
        listen_sock_handles->Insert(handle_service_lst, &listen_sock_handles);
        ++thread_counter;

        //For services offer & connect to client
        SOCKET_DATA* listen_sock_client = (SOCKET_DATA*)malloc(sizeof(SOCKET_DATA));
        if (listen_sock_client == NULL) break;
        listen_sock_client->Initialize();

        listen_sock_client->socket = (SOCKET*)malloc(sizeof(SOCKET));
        if (listen_sock_client->socket == NULL) break;
        *listen_sock_client->socket = INVALID_SOCKET;

        if ((*(listen_sock_client->socket) = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            EnterCriticalSection(&disp);
            printf("Ann error occurred creating listening sockets\n");
            LeaveCriticalSection(&disp);
        }
        else ++valid_lst_socks;

        listen_sock_client->address = (sockaddr_in*)(malloc(sizeof(sockaddr_in)));

        listen_sock_client->address->sin_family = AF_INET;
        network_params->tcp_params->listen_socket_params[1].FormatIP(ip_formatted);
        listen_sock_client->address->sin_addr.s_addr = inet_addr(ip_formatted);
        listen_sock_client->address->sin_port = htons(network_params->tcp_params->listen_socket_params[1].port);
        listen_socks_params->Insert(listen_sock_client, &listen_socks_params);

        HANDLE_LST* handle_client_lst = (HANDLE_LST*)(malloc(sizeof(HANDLE_LST)));
        if (handle_client_lst == NULL)
        {
            escape_flag = true; break;
        }

        handle_client_lst->Initialize();
        handle_client_lst->handle = (HANDLE*)malloc(sizeof(HANDLE));
        thread_IDs[thread_counter] = thread_counter;

        CLIENT_REGISTER_THR_PARAMS client_register_params;
        client_register_params.Initialize();

        client_register_params.accept_triggers = accept_triggers;               // Needed for fetch invoke
        client_register_params.end_thr_flag = &thr_shudown_flag;
        client_register_params.register_socket_params = listen_sock_client;
        client_register_params.service_names = service_names;
        client_register_params.client_socket_params = client_sock_params;

        
        *handle_client_lst->handle = CreateThread(NULL, 0, &ClientRegisterThr, &client_register_params, 0, thread_IDs + thread_counter);
        ++thread_counter;
   
        listen_sock_handles->Insert(handle_client_lst, &listen_sock_handles);
        ++thread_counter;
        
        Sleep(2000);//Wait for threads to initialize
        EnterCriticalSection(&disp);
        printf("Thread initialization completed.\n");
        LeaveCriticalSection(&disp);

        // Check listen socket minimal configuration
        if (valid_lst_socks <2 || escape_flag) break;

        valid_lst_socks = 0;
        for (int loc = 0; loc < network_params->tcp_params->listen_socket_units; ++loc)
            valid_lst_socks += listen_socks_params->initialized;
        
        if (valid_lst_socks <= 0)
        { 
            EnterCriticalSection(&disp);
            printf("Ann error occurred initializing listening sockets\n"); 
            LeaveCriticalSection(&disp);
            break; 
        }
        else 
        { 
            EnterCriticalSection(&disp);
            printf("%d/%d Listening socket succesfully initialized\n", valid_lst_socks, network_params->tcp_params->listen_socket_units);
            LeaveCriticalSection(&disp);
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
    
    // Dispose allocated resources
    WSACleanup();
    if (subscriebers            != NULL) { subscriebers->Dispose();              free(subscriebers);           subscriebers          = NULL;}
    if (network_params           != NULL) { network_params->Dispose();           free(network_params);         network_params        = NULL;}
    if (input_buffer            != NULL) { input_buffer->Dispose();              free(input_buffer);           input_buffer          = NULL;}
    if (ack_buffer              != NULL) { ack_buffer->Dispose();                free(ack_buffer);             ack_buffer            = NULL;}
    if (service_buffs_in        != NULL) { service_buffs_in->Dispose();          free(service_buffs_in);       service_buffs_in      = NULL;}
    if (service_buffs_out       != NULL) { service_buffs_out->Dispose();         free(service_buffs_out);      service_buffs_out     = NULL;}
    if (service_names           != NULL) { service_names->Dispose();             free(service_names);          service_names         = NULL;}
    if (listen_socks_params     != NULL) { listen_socks_params->Dispose();       free(listen_socks_params);    listen_socks_params   = NULL;}
    if (service_sock_params     != NULL) { service_sock_params->Dispose();       free(service_sock_params);    service_sock_params   = NULL;}
    if (client_sock_params      != NULL) { client_sock_params->Dispose();        free(client_sock_params);     client_sock_params    = NULL;}
    if (subscriebers            != NULL) { subscriebers->Dispose();              free(subscriebers);           subscriebers          = NULL;}
    if (service_buffs_in        != NULL) { service_buffs_in->Dispose();          free(service_buffs_in);       service_buffs_in      = NULL;}
    if (listen_socks_params     != NULL) { listen_socks_params->Dispose();       free(listen_socks_params);    listen_socks_params   = NULL;}
    if (ack_buffer              != NULL) { ack_buffer->Dispose();                free(ack_buffer);             ack_buffer            = NULL;}
    if (listen_sock_handles     != NULL) { listen_sock_handles->Dispose();       free(listen_sock_handles);    listen_sock_handles   = NULL;}
    if (input_sock_handle       != NULL) { input_sock_handle->Dispose();         free(input_sock_handle);      input_sock_handle     = NULL;}
    if (output_sock_handle      != NULL) { output_sock_handle->Dispose();        free(output_sock_handle);     output_sock_handle    = NULL;}
    if (loader_handle           != NULL) { loader_handle->Dispose();             free(loader_handle);          loader_handle         = NULL;}
    if (GC_handle               != NULL) { GC_handle->Dispose();                 free(GC_handle);              GC_handle             = NULL;}
    if (client_req_handle       != NULL) { client_req_handle->Dispose();         free(client_req_handle);      client_req_handle     = NULL;}
    if (thread_IDs              != NULL) {                                       free(thread_IDs);             thread_IDs            = NULL;}
    if (mess != NULL)                    {                                       free(mess);                   mess                  = NULL;}
    if (msg != NULL)                     {                                       free(msg);                    msg                   = NULL;}
    DeleteCriticalSection(&disp);  

    printf("Press any key to exit..\n");
    getchar();
    return 0;
}
