#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "direct.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996) 

#pragma region Constants
    #define MAX_RECORD_LENGTH 255
    #define MAX_MESSAGE_SIZE 255 
#pragma endregion

// Element of service names list
typedef struct SERVICE_NAME
{
    char* name;			// Null termianted string of service name
    unsigned length;	// Length of service name
    SERVICE_NAME* next;	// Pointer to next element of list

    // Initialize all fields (remove garbage values)
    void Initialize()
    {
        name = NULL;
        next = NULL;
        length = 0;
    }

    // Retrieves element from list at specific index
    // int loc						- target index
    // SERVICE_NAME* service_names	- list head
    // Returns pointer to target element, NULL if not found
    SERVICE_NAME* At(int loc, SERVICE_NAME* service_names)
    {
        SERVICE_NAME* it = service_names;
        while (loc > 0 && it != NULL)
            it = it->next;

        return it;
    }

    // Formats list of service names into string, dividing them iwth '|'
    // char* buff					- output string buffer
    // int buff_len					- output buffer length
    // int services_num				- number of service names sto format
    // SERVICE_NAME* head			- list head
    // SERVICE_NAME* except_head	- list of vallues wanna be ignored, NULL if parse all
    void Format(char* buff, int buff_len, int services_num, SERVICE_NAME* head, SERVICE_NAME* except_head)
    {
        memset(buff, 0, buff_len);
        SERVICE_NAME* names_it = head;
        if (names_it == NULL) return;

        SERVICE_NAME* except_it;

        char* buff_it = buff;

        bool parse_all_regime = false;
        if (services_num <= -1) parse_all_regime = true;

        do
        {
            except_it = except_head;
            if (except_it != NULL)
                do
                {
                    if (!strcmp(names_it->name, except_it->name)) break;

                } while ((except_it = except_it->next) != NULL);

                if (except_it == NULL)
                {
                    memcpy(buff_it, names_it->name, strlen(names_it->name));
                    buff_it += strlen(names_it->name);
                    *buff_it = '|';
                    ++buff_it;

                    if (!parse_all_regime && (--services_num) <= 0) return;
                }

        } while ((names_it = names_it->next) != NULL);
    }

    // Prints all service names
    // SERVICE_NAME* head - list head
    void PrintOut(SERVICE_NAME* head)
    {
        SERVICE_NAME* it = head;
        while (it != NULL)
        {
            printf("\t%s\n", it->name);
            it = it->next;
        }
    }

    // Safe dispose of all list resources (ignore ones passed by reference)
    bool Dispose()
    {
        if (next == NULL) return true;
        else
        {
            next->Dispose();
            free(next);
            next = NULL;
            if (name != NULL)
            {
                free(name);
                name = NULL;
            }
        }
        return true;
    }

    // Inserts element at the end of the list
    // SERVICE_NAME* new_el - new element
    // SERVICE_NAME** head	- pointer to list head
    void Insert(SERVICE_NAME* new_el, SERVICE_NAME** head)
    {
        if (*head == NULL)
        {
            *head = new_el; return;
        }
        SERVICE_NAME* free_loc = *head;
        while (free_loc->next != NULL) free_loc = free_loc->next;

        free_loc->next = new_el;
    }

    // SERVICE_NAME* head - list head
    // Returns list length
    unsigned Count(SERVICE_NAME* head)
    {
        unsigned num = 0;
        SERVICE_NAME* it = head;
        while (it != NULL)
        {
            ++num;
            it = it->next;
        }
        return num;
    }

    // Check if list contains target element by service name 
    // char* name			- to check element
    // SERVICE_NAME* head	- list head
    // Returns true if found, false if not
    bool Contains(char* name, SERVICE_NAME* head)
    {
        if (name == NULL) return false;

        SERVICE_NAME* it = head;
        while (it != NULL)
        {
            if (!strcmp(it->name, name)) return true;
            it = it->next;
        }
        return false;
    }

    // Check if list contains target element by service name 
    // char* name			- to check element
    // SERVICE_NAME* head	- list head
    // Returns pointer to target SERVICE_NAME, NULL if not found
    SERVICE_NAME* Find(char* name, SERVICE_NAME* head)
    {
        if (name == NULL) return NULL;

        SERVICE_NAME* it = head;
        while (it != NULL)
        {
            if (!strcmp(it->name, name)) return it;
            it = it->next;
        }
        return NULL;
    }

    // char* name - target name
    // SERVICE_NAME* head - list head
    // Returns index of target element, -1 if not found
    int IndexOf(char* name, SERVICE_NAME* head)
    {
        SERVICE_NAME* it = head;
        int loc = 0;
        while (it != NULL)
        {
            if (!strcmp(it->name, name)) return loc;
            it = it->next;
            ++loc;
        }
        return -1;
    }



    // Removes element from list
    // SERVICE_NAME* to_del - to delete element
    // SERVICE_NAME** head  - pointer to list head
    void Remove(SERVICE_NAME* to_del, SERVICE_NAME** head)
    {
        if (*head == to_del)*head = to_del->next;
        else
        {
            SERVICE_NAME* it_prev = *head;
            SERVICE_NAME* it = (*head)->next;
            while (it != NULL)
            {
                if (it == to_del)
                {
                    it_prev->next = it->next; break;
                }

                it_prev = it;
                it = it->next;
            }
        }
        free(name);
        name = NULL;
        next = NULL;
    }

} SERVICE_NAME;

#pragma region Function_Decl
    //Reads ServiceCfg.txt in order to retrive IPV4 address and port of target service
    //FILE* file        - Pointer to ServiceCfg.txt file descriptor
    //sockaddr_in* addr - Pointer to sockaddr_in structure to be filled
    bool ParseNetworkConfig(FILE* file, sockaddr_in* addr);

    //Thread recieving service messages in asynchronous manner
    DWORD WINAPI RecvThr(LPVOID lp_param);

    //Replaces \r\n with \0 
    void TrimEndNL(char* str, unsigned size);


#pragma endregion

#pragma region Function_Impl
    bool ParseNetworkConfig(FILE* fptr, sockaddr_in* addr)
    {
        char buff[MAX_RECORD_LENGTH];
        memset(buff, 0, MAX_RECORD_LENGTH);
        if(!fgets(buff, MAX_RECORD_LENGTH, fptr)) return false;

        char* segment = strtok(buff, ":");
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = inet_addr(segment);

        if (addr->sin_addr.s_addr == INADDR_NONE)
            {printf("[CLIENT]:]\nInvalid service address\n\n"); return false;}

        segment = strtok(NULL, ":");

        addr->sin_port = atoi(segment);
        if(addr->sin_port<49152 || addr->sin_port>65535)
            {printf("[CLIENT]:]\nInvalid service port\n\n"); return false;}

        addr->sin_port = htons(addr->sin_port);
        return true;
    }

    DWORD WINAPI RecvThr(LPVOID lp_param)
    {
        do
        {

        }while (true);
    }

    void TrimEndNL(char* str, unsigned size)
    {
        for (unsigned loc=0; loc < size; ++loc)
        {
            if (str[loc] == '\0') return;
            else if (str[loc] == '\r' || str[loc] == '\n') { str[loc] = '\0'; return; }
        }
    }

#pragma endregion

int main()
{
    WSAData wsa_data;
    if (WSAStartup(MAKEWORD(1, 1), &wsa_data) != 0)
    {
        printf("WSAStartup Failed\n");
        return -1;
    }

    SERVICE_NAME* service_names=NULL;
    switch (true)
    {
        case true: 
        {
            // Read Network setup
            printf("==================================================================================================\n");
            printf("Loading network data..\n");
            char cwd[FILENAME_MAX];
            if (getcwd(cwd, sizeof(cwd)) == NULL)
            {
                printf("Error loading path\n");
                return 1;
            }

            strcat_s(cwd, "\\ServiceCfg.txt");
            cwd[sizeof(cwd) - 1] = '\0';  //Append config file name

            FILE* fptr = NULL;
            fopen_s(&fptr, cwd, "rb");
            if (!fptr)
            {
                printf("Opening ServiceCfg at %s failed, closing..\n", cwd);
                break;
            }

            sockaddr_in service_addr;
            if (!ParseNetworkConfig(fptr, &service_addr)) break;
            fclose(fptr);
            printf("\nDone.\n");
            printf("==================================================================================================\n");
            printf("Contacting server...");

            bool re_init;
            char message_buff[MAX_MESSAGE_SIZE];
            do
            {
                re_init = false;
                SOCKET service_sock;
                if ((service_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
                {
                    printf("Creating socket failed, press \'e\' to exit, other key to retry.. \n");

                    gets_s(message_buff, 2);
                    if (message_buff[0] == 'e') break;
                    else
                    {
                        re_init = true; continue;
                    }
                }


                if (connect(service_sock, (sockaddr*)&service_addr, sizeof(service_addr)) != 0)
                {
                    printf("\n\nConnecting to service on %s:%hu failed, press \'e\' to exit, other key to retry.. \n",
                        inet_ntoa(service_addr.sin_addr), ntohs(service_addr.sin_port));

                    gets_s(message_buff, 2);
                    if(message_buff[0]=='e') break;
                    else
                        {re_init = true; continue;}
                }
                else
                    printf("\n\nConnected to %s:%hu\n",
                        inet_ntoa(service_addr.sin_addr), ntohs(service_addr.sin_port));
                printf("==================================================================================================\n");

                char* segment;
                memset(message_buff, 0, MAX_MESSAGE_SIZE);
                int bytes_rec = recv(service_sock, message_buff, MAX_MESSAGE_SIZE, 0);  //Recv. all service names

                printf("-------- AVAILABLE SERVICES --------\n");
                segment = strtok(message_buff, "|");
                int tmp_size;
                while (segment != NULL)
                {
                    printf("Service Name:\t%s\n", segment);
                    SERVICE_NAME* to_add = (SERVICE_NAME*)(malloc(sizeof(SERVICE_NAME)));
                    to_add->Initialize();
                    tmp_size = strlen(segment) + 1;
                    to_add->name = (char*)(malloc(tmp_size));
                    memset(to_add->name, 0, tmp_size);
                    memcpy(to_add->name, segment, tmp_size-1);
                    to_add->Insert(to_add, &service_names);
                    segment = strtok(NULL, "|");
                }
                printf("\n");          
                
                do
                {
                    do
                    {
                        printf("\n[CLIENT]: Enter service name to connect: ");
                        memset(message_buff, 0, MAX_MESSAGE_SIZE);
                        gets_s(message_buff, MAX_MESSAGE_SIZE - 1);
                        TrimEndNL(message_buff, MAX_MESSAGE_SIZE - 1);
                    } while (!service_names->Contains(message_buff, service_names));

                    if (send(service_sock, message_buff, strlen(message_buff), 0) == SOCKET_ERROR)
                    {
                        printf("[CLIENT]:\nService connect failed, press \'e\' to exit, other key to retry.. \n");

                        gets_s(message_buff, 2);
                        if (message_buff[0] == 'e') break;
                        else
                        {
                            re_init = true; continue;
                        }
                    }

                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    bytes_rec = recv(service_sock, message_buff, MAX_MESSAGE_SIZE, 0);
                    segment = strtok(message_buff, ":");
                    if (!strcmp(segment, "NACK\0"))
                    {
                        segment = strtok(NULL, ":");
                        printf("[CLIENT]:\nConnect failed with error: %s, press \'e\' to exit, other key to retry.. \n", segment);
                        gets_s(message_buff, 2);
                        if (message_buff[0] == 'e') { re_init = false; break; }                      
                    }
                } while (strcmp(segment, "ACK\0"));
                printf("Connected\n");
                service_names->Dispose();
                printf("==================================================================================================\n");
                do
                {
                    memset(message_buff, 0, MAX_MESSAGE_SIZE);
                    gets_s(message_buff, MAX_MESSAGE_SIZE-1);
                    if (send(service_sock, message_buff, strlen(message_buff), 0) == SOCKET_ERROR)
                    {
                        printf("[CLIENT]:\nSending message failed, press \'e\' to exit, other key to retry.. \n");

                        gets_s(message_buff, 2);
                        if (message_buff[0] == 'e') { re_init = false; break; }
                        else
                         {re_init = true; break; }
                    }

                    if (re_init)break;
                } while (strcmp(message_buff, "e\0") || re_init);       
            } while (re_init);

            break;
        }
    }

    if (service_names != NULL) service_names->Dispose();
    
    WSACleanup();
	printf("Press any key to exit..");
	getchar();
	return 0;
}


