#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"
#include "Messages.h"

#ifndef MAX_SERVICES_HOSTED 
#define MAX_SERVICES_HOSTED 10
#endif

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
			if(except_it!=NULL)				
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

		}while ((names_it = names_it->next) != NULL);
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
			{*head = new_el; return;}
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
					{it_prev->next = it->next; break;}

				it_prev = it;
				it = it->next;
			}
		}
		free(name);
		name = NULL;
		next = NULL;	
	}

} SERVICE_NAME;

// Element of socket data list describing network parameters
typedef struct SOCKET_DATA
{
	SOCKET* socket;			// Pointer to socket
	sockaddr_in* address;	// Pointer to sockaddr_in address structure
	SOCKET_DATA* next;		// Pointer to next element of the list
	bool initialized;		// Initialized flag

	// Initialize all fields (remove garbage values)
	void Initialize()
	{
		socket=NULL;
		address=NULL;
		next=NULL;
		initialized = false;
	}

	// Safe dispose of allocated memory (for list)
	bool Dispose()
	{
		if (next == NULL) return true;
		else
		{
			next->Dispose();
			free(next);
			next = NULL;
			if (socket != NULL)
			{
				closesocket(*socket);
				*socket = INVALID_SOCKET;
				free(socket);
				socket = NULL;
			}

			if (address != NULL)
			{
				free(address);
				address = NULL;
			}
		}
		return true;
	}

	// Insert new element at the end of the list
	// SOCKET_DATA* new_el - to add element
	// SOCKET_DATA** head  - pointer to list head
	void Insert(SOCKET_DATA* new_el, SOCKET_DATA** head)
	{
		if (*head == NULL)
			{*head = new_el; return;}

		SOCKET_DATA* free_loc = *head;
		while (free_loc->next != NULL) free_loc = free_loc->next;

		free_loc->next = new_el;
	}

	// Safe dispose of allocated memory (for single element)
	void DisposeSelf()	
	{
		next = NULL;
		if (socket != NULL)
		{
			closesocket(*socket);
			free(socket);
			socket = NULL;
		}

		if (address != NULL)
		{
			free(address);
			address = NULL;
		}
	}

	// Returns list element at specific index
	// unsigned loc		 - target index
	// SOCKET_DATA* head - list head
	SOCKET_DATA* At(unsigned loc, SOCKET_DATA* head)
	{
		
		SOCKET_DATA* it = head;
		while (it != NULL)
		{
			if (loc == 0) return it;
			--loc;
			it = it->next;
		}
		return NULL;	
	}

	//Removes item from list
	//SOCKET_DATA** head	- pointer to list head
	//SOCKET_DATA* target	- element to be deleted
	void Remove(SOCKET_DATA** head, SOCKET_DATA* target)
	{
		if (*head == target) { *head = target->next, target->Dispose(); return; }	// If head
		SOCKET_DATA* it = (*head)->next;
		SOCKET_DATA* it_prev = *head;
		while (it != NULL)	// If not
		{
			if (it == target)
			{
				it_prev->next = it->next;	// Skip
				target->Dispose();
				return;
			}

			it_prev = it;
			it = it->next;
		}
	}

	//Removes item from list without resources disposal
	//SOCKET_DATA** head	- pointer to list head
	//SOCKET_DATA* target	- element to be deleted
	void Detach(SOCKET_DATA** head, SOCKET_DATA* target)
	{
		if (*head == target) { *head = target->next; return; }	// If head
		SOCKET_DATA* it = (*head)->next;
		SOCKET_DATA* it_prev = *head;
		while (it != NULL)	// If not
		{
			if (it == target)
			{
				it_prev->next = it->next;	// Skip
				return;
			}

			it_prev = it;
			it = it->next;
		}
	}

} SOCKET_DATA;

// List of thread handles
typedef struct HANDLE_LST
{
	HANDLE* handle;		// Pointer to thread handle
	HANDLE_LST* next;	// Pointer to next element of the list

	// Initialize all fields (remove garbage values)
	void Initialize()
	{
		handle = NULL;
		next = NULL;
	}

	// Safe dispose of allocated memory (for list)
	bool Dispose()
	{
		if (next == NULL) return true;
		else
		{
			next->Dispose();
			free(next);
			next = NULL;
			if (handle != NULL)
			{
				free(handle);
				handle = NULL;
			}
		}
		return true;
	}

	// Inserts new element at he end of the list
	// HANDLE_LST* new_el - to add element
	// HANDLE_LST** head  - pointer to list head
	void Insert(HANDLE_LST* new_el, HANDLE_LST** head)
	{
		if (*head == NULL)
			{*head = new_el; return;}

		HANDLE_LST* free_loc = *head;
		while (free_loc->next != NULL) free_loc = free_loc->next;

		free_loc->next = new_el;
	}

} HANDLE_LST;

// Element of service host list (mirroring servers)
typedef struct OUT_SERVICE
{
	SOCKET* socket;							// Pointer to mirror server socket
	sockaddr_in* address;					// Pointer to mirror server sockaddr_in address strucure	
	OUT_SERVICE* next;						// Pointer to next element	
	int service_idx[MAX_SERVICES_HOSTED*2];	// Indexes indexing SERVICE_NAME elements representing subscription of single mirroring server
	bool exposed;							// Indicator of successfull sent of locally hosted services to mirroring server described by list element

	// Initialize all fields (remove garbage values)
	void Initialize()
	{
		socket = NULL;
		address=NULL;
		next = NULL;
		exposed = false;
		memset(service_idx, -1, sizeof(int) * MAX_SERVICES_HOSTED*2);
	}

	// Subscribe mirror server to specific service
	// int new_sub_idx - index of service inside SERVICE_NAME list
	// returns true if succeeded, false if not
	bool SubscribeTo(int new_sub_idx)
	{
		int loc = 0;
		while (loc < MAX_SERVICES_HOSTED * 2)
		{
			if (service_idx[loc] == new_sub_idx) return false;

			if (service_idx[loc] == -1)
				{service_idx[loc]=new_sub_idx; return true; }

			++loc;
		}
		return false;
	}

	// Remove element from list by reference
	// OUT_SERVICE* target - to delete element
	// OUT_SERVICE** head  - pointer to head of the list
	void RemoveByRef(OUT_SERVICE* target, OUT_SERVICE** head)
	{
		if (*head == target) { *head=target->next, target->Dispose(); return; }	// If head
		OUT_SERVICE* it = (*head)->next;
		OUT_SERVICE* it_prev = *head;
		while (it != NULL)	// If not
		{
			if (it == target)
			{
				it_prev->next = it->next;	// Skip
				target->Dispose();
				return;
			}

			it_prev = it;
			it = it->next;
		}
	}

	// Returns pointer to first element of the list matching passed element address structure
	// OUT_SERVICE* el   - source for address comparesion
 	// OUT_SERVICE* head - head of the list
	OUT_SERVICE* FindByAddr(OUT_SERVICE* el, OUT_SERVICE* head)
	{
		OUT_SERVICE* it = head;
		while (it != NULL)	// If not
		{
			if (it->address->sin_addr.S_un.S_addr == el->address->sin_addr.S_un.S_addr &&
				it->address->sin_family == el->address->sin_family &&
				it->address->sin_port == el->address->sin_port)
				return it;

			it = it->next;
		}
		return NULL;
	}

	// Returns pointer to first element of the list matching passed element address and its type
	// sockaddr_in* addr   - target address structure
	// OUT_SERVICE* head  - head of the list
	OUT_SERVICE* FindByAddrOnly(sockaddr_in* addr, OUT_SERVICE* head)
	{
		OUT_SERVICE* it = head;
		while (it != NULL)	// If not
		{
			if (it->address->sin_addr.S_un.S_addr == addr->sin_addr.S_un.S_addr &&
				it->address->sin_family == addr->sin_family)
				return it;

			it = it->next;
		}
		return NULL;
	}
	
	// Safe dispose of allocated memory (for list)
	bool Dispose()
	{
		if (next == NULL) return true;
		else
		{
			next->Dispose();
			free(next);
			next = NULL;

			if (socket != NULL)
			{
				if (*socket != INVALID_SOCKET)
					closesocket(*socket);
				free(socket);
				socket = NULL;
			}

			if (address != NULL)
			{
				free(address);
				address = NULL;
			}
		}
		return true;
	}

	// Inserts new element to the end of the list
	// OUT_SERVICE* new_el - to add element
	// OUT_SERVICE** head  - pointer to list head
	void Insert(OUT_SERVICE* new_el, OUT_SERVICE** head)
	{
		if (*head == NULL)
			{*head = new_el; return;}

		OUT_SERVICE* free_loc = *head;
		while (free_loc->next != NULL) free_loc = free_loc->next;

		free_loc->next = new_el;
	}

} OUT_SERVICE;

// Structure encapsulating paramters for Exposing function(s)
typedef struct EXPOSE_PARAMS
{
	SOCKETPARAMS* target_params;	// Pointer to network structure of target mirror server
	SERVICE_NAME* service_names;	// Head of hosted service names list
	OUT_SERVICE** subscriebers;		// Head to mirroring servers list
    SETUP_MSG* expose_mess;			// Message for hosted services esposing
	char* expose_mess_buff;			// Buffer for exposing message
	unsigned long* nb_mode;			// Pointer to socket mode (blocking, non blocking)

	// Initialize all fields (remove garbage values)
	void Initialize()
	{
		target_params	 = NULL;
	    service_names	 = NULL;
		subscriebers	 = NULL;
		expose_mess		 = NULL;
		expose_mess_buff = NULL;
		nb_mode			 = NULL;
	}

}EXPOSE_PARAMS;

#pragma region ThreadParams

	// Structure encapsulating Listening Thread parameters
	typedef struct LISTENING_THR_PARAMS
	{
		SOCKET_DATA* listen_socket_params;	// Pointer to listen socket network paramters
		OUT_SERVICE** subscriebers;			// Head of list for subscriebed mirroring servers
		SERVICE_NAME** service_names;		// Head of list for service names
		bool* end_thr_flag;					// Pointer to safe thread shutdown flag 
		SETUP_MSG* expose_mess;				// Service expose message
		char* expose_mess_buff;				// Service expose message buff
		bool* accept_triggers;				// Array of accept triggers triggering Client Handle threads

		BUFF_PARAMS* buff_params;			// pointer to structure wich defines buffer lenghts
		BUFF_DESC** service_buffers_in;		// Head of list for input buffer descriptors  (from client perspective)
		BUFF_DESC** service_buffers_out;	// Head of list for output buffer descriptors (from client perspective)
		BUFF_DESC** input_buffer;			// Head of list for input buffer descriptors (ony 1 supported a the moment)
		BUFF_DESC** ack_buffer;				// Head of list for ack buffer descriptors (ony 1 supported a the moment)
		HANDLE_LST** client_req_handle;		// Head of list for client connections thread handles
		HANDLE_LST** loader_handle;			// Head of list for client loader thread handles
		HANDLE_LST** GC_handle;				// Head of list for client GC thread handles
		DWORD* threadIDs;					// Array of thread IDs
		SOCKET_DATA** client_socket_params;	// Head of list for connected client network parameters 
		SOCKET_PARAMS* reinit_sock_data;	// Pointer to backup network channel descriptors to contact target

		// Initialize all fields (remove garbage values)
		void Initialize()
		{
			listen_socket_params = NULL;
			subscriebers		 = NULL;
			service_names		 = NULL;
			end_thr_flag		 = NULL;

			buff_params			 = NULL;
			service_buffers_in	 = NULL;
			service_buffers_out  = NULL;
			input_buffer		 = NULL;
			ack_buffer			 = NULL;
			client_req_handle	 = NULL;
			loader_handle		 = NULL;
			GC_handle			 = NULL;
			threadIDs			 = NULL;
			client_socket_params = NULL;
			expose_mess			 = NULL;
			expose_mess_buff	 = NULL;
			reinit_sock_data	 = NULL;
			accept_triggers	     = NULL;
		}

		// Safe dispose of allocated resource (ignore passed by reference)
		void Dispose()
		{
			if (listen_socket_params != NULL)
			{
				free(listen_socket_params);
				listen_socket_params = NULL;
			}
			if (subscriebers != NULL) 
			{ 
				(*subscriebers)->Dispose();
				free(subscriebers); 
				subscriebers = NULL;
			}

			// Common, do not dispose
			service_names		 = NULL;
			end_thr_flag		 = NULL;

			buff_params			 = NULL;
			service_buffers_in	 = NULL;
			service_buffers_out  = NULL;
			input_buffer		 = NULL;
			ack_buffer			 = NULL;
			client_req_handle	 = NULL;
			loader_handle		 = NULL;
			GC_handle			 = NULL;
			threadIDs			 = NULL;
			client_socket_params = NULL;
			expose_mess			 = NULL;
			expose_mess_buff	 = NULL;
			reinit_sock_data	 = NULL;
			accept_triggers		 = NULL;
		}

	} LISTENING_THR_PARAMS;

	// Structure encapsulating Service Loader Thread parameters
	typedef struct SERVICE_LOADER_THR_PARAMS
	{
		BUFF_DESC* in_buffer;	// Input buffer descriptor  (consumed by thread)
		BUFF_DESC* out_buffer;	// Output buffer descriptor (feeded by thread)
		char service_name[MAX_SERVICE_NAME_SIZE + 1]; // Null terminated string containing neme of service whose messages are loaded
		bool* end_thr_flag;		// Pointer common safe thread shutdown flag

		// Initialize all fields (remove garbage values)
		bool Initialize()
		{
			in_buffer = NULL;
			out_buffer = NULL;
			end_thr_flag = NULL;
			memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
			return true;
		}

		// Safe dispose of allocated resource (ignore passed by reference)
		bool Dispose()
		{
			end_thr_flag = NULL;
			in_buffer=NULL;
			out_buffer=NULL;
			return true;
		}

	} SERVICE_LOADER_THR_PARAMS;

	// Structure encapsulating Garbage Collector Thread parameters
	typedef struct SERVICE_GC_THR_PARAMS
	{
		BUFF_DESC* in_buffer;	// Input buffer descriptor  (ack buffer)
		BUFF_DESC* out_buffer;	// Output buffer descriptor ( service out buffer; to be acked) 
		char service_name[MAX_SERVICE_NAME_SIZE + 1]; // Null terminated string containing neme of service whose messages are acked
		bool* end_thr_flag;		// Pointer to safe thread shutdown flag 

		// Initialize all fields (remove garbage values)
		bool Initialize()
		{
			in_buffer = NULL;
			out_buffer = NULL;
			end_thr_flag = NULL;
			memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
			return true;
		}

		// Safe dispose of allocated memory (for list)
		bool Dispose()
		{
			in_buffer=NULL;
			out_buffer=NULL;
			end_thr_flag = NULL;
			return true;
		}

	} SERVICE_GC_THR_PARAMS;

	// Structure encapsulating input thread parameters
	typedef struct INPUT_THR_PARAMS
	{
		bool* end_thr_flag; // Pointer to safe thread shutdown flag

		// Initialize all fields (remove garbage values)
		bool Initialize()
		{

			end_thr_flag = NULL;
			return true;
		}

		// Safe dispose of allocated memory (for list)
		bool Dispose()
		{
			end_thr_flag = NULL;
		}

	} INPUT_THR_PARAMS;

	// Structure encapsulating output thread parameters
	typedef struct OUTPUT_THR_PARAMS
	{
		BUFF_DESC* out_buffers;	// Head of list for output buffers consumed by thread (data sent by client)
		OUT_SERVICE* dst;		// Mirroring server network parameters
		SERVICE_NAME* service_names; // Head of service names list
		bool* end_thr_flag;		// Pointer to safe thread shutdown flag

		// Initialize all fields (remove garbage values)
		bool Initialize()
		{

			end_thr_flag = NULL;
			out_buffers = NULL;
			dst = NULL;
			service_names = NULL;
			return true;
		}

		// Safe dispose of allocated memory (for list)
		bool Dispose()
		{
			if (dst != NULL)
			{
				dst->Dispose();
				free(dst);
				dst = NULL;
			}
			service_names = NULL;
			out_buffers = NULL;
			end_thr_flag = NULL;
		}

	} OUTPUT_THR_PARAMS;

	// Structure encapsulating Clienat Request Handle thread parameters
	typedef struct CLIENT_THR_PARAMS
	{
		BUFF_DESC* in_buffer;	// Input buffer descriptor (content sent by client)
		BUFF_DESC* out_buffer;	// Output buffer descriptor (content ready to be read by client)					
		char service_name[MAX_SERVICE_NAME_SIZE + 1];	// Null terminated string containing name of service whose messages are handled
		bool* end_thr_flag;		// Pointer to common thread shutdown flag
		SOCKET_DATA* socket_data_accepted;	// Pointer to client network parameters (fetched by Client Register thread)
		bool* accept_trigger;	// Pointer to common safe thread shutdown flag

		// Initialize all fields (remove garbage values)
		bool Initialize()
		{
			in_buffer = NULL;
			out_buffer = NULL;

			end_thr_flag = NULL;
			memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
			socket_data_accepted = NULL;
			accept_trigger = NULL;
			return true;
		}

		// Safe dispose of allocated memory (for list)
		bool Dispose()
		{
			if (socket_data_accepted != NULL)
			{
				free(socket_data_accepted);
				socket_data_accepted = NULL;
			}

			in_buffer = NULL;
			out_buffer = NULL;
			end_thr_flag = NULL;
			accept_trigger = NULL;
			return true;
		}

	} CLIENT_THR_PARAMS;

	// Structure encapsulating Client Register thread parameters
	typedef struct CLIENT_REGISTER_THR_PARAMS
	{

		SOCKET_DATA* register_socket_params;	// Network parameter for socket listening for client connections
		SERVICE_NAME* service_names;			// Head of service names list
		bool* end_thr_flag;						// Pointer to common thread safe shudown flag
		bool* accept_triggers;					// Triggers for accept in Client Req Handle threads
		SOCKET_DATA* client_socket_params;		// Head of client network parameters list

		// Initialize all fields (remove garbage values)
		void Initialize()
		{
			register_socket_params = NULL;
			service_names = NULL;
			end_thr_flag = NULL;
			client_socket_params = NULL;
			if (accept_triggers != NULL)
			{
				accept_triggers = NULL;
			}
		}
	

	}CLIENT_REGISTER_THR_PARAMS;

#pragma endregion

// Structure represents pending ACK message
typedef struct MSG_ACK_PND
{
	struct MSG_ACK* ack;    // Pointer to ack
	OUT_SERVICE* reciever;  // Pointer to reciever (mirror server) network channel
	MSG_ACK_PND* next;      // Next element of the list

	// Initialize all fields (remove garbage values)
	void Initialize()
	{
		ack = NULL;
		reciever = NULL;
		next = NULL;
	}

	// Safe dispose of allocated memory
	void Dispose()
	{
		if (next != NULL)
			next->Dispose();

		if (ack != NULL)
		{
			ack->Dispose();
			ack = NULL;
			reciever = NULL;
		}
	}

	// Inserts ack into list
	// MSG_ACK_PND* new_el - to be added element
	// MSG_ACK_PND** head  - pointer to head list
	void Insert(MSG_ACK_PND* new_el, MSG_ACK_PND** head)
	{
		if (*head == NULL)
		{
			*head = new_el; return;
		}

		MSG_ACK_PND* free_loc = *head;
		while (free_loc->next != NULL) free_loc = free_loc->next;

		free_loc->next = new_el;
	}

	void Remove(MSG_ACK_PND* to_del, MSG_ACK_PND** head)
	{
		if (*head == to_del)*head = to_del->next;
		else
		{
			MSG_ACK_PND* it_prev = *head;
			MSG_ACK_PND* it = (*head)->next;
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
		ack->Dispose();
		ack = NULL;
		reciever = NULL;
	}

}MSG_ACK_PND;

