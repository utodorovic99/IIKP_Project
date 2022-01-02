#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"

#ifndef MAX_SERVICES_HOSTED 
#define MAX_SERVICES_HOSTED 10
#endif

typedef struct SERVICE_NAME
{
	char* name;
	unsigned length;
	SERVICE_NAME* next;

	void Initialize()
	{
		name = NULL;
		next = NULL;
		length = 0;
	}

	SERVICE_NAME* At(int loc, SERVICE_NAME* service_names)
	{
		SERVICE_NAME* it = service_names;
		while (loc > 0 && it != NULL)
			it = it->next;
		
		return it;
	}

	void Format(char* buff, int buffLen, int servicesNum, SERVICE_NAME* head)
	{
		memset(buff, 0, buffLen);
		SERVICE_NAME* names_it = head;
		if (names_it == NULL) return;
		char* buff_it = buff;

		bool parse_all_regime = false;
		if (servicesNum <= -1) parse_all_regime = true;

		do
		{
			memcpy(buff_it, names_it->name, strlen(names_it->name));
			buff_it += strlen(names_it->name);
			*buff_it = '|';
			++buff_it;

			if (!parse_all_regime && (--servicesNum) <= 0) return;

		}while ((names_it = names_it->next) != NULL);
	}

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

	void Insert(SERVICE_NAME* newEl, SERVICE_NAME** head)
	{
		if (*head == NULL)
			{*head = newEl; return;}
		SERVICE_NAME* freeLoc = *head;
		while (freeLoc->next != NULL) freeLoc = freeLoc->next;

		freeLoc->next = newEl;
	}

	unsigned Count(SERVICE_NAME* head)
	{
		unsigned num = 0;
		SERVICE_NAME* it = head;
		while (head != NULL)
		{
			++num;
			it = it->next;
		}
		return num;
	}

} SERVICE_NAME;


typedef struct SOCKET_DATA
{
	SOCKET* socket;
	sockaddr_in* address;
	SOCKET_DATA* next;
	bool initialized;

	void Initialize()
	{
		socket=NULL;
		address=NULL;
		next=NULL;
		initialized = false;
	}

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

	void Insert(SOCKET_DATA* newEl, SOCKET_DATA** head)
	{
		if (*head == NULL)
			{*head = newEl; return;}

		SOCKET_DATA* freeLoc = *head;
		while (freeLoc->next != NULL) freeLoc = freeLoc->next;

		freeLoc->next = newEl;
	}

} SOCKET_DATA;

typedef struct HANDLE_LST
{
	HANDLE* handle;
	HANDLE_LST* next;


	void Initialize()
	{
		handle = NULL;
		next = NULL;
	}

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

	void Insert(HANDLE_LST* newEl, HANDLE_LST** head)
	{
		if (*head == NULL)
			{*head = newEl; return;}

		HANDLE_LST* freeLoc = *head;
		while (freeLoc->next != NULL) freeLoc = freeLoc->next;

		freeLoc->next = newEl;
	}

} HANDLE_LST;

typedef struct OUT_SERVICE
{
	SOCKET* socket;
	sockaddr_in* address;
	OUT_SERVICE* next;
	int service_idx[MAX_SERVICES_HOSTED];


	void Initialize()
	{
		socket = NULL;
		address=NULL;
		next = NULL;
		memset(service_idx, -1, sizeof(int) * MAX_SERVICES_HOSTED);
	}

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

	OUT_SERVICE* FindByAddr(OUT_SERVICE* el, OUT_SERVICE* head)
	{
		OUT_SERVICE* it = head;
		while (it != NULL)	// If not
		{
			if (it->address->sin_addr.S_un.S_addr == el->address->sin_addr.S_un.S_addr &&
				it->address->sin_family == el->address->sin_family &&
				it->address->sin_port == el->address->sin_port)
		    break;

			it = it->next;
		}
		return it;
	}

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

	void Insert(OUT_SERVICE* newEl, OUT_SERVICE** head)
	{
		if (*head == NULL)
			{*head = newEl; return;}

		OUT_SERVICE* freeLoc = *head;
		while (freeLoc->next != NULL) freeLoc = freeLoc->next;

		freeLoc->next = newEl;
	}

} OUT_SERVICE;

// Thread params
typedef struct LISTENING_THR_PARAMS
{
	SOCKET_DATA* listen_socket_params;
	OUT_SERVICE* subscriebers;
	SERVICE_NAME* service_names;
	bool* end_thr_flag;

	void Initialize()
	{
		listen_socket_params = NULL;
		subscriebers = NULL;
		service_names = NULL;
		end_thr_flag = NULL;
	}

	void Dispose()
	{
		if (listen_socket_params != NULL)
		{
			free(listen_socket_params);
			listen_socket_params = NULL;
		}
		if (subscriebers != NULL) 
		{ 
			subscriebers->Dispose();
			free(subscriebers); 
			subscriebers = NULL;
		}

		service_names = NULL;
		end_thr_flag = NULL;	
	}

} LISTENING_THR_PARAMS;

typedef struct SERVICE_LOADER_THR_PARAMS
{
	BUFF_DESC* in_buffer;
	BUFF_DESC* out_buffer;
	char service_name[MAX_SERVICE_NAME_SIZE + 1];
	bool* end_thr_flag;

	bool Initialize()
	{
		in_buffer = NULL;
		out_buffer = NULL;
		end_thr_flag = NULL;
		memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
		return true;
	}

	bool Dispose()
	{
		end_thr_flag = NULL;
		in_buffer=NULL;
		out_buffer=NULL;
		return true;
	}

} SERVICE_LOADER_THR_PARAMS;

typedef struct SERVICE_GC_THR_PARAMS
{
	BUFF_DESC* in_buffer;
	BUFF_DESC* out_buffer;
	SOCKET_DATA* socket_data = NULL;
	char service_name[MAX_SERVICE_NAME_SIZE + 1];
	bool* end_thr_flag;

	bool Initialize()
	{
		in_buffer = NULL;
		out_buffer = NULL;
		end_thr_flag = NULL;
		memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
		return true;
	}

	bool Dispose()
	{
		if (socket_data != NULL)
		{
			socket_data->Dispose();
			free(socket_data);
			socket_data = NULL;
		}

		in_buffer=NULL;
		out_buffer=NULL;
		end_thr_flag = NULL;
		return true;
	}

} SERVICE_GC_THR_PARAMS;

typedef struct CLIENT_THR_PARAMS
{
	BUFF_DESC* in_buffer;
	BUFF_DESC* out_buffer;
	SOCKET_DATA* socket_data = NULL;
	char service_name[MAX_SERVICE_NAME_SIZE + 1];
	bool* end_thr_flag;

	bool Initialize()
	{
		in_buffer = NULL;
		out_buffer = NULL;
		socket_data = NULL;
		end_thr_flag = NULL;
		memset(service_name, 0, MAX_SERVICE_NAME_SIZE + 1);
		return true;
	}

	bool Dispose()
	{
		if (socket_data != NULL)
		{
			socket_data->Dispose();
			free(socket_data);
			socket_data = NULL;
		}

		in_buffer = NULL;
		out_buffer = NULL;
		end_thr_flag = NULL;
		return true;
	}

} CLIENT_THR_PARAMS;


typedef struct INPUT_THR_PARAMS
{
	bool* end_thr_flag;

	bool Initialize()
	{

		end_thr_flag = NULL;
		return true;
	}

	bool Dispose()
	{
		end_thr_flag = NULL;
	}

} INPUT_THR_PARAMS;

typedef struct OUTPUT_THR_PARAMS
{
	BUFF_DESC* out_buffer;
	SOCKET_DATA* dst;
	bool* end_thr_flag;

	bool Initialize()
	{

		end_thr_flag = NULL;
		out_buffer = NULL;
		dst = NULL;
		return true;
	}

	bool Dispose()
	{
		if (dst != NULL)
		{
			dst->Dispose();
			free(dst);
			dst = NULL;
		}

		out_buffer = NULL;
		end_thr_flag = NULL;
	}

} OUTPUT_THR_PARAMS;
