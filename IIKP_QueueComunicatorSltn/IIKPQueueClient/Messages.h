#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"
#include "Common.h"

using namespace std;

// Structure representing App Layer Setup Message 
// Message is used in delta services setup phase
typedef struct SETUP_MSG
{
    unsigned short msg_code;    // Message code
    unsigned content_size;      // Content buffer size
    char* content;              // Null terminated string containing names of services hosted by mirroring server

    // Initialize all fields (remove garbage values)
    void Initialize()
    {
        unsigned short msg_code=0;
        unsigned content_size=0;
        char* content=NULL;
    }

    // Safe dispose of allocated memory (for list)
    void Dispose()
    {
        free(content);
        content = NULL;
    }

}SETUP_MSG;

// Structure representing App Layer communication message
// Message is used in inner mirroring server communication
typedef struct SERVICE_MSG
{
    unsigned short msg_code;    // Message code
    char service[MAX_SERVICE_NAME_SIZE]; // Null termninated string of service name wich message is associated
    char* content;              // Null terminated string containing message
    unsigned msg_id;            // Unique message ID set by mirroring server

    // Safe dispose of allocated memory (for list)
    void Dispose()
    {
        free(content);
        content = NULL;
    }

}SERVICE_MSG;

// Structure representing client message enqueue request 
typedef struct CLIENT_MSG_ENQ
{
    unsigned short msg_code; // Message code
    unsigned  msg_id;        // Message id 
    char* content;           // Null terminated string containing message

    // Safe dispose of allocated memory (for list)
    void Dispose()
    {
        free(content);
        content = NULL;
    }

}CLIENT_MSG_ENQ;

// Structure representing client connect request 
typedef struct CLIENT_MSG_CONN
{
    unsigned short msg_code;    // Message code
    char* service;              // Null terminated string conaining target service name

    // Safe dispose of allocated memory (for list)
    void Dispose()
    {
        free(service);
        service = NULL;
    }

}CLIENT_MSG_CONN;

// Structure represents message ack
typedef struct MSG_NACK
{
    unsigned short msg_code;    // Message code
    unsigned msg_id;            // Message ID
    char* error;                // Optionally add cause

    // Initialize all fields (remove garbage values)
    void Initialize()
    {
        error = NULL;
        msg_code = -1;
        msg_id = 0;
    }

    // Safe dispose of allocated memory (
    void Dispose()
    {
        if (error != NULL)
        {
            free(error);
            error = NULL;
        }
    }

}MSG_NACK;

// Structure represents message ack
typedef struct MSG_ACK
{
    unsigned short msg_code;    // Message code
    unsigned msg_id;            // Message ID
    char* service;                // Optionally add cause
    MSG_ACK* next;

    // Initialize all fields (remove garbage values)
    void Initialize()
    {
        service = NULL;
        msg_code = -1;
        msg_id = 0;
        next = NULL;
    }

    // Safe dispose of allocated memory
    void Dispose()
    {
        free(service);
        service = NULL;       
    }

    // Inserts ack into list
    // MSG_ACK* new_el - to be added element
    // MSG_ACK** head  - pointer to head list
    void Insert(MSG_ACK* new_el, MSG_ACK** head)
    {
        if (*head == NULL)
        {
            *head = new_el; return;
        }

        MSG_ACK* free_loc = *head;
        while (free_loc->next != NULL) free_loc = free_loc->next;

        free_loc->next = new_el;
    }

}MSG_ACK;

// Enumeration for distinct message codes
enum  EQueueingMsgType { SERVICES_ENL = 1, SERVICE_MSG = 2, CLIENT_ENQ=3, CLIENT_CONN=4, MSG_ACK=5, MSG_NACK=6};
