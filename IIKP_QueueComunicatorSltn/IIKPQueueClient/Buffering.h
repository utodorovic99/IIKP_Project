#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"
#include "Common.h"

#include <direct.h>                               // Windows supported only
#define GetCurrentDir _getcwd
using namespace std;

#pragma region IgnoreWarnings
#pragma warning(suppress : 6387)
#pragma warning(suppress : 6011)
#pragma warning(suppress : 26812)
#pragma endregion

#pragma region Constants
# define ERR_BUFF_SIZE 255
#pragma endregion

#pragma region Globals
char QueueErrMsg[ERR_BUFF_SIZE + 1];
#pragma endregion

#pragma region Data

// Structure containing buffer parameters (size for each buffer type )
typedef struct BUFF_PARAMS
{
	unsigned inqueue;           // Size of input queue
	unsigned ackqueue;          // Size of ack queue
	unsigned service_in_queue;  // Size of service input queue  (queue accepting mirroring messages)
	unsigned service_out_queue; // Size of service output queue (queue sending messages to be mirrored)

    // Validates buffer parameters
    // Returns true if success, false if not
    bool Validate()
    {
        return 	(inqueue >0) && (ackqueue > 0) && (service_in_queue > 0) && (service_out_queue);
    }
}BUFF_PARAMS;

// Structure acting as circular buffer descriptor, contains attributes associated with buffer. Supports list organisation. 
typedef struct BUFF_DESC
{
	char context;       // Buffer type code
	char* name;         // Null terminated string containing buffer name (formatted by service & context)
	unsigned capacity;  // Buffer capacity
	char* memory;       // Buffer memory
	unsigned start;     // Used memory start index
	unsigned stop;      // Used memory stop index
    unsigned messges_enqueued; // Total numbers of messages enqueued
    BUFF_DESC* next;    // Pointer to next liste element

    // Finds first buffer descriptor by name
    // const char* name - target name
    // BUFF_DESC* head  - list of buffer descriptor to be searched
    // Returns pointer to taget buffer descriptor, NULL if not found 
    BUFF_DESC* FindByName(const char* name, BUFF_DESC* head)
    {
        BUFF_DESC* buff_it = head;
        while (buff_it != NULL)
        {
            if (!strcmp(buff_it->name, name))
                return buff_it;

            buff_it = buff_it->next;
        }
        return NULL;
    }

    // Initialize (remove garbage values)
	void Initialize()
	{
		memory = NULL;
        next = NULL;
        name = NULL;
        messges_enqueued = 0; // Total numbers of messages enqueued
	}

    // Safe dispose of allocated memory (for list)
	bool Dispose()
	{
        if (next == NULL) return true;
        else 
        { 
            next->Dispose();
            free(next);
            free(memory);
            free(name);
            next = NULL;
            memory = NULL;
            name = NULL;
            return true;
        }
	}

    // Prepares structure content
	void Prepare()
	{
		memset(memory, 0, capacity);
		start = 0;
		stop = 0;
	}

    // Inserts element at the end of the list
    // BUFF_DESC* new_el - to insert element
    // BUFF_DESC** head  - pointer to head of the list for buffer descriptor
    void Insert(BUFF_DESC* new_el, BUFF_DESC** head)
    {
        if (*head == NULL)
            {*head = new_el; return;}
        BUFF_DESC* freeLoc = *head;
        while (freeLoc->next != NULL) freeLoc = freeLoc->next;

        freeLoc->next = new_el;
    }

    // Skips forwarded number of elements starting from callers index
    // int elems_num - number of elements to be skipped
    // Returns buffer descriptor of target element, NULL if not found
    BUFF_DESC* SkipElems(int elems_num)
    {
        BUFF_DESC* buff_it = next;
        elems_num--;

        if (elems_num > 0) 
            do
                {buff_it = next->next;}
            while (elems_num > 0 && buff_it != NULL);
       
        return buff_it;
    }

    // Removes element from the list
    // BUFF_DESC* to_del - to delete element
    // BUFF_DESC** head  - pointer to list head
    void Remove(BUFF_DESC* to_del , BUFF_DESC** head)
    {
        if (*head == to_del)*head = to_del->next;
        else
        {
            BUFF_DESC* it_prev = *head;
            BUFF_DESC* it = (*head)->next;
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

    // Prints formatted list content
    // BUFF_DESC* head - list head
    void PrintOut(BUFF_DESC* head)
    {
        BUFF_DESC* it = head;
        while (it != NULL)
        {
            printf("\tNAME: %s\tCAPACITY:%u\n", it->name, it->capacity);
            it = it->next;
        }
    }

    // TODO:
    // Stores message into circular buffer
    bool Enqueue(char* msg, unsigned mess_buff_size) { ++messges_enqueued; return true; }

    // TODO:
    // Takes message from circular buffer
    // char* mess_buff      - message buff (acts as return value)
    // char mess_buff_size  - message buff size
    bool Dequeue(char* mess_buff)                    { --messges_enqueued; return true; }

}BUFF_DESC;

// Enumeration representing buffer context code (its function)
enum BUFF_TYPE { INBUF = 0, ACKBUF = 1, DELTABUF = 2, REGISTERBUF = 2, INBUF_SRV = 3, OUTBUF_SRV = 4, UNKNOWN = 5 };
#pragma endregion

#pragma region FunctionsDecl
    // Loads buffer parameters structure (buffer sizes) from config file
    // FILE** file          - pointer to config file descriptor
    // bool* success_flag   - pointer to outcome flag (acts as return value)
    // Returns buffer parameters structure 
    BUFF_PARAMS LoadBufferParams(FILE** file, bool* success_flag);

    // Parses single buffer parameter record
    // char* record          - string of to be parsed record
    // int length            - record length
    // BUFF_PARAMS* buffDesc - pointer to buffer descriptor to be filled (acts as return value)
    // int* end_ptr          - pointer to end index (acts as return value, used for skipping parsed record)
    // Returns enum indicating wich type of record has beeen parsed
    BUFF_TYPE ParseBUFFDefRecord(char* record, int length, BUFF_PARAMS* buff_desc, int* end_ptr);
#pragma endregion

#pragma region FunctionsImpl

    BUFF_TYPE ParseBUFFDefRecord(char* record, int length, BUFF_PARAMS* buff_desc, int* end_ptr)
    {
        int byte_loc = 0;
        int stop_loc = 0;

        if (record[byte_loc] == '\n' || record[byte_loc] == '\t' || record[byte_loc] == ' ') SkipSpacingsFront(&record[byte_loc], length, &byte_loc);
        if (byte_loc >= length) return UNKNOWN;

        int times_found = 0;

        for (byte_loc; byte_loc < length; ++byte_loc)
            if (record[byte_loc] == '$') { ++times_found; break; }

        ++byte_loc;

        for (stop_loc = byte_loc + 1; stop_loc < length; ++stop_loc)
            if (record[stop_loc] == '$'){++times_found;break; }

        if (stop_loc == length || times_found<2) return UNKNOWN;

        --stop_loc;
        BUFF_TYPE type_found = UNKNOWN;
        if (strstr(record, ":")) 
        {
            char buff_str[MAX_RECORD_LENGTH];
            memset(buff_str, 0, MAX_RECORD_LENGTH);
            memcpy(buff_str, &record[byte_loc], stop_loc - byte_loc + 1);
            SkipSpacingsFront(&record[byte_loc], stop_loc - byte_loc + 1, &byte_loc);
            char* part = strtok(buff_str, ":");
            if (strstr(part, "INQUEUE") != NULL)            type_found = INBUF;
            else if (strstr(part, "ACKQUEUE") != NULL)      type_found = ACKBUF;
            else if (strstr(part, "SERVICEIN") != NULL)     type_found = INBUF_SRV;
            else if (strstr(part, "SERVICEOUT") != NULL)    type_found = OUTBUF_SRV;
            else return UNKNOWN;

            part = strtok(NULL, ":");
            switch (type_found)
            {
                case  INBUF:
                { 
                    buff_desc->inqueue = atoi(part); 
                    printf("Parsed line: INBUF:\t\t%u\n", buff_desc->inqueue);
                    break;
                }
                case  ACKBUF:
                {
                    buff_desc->ackqueue = atoi(part); 
                    printf("Parsed line: ACKBUFF:\t\t%u\n", buff_desc->ackqueue);
                    break;
                }
                case  INBUF_SRV:
                {
                    buff_desc->service_in_queue = atoi(part); 
                    printf("Parsed line: SERVICE_IN:\t%u\n", buff_desc->service_in_queue);
                    break;
                }
                case  OUTBUF_SRV:
                {
                    buff_desc->service_out_queue = atoi(part);
                    printf("Parsed line: SERVICE_OUT:\t%u\n", buff_desc->service_out_queue);
                    break;
                }
            }
        }
        *end_ptr = stop_loc + 1;
        return type_found;
    }
    BUFF_PARAMS LoadBufferParams(FILE** file, bool* succ_flag)
	{
        BUFF_PARAMS buff_params;
        buff_params.ackqueue = 0;
        buff_params.inqueue = 0;
        buff_params.service_in_queue = 0;
        buff_params.service_out_queue = 0;

        if (file == NULL || *file == NULL) { *succ_flag = 0; return buff_params; }
        FILE* fptr = *file;

        char buff[MAX_RECORD_LENGTH];
        memset(buff, 0, MAX_RECORD_LENGTH);
        char* buff_it = buff;

        int cls_idx = 0;
        bool lineProccessing = false;
        bool load_flag = true;
        char* delimit_ptr = NULL;

        bool defs_found[5];
        defs_found[0] = 0;
        defs_found[1] = 0;
        defs_found[2] = 0;
        defs_found[3] = 0;
        defs_found[4] = 0;

        *succ_flag = 1;
        while (true)                         //Read line by line 
        {
            if (load_flag)
                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *succ_flag = 0; return buff_params; }


            if (strstr(buff_it, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                do
                {
                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *succ_flag = 0; return buff_params; }

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
                else if (buff_it[cls_idx] == EOF) { *succ_flag = 0; return buff_params; }           // End of file
                else if (buff_it[cls_idx] == '%')
                {
                    ++cls_idx;
                    char* cut_ptr = NULL;
                    if (cls_idx < MAX_RECORD_LENGTH)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if ((cut_ptr = strstr(buff_it, "%BUFFDEF:\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))++buff_it;
                        else { *succ_flag = 0; return buff_params; }

                        int start, stop = -1;
                        bool open_body_found = false;

                        for (int loc = 0; loc < MAX_RECORD_LENGTH; ++loc)  // Continue searching in same line
                        {
                            if (buff_it[loc] == '_' || buff_it[loc] == '\t')
                                SkipSpacingsFront(&buff_it[loc], MAX_RECORD_LENGTH, &loc);
                            if (buff_it[loc] == EOF) { *succ_flag = 0; return buff_params; }  // Bad syntax-no closing tag
                            if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                            {
                                do
                                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                                        {*succ_flag = 0; return buff_params;}
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
                                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *succ_flag = 0; return buff_params; }
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
                                            if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *succ_flag = 0; return buff_params; }
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

                                            switch (ParseBUFFDefRecord(buff_it, strlen(buff_it), &buff_params, &line_loc))
                                            {
                                                case  INBUF: 
                                                    { defs_found[INBUF] = 1; break; }
                                                case  ACKBUF: 
                                                    {defs_found[ACKBUF] = 1; break; }
                                                case  INBUF_SRV: 
                                                    {defs_found[INBUF_SRV] = 1; break; }
                                                case  OUTBUF_SRV: 
                                                    {defs_found[OUTBUF_SRV] = 1; break; }
                                                case  UNKNOWN: 
                                                    { *succ_flag = 0; return buff_params; }
                                            }
                                                                                        
                                            ++line_loc;
                                            open_tag_found = false;
                                            closed_tag_found = false;
                                            continue;
                                        }
                                    }
                                    else if (buff_it[line_loc] == '}')
                                    {
                                        cls_idx = line_loc + 2;     // Skip }%
                                        seek_proto = true;
                                        break;
                                    }
                                }

                                if (open_body_found == true) { *succ_flag = 0; return buff_params; }    // No } closure
                                if (seek_proto) break;   // Brake
                            }
                        }
                       
                    }
                }
            }
        }

        *succ_flag = defs_found[INBUF] && defs_found[ACKBUF] && defs_found[INBUF_SRV] && defs_found[OUTBUF_SRV];
        return buff_params;
	}
#pragma endregion