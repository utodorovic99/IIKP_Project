#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"
#include "Common.h"

using namespace std;

typedef struct SETUP_MSG
{
    unsigned short msg_code;
    unsigned content_size;
    char* content;

    void Initialize()
    {
        unsigned short msg_code=0;
        unsigned content_size=0;
        char* content=NULL;
    }

    void Dispose()
    {
        free(content);
        content = NULL;
    }

}SETUP_MSG;

typedef struct SERVICE_MSG
{
    unsigned short msg_code;
    char service[MAX_SERVICE_NAME_SIZE];
    char* content;

    void Dispose()
    {
        free(content);
        content = NULL;
    }

}SERVICE_MSG;

enum  EQueueingMsgType { SERVICES_ENL = 0, SERVICE_MSG = 1 };
