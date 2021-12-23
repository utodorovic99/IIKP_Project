#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include "string.h"

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
# define MAX_BUFF_NAME 30
#pragma endregion

#pragma region Globals
char QueueErrMsg[ERR_BUFF_SIZE + 1];
#pragma endregion

#pragma region Data

enum BUFF_TYPE { INBUF = 0, ACKBUF = 1, INBUF_SRV = 2, OUTBUF_SRV = 3, UNKNOWN = 4 };

// Struct contains 
typedef struct BUFF_PARAMS
{
	unsigned inqueue;
	unsigned ackqueue;
	unsigned service_in_queue;
	unsigned service_out_queue;
}BUFF_PARAMS;

typedef struct BUFF_DESC
{
	char context;
	char name[MAX_BUFF_NAME + 1];
	unsigned capacity;
	char* memory;
	unsigned start;
	unsigned stop;

	void Prepare()
	{
		memory = NULL;
	}

	void Dispose()
	{
		if (memory != NULL) free(memory);
	}

	void Initialize()
	{
		memset(memory, 0, capacity);
		memset(name, 0, MAX_BUFF_NAME + 1);
		start = 0;
		stop = 0;
	}

}BUFF_DESC;
#pragma endregion

#pragma region FunctionsDecl
    BUFF_PARAMS LoadBufferParams(FILE** file, bool* successFlag );
    BUFF_TYPE ParseBUFFDefRecord(char* record, int length, BUFF_PARAMS* buffDesc, int* endPtr);
#pragma endregion

#pragma region FunctionsImpl

    BUFF_TYPE ParseBUFFDefRecord(char* record, int length, BUFF_PARAMS* buffDesc, int* endPtr)
    {
        int byteLoc = 0;
        int stopLoc = 0;

        if (record[byteLoc] == '\n' || record[byteLoc] == '\t' || record[byteLoc] == ' ') SkipSpacingsFront(&record[byteLoc], length, &byteLoc);
        if (byteLoc >= length) return UNKNOWN;

        int timesFound = 0;

        for (byteLoc; byteLoc < length; ++byteLoc)
            if (record[byteLoc] == '$') { ++timesFound; break; }

        ++byteLoc;

        for (stopLoc = byteLoc + 1; stopLoc < length; ++stopLoc)
            if (record[stopLoc] == '$'){++timesFound;break; }

        if (stopLoc == length || timesFound<2) return UNKNOWN;

        --stopLoc;
        BUFF_TYPE foundType = UNKNOWN;
        if (strstr(record, ":")) 
        {
            char buffStr[MAX_RECORD_LENGTH];
            memset(buffStr, 0, MAX_RECORD_LENGTH);
            memcpy(buffStr, &record[byteLoc], stopLoc - byteLoc + 1);
            SkipSpacingsFront(&record[byteLoc], stopLoc - byteLoc + 1, &byteLoc);
            char* part = strtok(buffStr, ":");
            if (strstr(part, "INQUEUE") != NULL)            foundType = INBUF;
            else if (strstr(part, "ACKQUEUE") != NULL)      foundType = ACKBUF;
            else if (strstr(part, "SERVICEIN") != NULL)     foundType = INBUF_SRV;
            else if (strstr(part, "SERVICEOUT") != NULL)    foundType = OUTBUF_SRV;
            else return UNKNOWN;

            part = strtok(NULL, ":");
            switch (foundType)
            {
                case  INBUF:
                { buffDesc->inqueue = atoi(part); break; }
                case  ACKBUF:
                {buffDesc->ackqueue = atoi(part); break; }
                case  INBUF_SRV:
                {buffDesc->service_in_queue = atoi(part); break; }
                case  OUTBUF_SRV:
                {buffDesc->service_out_queue = atoi(part); break; }
            }
        }
        return foundType;
    }

    BUFF_PARAMS LoadBufferParams(FILE** file, bool* successFlag)
	{
        BUFF_PARAMS buffParams;
        buffParams.ackqueue = 0;
        buffParams.inqueue = 0;
        buffParams.service_in_queue = 0;
        buffParams.service_out_queue = 0;

        if (file == NULL || *file == NULL) { *successFlag = 0; return buffParams; }
        FILE* fptr = *file;

        char buff[MAX_RECORD_LENGTH];
        memset(buff, 0, MAX_RECORD_LENGTH);
        char* buff_it = buff;

        int clsIdx = 0;
        char cutCharOldVal = 0;
        bool lineProccessing = false;
        bool loadFlag = true;
        char* delimitPtr = NULL;

        bool defsFound[4];
        defsFound[0] = 0;
        defsFound[1] = 0;
        defsFound[2] = 0;
        defsFound[3] = 0;

        *successFlag = 1;
        while (true)                         //Read line by line 
        {
            if (loadFlag)
                if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *successFlag = 0; return buffParams; }


            if (strstr(buff_it, "#Legend"))                            //Skip Legend section (last line)
            {
                // Skip inner lines
                do
                {
                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *successFlag = 0; return buffParams; }

                    clsIdx = 0;
                }                 while (!(delimitPtr = strstr(buff_it, "#")));
                ++delimitPtr;

                //Trim Skip section ending
                sprintf_s(buff_it, MAX_RECORD_LENGTH, "%s\0", delimitPtr);
                clsIdx = 0;
            }

            // Seek % starter          
            bool seekProto = false;
            for (clsIdx; clsIdx < MAX_RECORD_LENGTH; ++clsIdx)   // Seek in current line
            {
                if (clsIdx == MAX_RECORD_LENGTH || buff_it[clsIdx] == '\r' || buff_it[clsIdx] == '\n') break;          // End of line, take another one
                else if (buff_it[clsIdx] == EOF) { *successFlag = 0; return buffParams; }           // End of file
                else if (buff_it[clsIdx] == '%')
                {
                    ++clsIdx;
                    unsigned short protocolFoundID = 0;
                    int skipOffset = 0;
                    char* cutPtr = NULL;
                    if (clsIdx < MAX_RECORD_LENGTH)         // Found in current line
                    {
                        //Compares end of previous and following line
                        if ((cutPtr = strstr(buff_it, "%BUFFDEF:\r")) && fgets(buff_it, MAX_RECORD_LENGTH, fptr))++buff_it;
                        else { *successFlag = 0; return buffParams; }

                        int start, stop = -1;
                        bool openBodyFound = false;

                        for (int loc = 0; loc < MAX_RECORD_LENGTH; ++loc)  // Continue searching in same line
                        {
                            if (buff_it[loc] == '_' || buff_it[loc] == '\t')
                                SkipSpacingsFront(&buff_it[loc], MAX_RECORD_LENGTH, &loc);
                            if (buff_it[loc] == EOF) { *successFlag = 0; return buffParams; }  // Bad syntax-no closing tag
                            if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                            {
                                do
                                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr))
                                        {*successFlag = 0; return buffParams;}
                                while (strlen(buff_it) == 0);
                                loc = 0;
                                SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
                                loc = -1;   // Restarts loc to 0 after break;
                                continue;
                            }

                            if (buff_it[loc] == '{')                                    // Body detected
                            {
                                openBodyFound = true;
                                ++loc;
                                SkipSpacingsFront(buff_it + loc, MAX_RECORD_LENGTH - loc, &loc);   // Skip body spacings
                                if (loc >= MAX_RECORD_LENGTH || buff_it[loc] == '\r' || buff_it[loc] == '\n')    // If end line -> load new line
                                {
                                    if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *successFlag = 0; return buffParams; }
                                    loc = 0;
                                    SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH - loc, &loc);
                                    loc = -1;   // Restarts loc to 0 after break;
                                    continue;
                                }
                            }

                            if (openBodyFound)                                                       //Seek body start
                            {
                                bool openTagFound = false, closedTagFound = false;
                                int findedAtLine = -1, totalLinesFromHere = 0;
                                char recordStr[MAX_RECORD_LENGTH];
                                for (int lineLoc = loc; lineLoc < MAX_RECORD_LENGTH; ++lineLoc)  // Continue searching in same line
                                {
                                    if (lineLoc >= MAX_RECORD_LENGTH || buff_it[lineLoc] == '\r' || buff_it[lineLoc] == '\n')    // If end line -> load new line
                                    {
                                        if (openTagFound && !closedTagFound && findedAtLine == totalLinesFromHere)
                                        {
                                            memset(recordStr, 0, MAX_RECORD_LENGTH);
                                            memcpy(recordStr, buff_it + lineLoc, MAX_RECORD_LENGTH - lineLoc);
                                        }

                                        do
                                        {
                                            if (!fgets(buff_it, MAX_RECORD_LENGTH, fptr)) { *successFlag = 0; return buffParams; }
                                            else { lineLoc = 0; ++totalLinesFromHere; SkipSpacingsFront(buff_it, MAX_RECORD_LENGTH, &lineLoc); buff_it += lineLoc; }
                                        } while (lineLoc == MAX_RECORD_LENGTH);

                                        lineLoc = -1;
                                        continue;
                                    }

                                    if (buff_it[lineLoc] == '$')   // Delimiter found
                                    {
                                        if (!openBodyFound && !openTagFound) { openTagFound = true; start = lineLoc; ++lineLoc; findedAtLine = totalLinesFromHere; }
                                        else if (openBodyFound && !closedTagFound) { closedTagFound = true; stop = lineLoc; ++lineLoc; }

                                        if (openBodyFound && closedTagFound)
                                        {
                                            if (lineLoc > 0)
                                            {
                                                memcpy(buff_it, buff_it + lineLoc - 1, MAX_RECORD_LENGTH - lineLoc);
                                                buff_it[MAX_RECORD_LENGTH - lineLoc] = '\0';
                                            }

                                            switch (ParseBUFFDefRecord(buff_it, strlen(buff_it), &buffParams, &lineLoc))
                                            {
                                                case  INBUF: 
                                                    { defsFound[INBUF] = 1; break; }
                                                case  ACKBUF: 
                                                    {defsFound[ACKBUF] = 1; break; }
                                                case  INBUF_SRV: 
                                                    {defsFound[INBUF_SRV] = 1; break; }
                                                case  OUTBUF_SRV: 
                                                    {defsFound[OUTBUF_SRV] = 1; break; }
                                                case  UNKNOWN: 
                                                    { *successFlag = 0; return buffParams; }
                                            }
                                                                                        
                                            ++lineLoc;
                                            openTagFound = false;
                                            closedTagFound = false;
                                            continue;
                                        }
                                    }
                                    else if (buff_it[lineLoc] == '}')
                                    {
                                        clsIdx = lineLoc + 2;     // Skip }%
                                        seekProto = true;
                                        break;
                                    }
                                }

                                if (openBodyFound == true) { *successFlag = 0; return buffParams; }    // No } closure
                                if (seekProto) break;   // Brake
                            }
                        }
                       
                    }
                }
            }
        }

        *successFlag = defsFound[INBUF] && defsFound[ACKBUF] && defsFound[INBUF_SRV] && defsFound[OUTBUF_SRV];
        return buffParams;
	}
#pragma endregion

// Parsiranje fajla koji odredjuje duzine bafera