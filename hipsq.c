/* [H]iding [I]n [P]lain [S]ight with [Q]uic
*  hipsq.c
*  hipsq common functionality 
*
* Copyright 2024 Srdjan Rajcevic [www.sectreme.com]
* Parts of code Copyright (c) Microsoft Corporation.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
* associated documentation files (the “Software”), to deal in the Software without restriction, including 
* without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
* copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the 
* following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial 
* portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
* LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO 
* EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
* IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
* THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define CMD_PATH "C:\\Windows\\System32\\cmd.exe"

#include "hipsq.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOLEAN exec(char* cmd) 
{
    char *cmdLine = malloc(3 + strlen(cmd));
    strncpy(cmdLine, "/c ", 3);
    strncpy(cmdLine+3, cmd, strlen(cmd));

    STARTUPINFO startInf;
    memset( &startInf, 0, sizeof startInf );
    startInf.cb = sizeof(startInf);

    PROCESS_INFORMATION procInf;
    memset( &procInf, 0, sizeof procInf );
    if (!CreateProcess(CMD_PATH, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &startInf, &procInf ))
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return FALSE;
    }
    CloseHandle(procInf.hProcess);
    free(cmdLine);
    return TRUE;
}

char* getCmdLine(char* cmd)
{
    char *token = strtok(cmd, " ");
    token = strtok(NULL, " ");
    return token;
}
