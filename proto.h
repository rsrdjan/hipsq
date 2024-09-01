/* [H]iding [I]n [P]lain [S]ight with [Q]uic
*  proto.h
*  hipsq protocol declarations
*
* Copyright 2024 Srdjan Rajcevic [www.sectreme.com]
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

#ifndef _PROTO_H
#define _PROTO_H

#include "msquic.h"
#define MAX_HEADER_SIZE 8
#define MAX_PAYLOAD_SIZE 1025
#define MAX_MSG_SIZE 1033
#define HIPSQ_PROTO_ID "hipsq"

typedef enum HIPSQ_PAYLOAD_ID{
    HIPSQ_PAYLOAD_ID_INIT = 0x0,        // Init connection (beacon for now)
    HIPSQ_PAYLOAD_ID_EXIT = 0x1,        // Close connection
    HIPSQ_PAYLOAD_ID_EXEC = 0x2,        // Execute command
    HIPSQ_PAYLOAD_ID_SEND = 0x3,        // Send file
    HIPSQ_PAYLOAD_ID_RECV = 0x4,        // Receive file
    HIPSQ_PAYLOAD_ID_BCN = 0x5,         // Beacon (TODO)
    HIPSQ_PAYLOAD_ID_OK = 0x6,          // Success
    HIPSQ_PAYLOAD_ID_ERR = 0x7,         // Error
}HIPSQ_PAYLOAD_ID;


typedef struct hipsq_msg {
    uint8_t msg_size;                   // Size of the message (calculate at the end)
    char* proto_id;                     // Id of the protocol - can change in future versions
    uint8_t payload_id;                 // Id of the payload - indicates command
    char* payload;                      // Payload
}hipsq_msg;

char* pack_raw(hipsq_msg*, size_t*);    // Pack message as byte stream
int unpack_raw(char*, hipsq_msg*);      // Unpack message from byte stream
#endif