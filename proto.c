/* [H]iding [I]n [P]lain [S]ight with [Q]uic
*  proto.c
*  hipsq protocol implementation
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

#include "proto.h"
#include <stdlib.h>
#include <stdio.h>

char* pack_raw(hipsq_msg* msg, size_t *msg_size)
{
    unsigned char* cnt;
    size_t header_size, payload_size, size;

    header_size = sizeof(msg->msg_size)
                + strlen(msg->proto_id)+1
                + sizeof(msg->payload_id);

    payload_size = strlen(msg->payload)+1;

    size = header_size + payload_size;
    
    char *raw = malloc(size);
    if (raw == NULL)
        return NULL;
    
    memset(raw,0,size);
    cnt = raw;

    memcpy(cnt, &size, sizeof(msg->msg_size));
    cnt += sizeof(msg->msg_size);
    memcpy(cnt, msg->proto_id, strlen(msg->proto_id));
    cnt += strlen(msg->proto_id);
    memset(cnt, 0x0, sizeof(char));
    cnt += sizeof(char);
    memcpy(cnt, &msg->payload_id, sizeof(msg->payload_id));
    cnt += sizeof(msg->payload_id);
    memcpy(cnt, msg->payload, strlen(msg->payload));
    cnt += strlen(msg->payload);
    memset(cnt, 0x0, sizeof(char));

    if ((header_size > MAX_HEADER_SIZE) ||
        (payload_size > MAX_PAYLOAD_SIZE) ||
        (size > MAX_MSG_SIZE))
        return NULL;

    *msg_size = size;
    return raw;
}

int unpack_raw(char *buffer, hipsq_msg *msg)
{
    char *cnt = buffer;
    memcpy(&msg->msg_size, cnt, sizeof(msg->msg_size));

    size_t size, header_size, payload_size;

    if (msg->msg_size > MAX_MSG_SIZE)
        return 0;

    cnt += sizeof(msg->msg_size);
    char* p_id = malloc(strlen(cnt)+1);
    strncpy(p_id, cnt, strlen(cnt)+1);
    msg->proto_id = p_id;
    cnt += strlen(cnt)+1;
    memcpy(&msg->payload_id, cnt, sizeof(msg->payload_id));
    cnt += sizeof(msg->payload_id);
    char *p = malloc(strlen(cnt)+1);
    strncpy(p, cnt, strlen(cnt)+1);
    msg->payload = p;

    header_size = sizeof(msg->msg_size) + sizeof(msg->payload_id) + strlen(msg->proto_id)+1;
    payload_size = strlen(msg->payload)+1;
    size = header_size + payload_size;

    if ((header_size > MAX_HEADER_SIZE) ||
        (payload_size > MAX_PAYLOAD_SIZE) ||
        (size > MAX_MSG_SIZE))
            return 0;
    
    if (strncmp(msg->proto_id, "hipsq", 5) != 0)
        return 0;

    return 1;
}