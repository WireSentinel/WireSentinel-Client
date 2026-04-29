#ifndef JSONPARSER_H
#define JSONPARSER_H
#include "packet.h"
#define MAX_JSON_SIZE (long)(1024*1024*2)
    void generate_json_payload(PacketList *original_inicio, char *buffer[]);
    void generate_json_header(char* host, long int content_length, char* buffer[]);
    void generate_request(char* host, char* json_payload, char* buffer[]);
#endif