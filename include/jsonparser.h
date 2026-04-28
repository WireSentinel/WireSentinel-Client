#ifndef JSONPARSER_H
#define JSONPARSER_H
#include "packet.h"
#define MAX_JSON_SIZE (long)(1024*1024*1024)
    void generate_json_payload(PacketList *original_inicio, char *buffer[]);
#endif