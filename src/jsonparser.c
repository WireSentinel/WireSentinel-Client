#include "jsonparser.h"
#include "packet.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>



void generate_json_payload(PacketList *original_inicio, char *buffer[]) {
    PacketList *inicio = original_inicio;
    char temporary_buffer[2048];
    memset(*buffer, 0, MAX_JSON_SIZE);
    strcat(*buffer, 
            "{\n"
            "  \"packets\": [\n");
    while (inicio!=NULL){
        InternetPacket *pkt = (inicio)->packet;
        memset(temporary_buffer, 0, 2048);
        snprintf(temporary_buffer, 2048,
            "    {\n"
            "      \"mac_origem\": \"%s\",\n"
            "      \"mac_destino\": \"%s\",\n"
            "      \"protocolo_ip\": \"%s\",\n"
            "      \"ip_origem\": \"%s\",\n"
            "      \"ip_destino\": \"%s\",\n"
            "      \"protocolo_transporte\": \"%s\",\n"
            "      \"tempo_vida\": %d, \n"
            "      \"ip_header_length\": %d,\n"
            "      \"tamanho_total_packet\": %d,\n"
            "      \"porta_origem\": %s,\n"
            "      \"porta_destino\": %s,\n"
            "      \"seq\": %ld,\n"
            "      \"ack_seq\": %ld,\n"
            "      \"ack\": %d,\n"
            "      \"fin\": %d,\n"
            "      \"syn\": %d,\n"
            "      \"rst\": %d,\n"
            "      \"psh\": %d,\n"
            "      \"urg\": %d,\n"
            "      \"timestamp\": \"%s\"\n"
            "    }",
    
            // camada física
            pkt->mac_origem,
            pkt->mac_destino,
            pkt->protocolo_ip,
    
            // camada IP
            pkt->ip_origem,
            pkt->ip_destino,
            pkt->protocolo_transporte,
            pkt->tempo_vida,
            pkt->ip_header_lenght,
            pkt->tamanho_total_packet,
    
            // transporte
            pkt->porta_origem,
            pkt->porta_destino,
            pkt->seq,
            pkt->ack_seq,
            pkt->ack,
            pkt->fin,
            pkt->syn,
            pkt->rst,
            pkt->psh,
            pkt->urg,
    
            // metadata
            pkt->timestamp
        );
        inicio = (inicio)->next;
        if (inicio != NULL){
            strcat(temporary_buffer, ",\n");
        }
        strcat(*buffer, temporary_buffer);
    }
    strcat(*buffer, 
            "\n  ]\n"
            "}\n");
        
}
void generate_json_header(char* host, long int content_length, char* buffer[]){
    snprintf(*buffer, 2048,
        "POST /ingest HTTP/1.1\n"
        "Host: %s\n"
        "Content-Type: application/json\n"
        "Content-Length: %ld\n"
        "User-Agent: WireSentinel-Agent/1.0\n\n",
        host, content_length);
}
void generate_request(char* host, char* json_payload, char* buffer[]){
    char *header = malloc(sizeof(char)*2048);
    generate_json_header(host, strlen(json_payload), &header);
    snprintf(*buffer, MAX_JSON_SIZE, "%s%s", header, json_payload);
    free(header);
}