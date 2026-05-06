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
        /*
                    case 1:
                cond_break_loop=0;
                node->protocolo_transporte = 1;//"ICMP";    
                break;
        
            case 5:
                cond_break_loop=0;
                node->protocolo_transporte = 5;//"STREA");
                break;
            case 6:
                cond_break_loop=0;
                node->protocolo_transporte = 6;//"TCP")
                break;
            case 17:
                cond_break_loop=0;
                node->protocolo_transporte = 17;//"UDP")
                break;
            case 58 icmpv6
        */
        FullInternetPacket *pkt = (inicio)->packet;
        memset(temporary_buffer, 0, 2048);
        snprintf(temporary_buffer, 2048,
            "    {\n"
            "      \"timestamp\": \"%s\",\n"         
            "      \"mac_origem\": \"%s\",\n"
            "      \"mac_destino\": \"%s\",\n"
            "      \"protocolo_ip\": \"%s\",\n"
            "      \"ip_origem\": \"%s\",\n"
            "      \"ip_destino\": \"%s\",\n"
            "      \"tempo_vida\": %d, \n"
            "      \"ip_header_length\": %d,\n"
            "      \"tamanho_total_packet\": %d,\n"
            "      \"porta_origem\": %d,\n"
            "      \"porta_destino\": %d,\n"
            "      \"tcp_seq\": %ld,\n"
            "      \"tcp_ack_seq\": %ld,\n",
    
            // camada física
            pkt->timestamp,
            pkt->mac_origem,
            pkt->mac_destino,
            pkt->protocolo_ip,
    
            // camada IP
            pkt->ip_origem,
            pkt->ip_destino,
            pkt->tempo_vida,
            pkt->ip_header_lenght,
            pkt->tamanho_total_packet,
    
            // transporte
            pkt->porta_origem,
            pkt->porta_destino,
            pkt->tcp_seq,
            pkt->tcp_ack_seq
        );    
        (pkt->tcp_ack)? strcat(temporary_buffer, "      \"tcp_ack\": true,\n") : strcat(temporary_buffer, "      \"tcp_ack\": false,\n" );
        (pkt->tcp_fin)? strcat(temporary_buffer, "      \"tcp_fin\": true,\n") : strcat(temporary_buffer, "      \"tcp_fin\": false,\n" );
        (pkt->tcp_syn)? strcat(temporary_buffer, "      \"tcp_syn\": true,\n") : strcat(temporary_buffer, "      \"tcp_syn\": false,\n" );
        (pkt->tcp_rst)? strcat(temporary_buffer, "      \"tcp_rst\": true,\n") : strcat(temporary_buffer, "      \"tcp_rst\": false,\n" );
        (pkt->tcp_psh)? strcat(temporary_buffer, "      \"tcp_psh\": true,\n") : strcat(temporary_buffer, "      \"tcp_psh\": false,\n" );
        (pkt->tcp_urg)? strcat(temporary_buffer, "      \"tcp_urg\": true,\n") : strcat(temporary_buffer, "      \"tcp_urg\": false,\n" );
        (pkt->tcp_cwr)? strcat(temporary_buffer, "      \"tcp_cwr\": true,\n") : strcat(temporary_buffer, "      \"tcp_cwr\": false,\n" );
        (pkt->tcp_ece)? strcat(temporary_buffer, "      \"tcp_ece\": true,\n") : strcat(temporary_buffer, "      \"tcp_ece\": false,\n" );
        
        switch (pkt->protocolo_transporte)//
        {
        case 1:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"ICMP\"\n");
            break;
        
        case 5:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"STREAM\"\n");
            break;
        
        case 6:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"TCP\"\n");
            break;
        
        case 17:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"UDP\"\n");
            break;
        
        case 58:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"ICMPv6\"\n");
            break;
        
        case -1:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"Unkown/None\"\n");
            break;
        
        default:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"Unkown/None\"\n");
            break;
        }                
        strcat(temporary_buffer, "    }");
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
        "POST /ingest HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "User-Agent: WireSentinel-Agent/1.0\r\n\r\n",
        host, content_length);
}
void generate_request(char* host, char* json_payload, char* buffer[]){
    char *header = malloc(sizeof(char)*2048);
    generate_json_header(host, strlen(json_payload), &header);
    snprintf(*buffer, MAX_JSON_SIZE, "%s%s", header, json_payload);
    free(header);
}