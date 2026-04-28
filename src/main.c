#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "packet.h"
#include "security.h"
#include "jsonparser.h"

#define MAX_ITENS 4 
#define MAX_SIZE 64

int curr_index = 0;
char tempo[80];

char *get_time() {
    time_t timer;
    time(&timer);
    struct tm *tm_info = localtime(&timer);
    strftime(tempo, sizeof(tempo), "%Y-%m-%dT%H:%M:%S", tm_info);
    return tempo;
}

void fill_physical_layer(struct ethhdr* phys_lyr, InternetPacket *packetNode) {
    char buffer[256];
    //MAC Destino
    snprintf(buffer,256,"%02x:%02x:%02x:%02x:%02x:%02x",phys_lyr->h_dest[0],phys_lyr->h_dest[1],phys_lyr->h_dest[2],phys_lyr->h_dest[3],phys_lyr->h_dest[4],phys_lyr->h_dest[5]);
    strncpy(packetNode->mac_destino,buffer,MAX_SIZE);
    packetNode->mac_destino[MAX_SIZE - 1] = '\0';

    //MAC Origem
    snprintf(buffer,256,"%02x:%02x:%02x:%02x:%02x:%02x",phys_lyr->h_source[0],phys_lyr->h_source[1],phys_lyr->h_source[2],phys_lyr->h_source[3],phys_lyr->h_source[4],phys_lyr->h_source[5]);
    strncpy(packetNode->mac_origem,buffer,MAX_SIZE);
    packetNode->mac_origem[MAX_SIZE - 1] = '\0';

    switch (ntohs(phys_lyr->h_proto)){
        case 0x0800:
            strcpy(packetNode->protocolo_ip, "IPV4");
        break;

    case 0x86DD:
            strcpy(packetNode->protocolo_ip, "IPV6");
        break;

    case 0x0806:
            strcpy(packetNode->protocolo_ip, "ARP");
        break;

    default:
            strcpy(packetNode->protocolo_ip, "Unknown");
        break;
    }
}

void fill_ip_layer(struct iphdr* ip_lyr, InternetPacket *packetNode) {
    char buffer[256];
    inet_ntop(AF_INET, &ip_lyr->daddr, buffer, 256);
    strncpy(packetNode->ip_destino,buffer,MAX_SIZE);

    inet_ntop(AF_INET, &ip_lyr->saddr, buffer, 256);
    strncpy(packetNode->ip_origem,buffer,MAX_SIZE);

    switch (ip_lyr->protocol){
    case 6: // TCP
            strcpy(packetNode->protocolo_transporte, "TCP");
        break;
    case 17: // UDP
            strcpy(packetNode->protocolo_transporte, "UDP");
        break;
    default: // N protocolo
            strcpy(packetNode->protocolo_transporte, "Unknown");
        break;
    }

    packetNode->tempo_vida = ip_lyr->ttl;
    packetNode->ip_header_lenght = ip_lyr->ihl*4;
    packetNode->tamanho_total_packet = ntohs(ip_lyr->tot_len);
}

void fill_ip6_layer(struct ip6_hdr* ip_lyr, InternetPacket *packetNode) {
    char buffer[256];
    inet_ntop(AF_INET6, &ip_lyr->ip6_dst, buffer, 256);
    strncpy(packetNode->ip_destino,buffer,MAX_SIZE);

    inet_ntop(AF_INET6, &ip_lyr->ip6_src, buffer, 256);
    strncpy(packetNode->ip_origem,buffer,MAX_SIZE);

    switch (ip_lyr->ip6_ctlun.ip6_un1.ip6_un1_nxt){
        case 6: // TCP
            strcpy(packetNode->protocolo_transporte, "TCP");
        break;
    case 17: // UDP
            strcpy(packetNode->protocolo_transporte, "UDP");
        break;
    default: // N protocolo
            strcpy(packetNode->protocolo_transporte, "Unknown");
        break;
    }
    
    packetNode->tempo_vida = ip_lyr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
    packetNode->ip_header_lenght = 40;
    packetNode->tamanho_total_packet = ntohs(ip_lyr->ip6_ctlun.ip6_un1.ip6_un1_plen) + 40;
}

void fill_tcp_layer(struct tcphdr* trsprt_lyr, InternetPacket *packetNode){
    snprintf(packetNode->porta_destino, MAX_SIZE, "%u", ntohs(trsprt_lyr->dest));
    snprintf(packetNode->porta_origem, MAX_SIZE, "%u", ntohs(trsprt_lyr->source));
    packetNode->seq = ntohl(trsprt_lyr->seq);
    packetNode->ack_seq = ntohl(trsprt_lyr->ack_seq);
    packetNode->ack = (trsprt_lyr->ack) ? 1 : 0;
    packetNode->rst = (trsprt_lyr->rst) ? 1 : 0;
    packetNode->psh = (trsprt_lyr->psh) ? 1 : 0;
    packetNode->urg = (trsprt_lyr->urg) ? 1 : 0;
    packetNode->fin = (trsprt_lyr->fin) ? 1 : 0;
    packetNode->syn = (trsprt_lyr->syn) ? 1 : 0;
    strcpy(packetNode->timestamp, get_time());
}

void fill_udp_layer(struct udphdr* trsprt_lyr, InternetPacket *packetNode){
    snprintf(packetNode->porta_destino, MAX_SIZE, "%u", ntohs(trsprt_lyr->dest));
    snprintf(packetNode->porta_origem, MAX_SIZE, "%u", ntohs(trsprt_lyr->source));
    strcpy(packetNode->timestamp, get_time());
    packetNode->seq = 0;
    packetNode->ack=0;
    packetNode->ack_seq = 0;
    packetNode->rst=0;
    packetNode->psh=0;
    packetNode->urg=0;
    packetNode->fin=0;
    packetNode->syn=0;
}

void fill_unkownTransport_layer(InternetPacket *packetNode){
    strcpy(packetNode->porta_origem, "Null");
    strcpy(packetNode->porta_destino, "Null");
    strcpy(packetNode->timestamp, get_time());
    packetNode->seq = 0;
    packetNode->ack=0;
    packetNode->ack_seq = 0;
    packetNode->rst=0;
    packetNode->psh=0;
    packetNode->urg=0;
    packetNode->fin=0;
    packetNode->syn=0;
}

InternetPacket* fill_fullPacket_node(unsigned char *buffer) {
    InternetPacket *packetNode = malloc(sizeof(InternetPacket));
    struct ethhdr *phys_layer = (struct ethhdr*) buffer;
    fill_physical_layer(phys_layer, packetNode);
    if (strcmp(packetNode->protocolo_ip, "IPV4") == 0){
        // IPV4
        struct iphdr  *ip_layer = (struct iphdr*) (buffer + 14); 
        fill_ip_layer(ip_layer, packetNode);
        if (ip_layer->protocol == 6){
            // TCP
            struct tcphdr *transport_layer = (struct tcphdr*) (buffer + 14 +  (ip_layer->ihl * 4));
            fill_tcp_layer(transport_layer, packetNode);
        }
        else if (ip_layer->protocol == 17){
            // UDP
            struct udphdr *transport_layer = (struct udphdr*) (buffer + 14 +  (ip_layer->ihl * 4));
            fill_udp_layer(transport_layer, packetNode);
        }
        else{
            // N protocol
            fill_unkownTransport_layer(packetNode);
        }
    }
    else if (strcmp(packetNode->protocolo_ip, "IPV6") == 0){
        // IPV6
        struct ip6_hdr *ip_layer = (struct ip6_hdr*) (buffer + 14); 
        fill_ip6_layer(ip_layer, packetNode);
        if (ip_layer->ip6_nxt == 6){
            // TCP
            struct tcphdr *transport_layer = (struct tcphdr*) (buffer + 54);
            fill_tcp_layer(transport_layer, packetNode);
        }
        else if (ip_layer->ip6_nxt == 17){
            // UDP
            struct udphdr *transport_layer = (struct udphdr*) (buffer + 54);
            fill_udp_layer(transport_layer, packetNode);
        }
        else{
            // N protocol
            fill_unkownTransport_layer(packetNode);
        }
    }
    else if (strcmp(packetNode->protocolo_ip, "ARP") == 0){
        // ARP (MAC mapping packet)
        strcpy(packetNode->ip_origem, "Null");
        strcpy(packetNode->ip_destino, "Null");
        strcpy(packetNode->protocolo_transporte, "Null");

        strcpy(packetNode->porta_origem, "Null");
        strcpy(packetNode->porta_destino, "Null");

        strcpy(packetNode->timestamp,get_time());

        packetNode->ip_header_lenght = 0;
        packetNode->tempo_vida=0;
    }
    else {
        // not recognized internet protocol
    }
    return packetNode;
}

int main(){
    char *json_payload = malloc(sizeof(char) * MAX_JSON_SIZE);
    unsigned char buffer[65535];
    PacketList *inicio = NULL;
    PacketList *final = NULL;
    file_greeter();
    int socketfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (socketfd < 0) {
        perror("socket");
        return 1;
    }
    while(1){
        if (recvfrom(socketfd,buffer,sizeof(buffer),0,NULL,NULL)>0){
            InternetPacket *packetNode = fill_fullPacket_node(buffer);
            insert_packet_node_on_list(&inicio, &final, &packetNode);            
            curr_index++;
        }
        if(curr_index == MAX_ITENS) break;
    }
    generate_json_payload(inicio, &json_payload);
    printf("%s", json_payload);
    free_list(&inicio);
    close(socketfd);
    return 0;
}
