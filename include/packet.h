
#ifndef PACKET_H
#define PACKET_H
#define MAX_SIZE 64

typedef struct{
    //camada Fisica
    char mac_origem[MAX_SIZE];
    char mac_destino[MAX_SIZE];
    char protocolo_ip[MAX_SIZE]; // ipv4 | ipv6 | arp (n tem checksum)

    //camada IP
    char ip_origem[MAX_SIZE];
    char ip_destino[MAX_SIZE];
    char protocolo_transporte[MAX_SIZE];
    int tempo_vida; // tempo de vida restante do packet, basicamente pra ver quantos roteadores que o pacote passou
    int ip_header_lenght; // ip->ihl*4
    int tamanho_total_packet;      // ip->tot_len
    
    //camada de Transferencia
    char porta_origem[MAX_SIZE];
    char porta_destino[MAX_SIZE];
    long int seq; //TCP Apenas
    long int ack_seq; //TCP Apenas
    // TCP flags (sim,  apenas TCP)
    int ack;
    int fin;
    int syn;
    int rst;
    int psh;
    int urg;
    //

    // metadado
    char timestamp[30];
} InternetPacket;

typedef struct PacketList{
    InternetPacket *packet;
    struct PacketList *next;
} PacketList;

void insert_packet_node_on_list(PacketList **inicio, PacketList **final, InternetPacket **pkt);
void free_list(PacketList **inicio);
#endif