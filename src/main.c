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
#include "misc.h"
#include "packet_service.h"
#include "server.h"
#include "packet.h"
#include "security.h"
#include "jsonparser.h"

#define MAX_ITENS 10
#define MAX_SIZE 64

int curr_index = 0;
char tempo[MAX_SIZE];



int main(){
    char *json_payload = malloc(sizeof(char) * MAX_JSON_SIZE);
    char *json_request = malloc(sizeof(char) * MAX_JSON_SIZE);
    unsigned char buffer[65535];
    PacketList *inicio = NULL;
    PacketList *final = NULL;
    file_greeter();
    int socketfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    int socketfd_server;
    start_server(&socketfd_server);
    if (socketfd < 0) {
        perror("socket");
        return 1;
    }
    while(1){
        if (recvfrom(socketfd,buffer,sizeof(buffer),0,NULL,NULL)>0){
            FullInternetPacket *packetNode = fill_fullPacket_node(buffer);
            insert_packet_node_on_list(&inicio, &final, &packetNode);            
            curr_index++;
        }
        if(curr_index == MAX_ITENS) break;
    }
    generate_json_payload(inicio, &json_payload);
    //printf("%s", json_payload);
    char*addr, *prt, urlbuffer[2048];
    get_file_url(&addr);
    get_file_prt(&prt);
    snprintf(urlbuffer, 2048, "%s:%s", addr, prt);
    generate_request(urlbuffer, json_payload, &json_request);
    send(socketfd_server, json_request, strlen(json_request), 0);
    free_list(&inicio);
    close(socketfd);
    return 0;
}
