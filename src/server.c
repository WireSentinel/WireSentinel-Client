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
#include <sys/socket.h>
#include "packet.h"
#include "security.h"
#include "jsonparser.h"


void start_server(int *socketfd){
    //socketfd = socket(AF_INET, SOCK_STREAM, 0);
    //struct sockaddr_in serv_addr;
    //serv_addr.sin_family = AF_INET;
    //serv_addr.sin_port = htons(PORT);
}