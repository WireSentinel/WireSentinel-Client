#define _DEFAULT_SOURCE
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include "packet.h"
#include "security.h"
#include "jsonparser.h"
#include "misc.h"

void start_server(int *socketfd){
    struct addrinfo socketConfig;
    memset(&socketConfig, 0, sizeof(socketConfig));
    
    struct addrinfo *socketList;
    int status_init, socket_cliente;
    char *address,*port, time[MAX_SIZE];

    socketConfig.ai_family = AF_INET;
    socketConfig.ai_socktype = SOCK_STREAM;
    socketConfig.ai_flags = AI_PASSIVE;

    get_file_url(&address);
    get_file_prt(&port); 
    status_init = getaddrinfo(address, port, &socketConfig, &socketList);
    *socketfd   = socket(socketList->ai_family,socketList->ai_socktype,socketList->ai_protocol);
    while (connect(*socketfd, socketList->ai_addr, socketList->ai_addrlen) != 0){
        get_time(time, MAX_SIZE);
        printf("[%s] Falha ao conectar com o servidor (> %s:%s <), tentando novamente em 5 segundos...\n",time, address, port);
        sleep(5);
    }
    //get_time_ptr(&time);
    get_time(time, MAX_SIZE);
    printf("[%s] Conectado com o servidor (> %s:%s <) iniciando transmissão de dados...\n", time, address, port);
}

