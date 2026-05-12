#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#include "buffer_list.h"
#include "misc.h"
#include "packet_service.h"
#include "packet_list.h"
#include "security.h"
#include <pthread.h>
#include "jsonparser.h"

#define MAX_ITENS 400
#define MAX_SIZE 64

pthread_mutex_t mutex_processing;
pthread_mutex_t mutex_payload;

pthread_cond_t cond_processing;
pthread_cond_t cond_payload;
int test = 0;
int nmbr_itens = 0;
int nmbr_packets = 0;
char tempo[MAX_SIZE];
#include <signal.h>

Buffer_List *inicio_buffer = NULL;
Buffer_List *final_buffer = NULL;

PacketList *inicio_packet = NULL;
PacketList *final_packet = NULL;

void *routine_processing(void*arg) {
    (void) arg;
    while (1){
        pthread_mutex_lock(&mutex_processing);
        while (nmbr_itens == 0) {
            pthread_cond_wait(&cond_processing,&mutex_processing);
        }
        Buffer_List *temp = inicio_buffer;
        inicio_buffer = inicio_buffer->next;
        FullInternetPacket *node = fill_fullPacket_node(temp->content,temp->recvlen);
        if (node == NULL) {
            free_item(&temp, &nmbr_itens);
            pthread_mutex_unlock(&mutex_processing);
        }
        else if (strcmp(node->mac_destino, "00:00:00:00:00:00") == 0 || strcmp(node->mac_origem, "00:00:00:00:00:00") == 0) {
            free(node);
            free_item(&temp, &nmbr_itens);
            pthread_mutex_unlock(&mutex_processing);
        }
        else {
            node->tamanho_total_packet = temp->recvlen;
            insert_packet_node_on_list(&inicio_packet,&final_packet, &node,&nmbr_packets);
            free_item(&temp, &nmbr_itens);
            test ++;
            pthread_mutex_unlock(&mutex_processing);
        }
    }
}

void start_server(int * socketfd, struct addrinfo *socketConfig, struct addrinfo ** socketList, char *address, char *port) {
    memset(socketConfig, 0, sizeof(*socketConfig));
    socketConfig->ai_family = AF_INET;
    socketConfig->ai_socktype = SOCK_STREAM;
    socketConfig->ai_flags = AI_PASSIVE;
    char time[MAX_SIZE];
    getaddrinfo(address, port, socketConfig, socketList);
    *socketfd   = socket((*socketList)->ai_family,(*socketList)->ai_socktype,(*socketList)->ai_protocol);
    while (connect(*socketfd, (*socketList)->ai_addr, (*socketList)->ai_addrlen) != 0){
        *socketfd = socket((*socketList)->ai_family,(*socketList)->ai_socktype,(*socketList)->ai_protocol);
        get_time(time, MAX_SIZE);
        printf("[%s] Falha ao conectar com o servidor (> %s:%s <), tentando novamente em 5 segundos...\n",time, address, port);
        sleep(5);
    }
    //get_time_ptr(&time);
    get_time(time, MAX_SIZE);
    printf("[%s] Conectado com o servidor (> %s:%s <) iniciando transmissão de dados...\n", time, address, port);

}
void *routine_payload(void*arg) {
    (void) arg;
    char *addr, *prt, urlbuffer[2048];

    get_file_url(&addr);
    get_file_prt(&prt);
    snprintf(urlbuffer, 2048, "%s:%s", addr, prt);
    int socketfd_server;
    struct addrinfo socketConfig;
    struct addrinfo *socketList;
    start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
    while (1){
        pthread_mutex_lock(&mutex_processing);
        while (inicio_packet==NULL) {
            pthread_cond_wait(&cond_payload,&mutex_processing);
        }
        char *json_payload = malloc(sizeof(char) * MAX_JSON_SIZE);
        char *json_request = malloc(sizeof(char) * MAX_JSON_SIZE);

        generate_json_payload(inicio_packet, &json_payload);
        free_list(&inicio_packet, &nmbr_packets);
        inicio_packet = NULL;
        final_packet = NULL;
        pthread_mutex_unlock(&mutex_processing);

        generate_request(urlbuffer, json_payload, &json_request);

        ssize_t result = send(socketfd_server, json_request, strlen(json_request), 0);
        while (result == -1) {
            close(socketfd_server);
            start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
            result = send(socketfd_server, json_request, strlen(json_request), 0);
        }
        char time[MAX_SIZE];
        get_time(time, MAX_SIZE);
        printf("[%s] Envio da requisicao ao servidor completo! Aguardando proximo payload...\n",time);

        //recv(socketfd_server, NULL, 0, 0);
        free(json_payload);
        free(json_request);
        //json_payload = NULL;
        //json_request = NULL;
        //close(socketfd_server);
    }
}

int main(){

    unsigned char buffer[65535];
    signal(SIGPIPE, SIG_IGN);
    pthread_mutex_init(&mutex_processing, NULL);
    pthread_cond_init(&cond_processing, NULL);

    pthread_mutex_init(&mutex_payload, NULL);
    pthread_cond_init(&cond_payload, NULL);

    file_greeter();

    pthread_t processing, payload;
    pthread_create(&processing, NULL, routine_processing,NULL);
    pthread_create(&payload, NULL, routine_payload,NULL);
    int socketfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (socketfd < 0) {
        perror("socket");
        return 1;
    }
    long int bytes_recived;
    long int secs = time(NULL);
    long int currsecs;
    while(1){
        bytes_recived = recvfrom(socketfd, buffer, sizeof(buffer), 0,NULL,NULL);
        currsecs = time(NULL);
        if (bytes_recived>0) {
            //FullInternetPacket *packetNode = fill_fullPacket_node(buffer);
            pthread_mutex_lock(&mutex_processing);
            add_item(&nmbr_itens,buffer,&inicio_buffer, &final_buffer,bytes_recived);
            //printf("iten quantity: %d\n", nmbr_itens);
            pthread_mutex_unlock(&mutex_processing);
            pthread_cond_signal(&cond_processing);

        }
        if (test >= 2000 || (currsecs - secs) >= 4 ) {
            pthread_mutex_lock(&mutex_processing);
            test = 0;
            pthread_mutex_unlock(&mutex_processing);
            //printf("iten quantity: %d\n", nmbr_itens);
            pthread_cond_signal(&cond_payload);
            secs = time(NULL);
        }
    }
    //generate_json_payload(inicio_packet, &json_payload);
    // generate_json_payload(inicio, &json_payload);
    //printf("%s", json_payload);
    // char*addr, *prt, urlbuffer[2048];
    // get_file_url(&addr);
    // get_file_prt(&prt);
    // snprintf(urlbuffer, 2048, "%s:%s", addr, prt);
    // generate_request(urlbuffer, json_payload, &json_request);
    // send(socketfd_server, json_request, strlen(json_request), 0);
    // //getchar();
    // close(socketfd);
    // free_list(&inicio_packet);
    // free(json_payload);
    // //return 0;
}
