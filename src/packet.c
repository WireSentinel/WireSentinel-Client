#include <stdio.h>
#include <stdlib.h>
#include "packet.h"

void insert_packet_node_on_list(PacketList **inicio, PacketList **final, FullInternetPacket **pkt){
    PacketList *new_node = (PacketList*)malloc(sizeof(PacketList));
    new_node->packet = *pkt;
    new_node->next = NULL;
    if (*inicio == NULL){
        *inicio = new_node;
        *final = new_node; 
    }
    else{
        (*final)->next = new_node;
        *final = new_node; 
    }
}

void free_list(PacketList **inicio){
    while (*inicio!=NULL){
        PacketList *temp = *inicio;
        *inicio = (*inicio)->next;
        //free(temp->packet);
        free(temp);
    }
}

