
#ifndef PACKET_SERVICE_H
#define PACKET_SERVICE_H
#include "packet.h"
void fill_physical_layer(struct ethhdr* phys_lyr, InternetPacket *packetNode);

void fill_ip_layer(struct iphdr* ip_lyr, InternetPacket *packetNode);

void fill_ip6_layer(struct ip6_hdr* ip_lyr, InternetPacket *packetNode);

void fill_tcp_layer(struct tcphdr* trsprt_lyr, InternetPacket *packetNode);

void fill_udp_layer(struct udphdr* trsprt_lyr, InternetPacket *packetNode);

void fill_unkownTransport_layer(InternetPacket *packetNode);

InternetPacket* fill_fullPacket_node(unsigned char *buffer);

#endif