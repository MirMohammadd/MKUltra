#ifndef __ARP_H
#define __ARP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

#ifdef __APPLE__
#include <net/ethernet.h>
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define BUF_SIZE 42 // Ethernet frame size for ARP request


struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   // Destination MAC address
    unsigned char   h_source[ETH_ALEN]; // Source MAC address
    unsigned short  h_proto;            // Protocol type
};

// ARP header
struct arphdr {
    unsigned short  ar_hrd;             // Hardware type
    unsigned short  ar_pro;             // Protocol type
    unsigned char   ar_hln;             // Hardware address length
    unsigned char   ar_pln;             // Protocol address length
    unsigned short  ar_op;              // Operation code
    unsigned char   ar_sha[ETH_ALEN];   // Sender hardware address
    unsigned char   ar_sip[4];          // Sender IP address
    unsigned char   ar_tha[ETH_ALEN];   // Target hardware address
    unsigned char   ar_tip[4];          // Target IP address
};


int arp_spoof(char* dev, char* sender_ip, char* target_ip);

#endif