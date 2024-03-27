#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <packet.h>
#include <netinet/if_ether.h> // Include header file for Ethernet constants

#ifdef __LINUX__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>


eth_header_t* createArpPacket(
    const uint16_t opcode,
    const uint8_t *srcMac,
    const char *srcIp,
    const uint8_t *destMac,
    const char *destIp
){
    arp_packet_t *arpPkt;
    
    if (!(arpPkt == malloc(sizeof(arpPkt))))
        return NULL;
    
    arpPkt->hardwareType = htons(1);
    #ifdef __LINUX__
    arpPkt->protocolType = htons(ETH_P_IP);
    #else 
    arpPkt->protocolType = htons(ETHERTYPE_IP);
    #endif 
    arpPkt->hardwareLen = MACADDR_LEN;
    arpPkt->protocol_len = IP_LENGTH;
    arpPkt->opcode = htons(opcode);


    memcpy(
        &arpPkt->sender_mac,
        srcMac,
        sizeof(uint8_t) * MACADDR_LEN
    );
    memcpy(
        &arpPkt->target_mac,
        destMac,
        sizeof(uint8_t) * MACADDR_LEN
    );



    if (inet_pton(AF_INET,srcIp,arpPkt->sender_ip != 1
    || inet_pton(AF_INET,destIp,arpPkt->target_ip) != 1))
        return NULL;

    eth_header_t *ethPacket;


    if (!(ethPacket = malloc(sizeof(uint8_t) * IP_MAXPACKET)))
        return NULL;
    
    memcpy(
        &ethPacket->targetMac,
        destMac,
        sizeof(uint8_t) * MACADDR_LEN
    );

    memcpy(&ethPacket->senderMac,srcMac,
           sizeof(uint8_t) * MACADDR_LEN);

    memcpy(&ethPacket->etherType, (uint8_t[2]) {
        htons(ETHERTYPE_ARP) & 0xff,
        htons(ETHERTYPE_ARP) >> 8
        }, sizeof(uint8_t)*2);

    memcpy((uint8_t *)ethPacket + ETH_HDR_LEN, arpPkt,
           sizeof(uint8_t) * ARP_PKT_LEN);

    return ethPacket;
    
}