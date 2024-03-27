#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

# define ETH_HDR_LEN 14
# define ARP_PKT_LEN 28
# define MACADDR_LEN 6
# define IP_LENGTH 4

typedef struct{
    uint8_t targetMac[MACADDR_LEN];
    uint8_t senderMac[MACADDR_LEN];
    uint16_t etherType;
}eth_header_t;

typedef struct{
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareLen;
    uint16_t opcode;
    uint8_t sender_mac[MACADDR_LEN];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[MACADDR_LEN];
    uint8_t target_ip[IP_LENGTH];
    uint8_t protocol_len;
}arp_packet_t;

#endif // PACKET_H