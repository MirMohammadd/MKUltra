#ifndef __DHCP_H
#define __DHCP_H

#include <stdint.h>
#include <netinet/in.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363

struct dhcp_packet {
    uint8_t op;           // Message type: 1=request, 2=reply
    uint8_t htype;        // Hardware address type
    uint8_t hlen;         // Hardware address length
    uint8_t hops;         // Number of hops
    uint32_t xid;         // Transaction ID
    uint16_t secs;        // Seconds elapsed
    uint16_t flags;       // Flags
    struct in_addr ciaddr; // Client IP address
    struct in_addr yiaddr; // Your IP address (server responds with this)
    struct in_addr siaddr; // Server IP address
    struct in_addr giaddr; // Gateway IP address
    uint8_t chaddr[16];   // Client hardware address
    uint8_t sname[64];    // Optional server host name
    uint8_t file[128];    // Boot file name
    uint32_t magic_cookie; // Magic cookie
    uint8_t options[312]; // Options
};

#endif