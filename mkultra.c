/*
* Created by: Asad Zia
* 
* Description:
* A packet sniffer created using the pcap library. 
* The default setting allows one to read live data from ALL interfaces. The -i option is used to read from a particular interface.
* The -f option is used to read recorded data from a file. The interval for displaying the data can be set by using the -d option.
* The -N option can be used to adjust the number of talkers we want to observe exchanging the packets.
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <hosts.h>
#include <arp.h>
#include <stdbool.h>
#include <dhcp.h>

#define BUFFER_INPUT_SIZE_MAX 100


int main(int argc,char **argv){
    static char broadCastAddr[BUFFER_INPUT_SIZE_MAX];
    static char buffer[BUFFER_INPUT_SIZE_MAX];
    bool arpSpoof = false;
    bool DHCPStarvationFlag = false;
    char* interface = NULL;
    char* sender = NULL;
    char* target = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-arp-spoof") == 0) {
            arpSpoof = true;
        }
        if (strcmp(argv[i], "--interface") == 0) {
            interface = argv[i + 1];
        }
        if (strcmp(argv[i], "--target-ip") == 0) {
            target = argv[i + 1];
        }
        if (strcmp(argv[i], "--sender-ip") == 0) {
            sender = argv[i + 1];
        }
        if (strcmp(argv[i], "--dhcp") == 0) {
            DHCPStarvationFlag = true;
        }
    }

    if (arpSpoof) {
        // Handle ARP Spoofing
    }

    if (DHCPStarvationFlag) {
        getAllInterfaces();
        printf("These are the devices in the network...\n");
        printf("Enter your broadcast address in order to do DHCP starvation:");
        fgets(broadCastAddr, sizeof(broadCastAddr), stdin);
        broadCastAddr[strcspn(broadCastAddr, "\n")] = '\0';
        strncpy(buffer, broadCastAddr, sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        DHCPStarvation(buffer);
    }

    return 0;
}