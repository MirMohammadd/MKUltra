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


int main(){
    getAllInterfaces();
    return 0;
}