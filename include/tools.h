#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>
#include <pcap.h>

namespace tools {
    void storeIp(char* argv[], int len);
    void getMyInfo(char* dev);

    int makeAndSend(
        pcap_t* fp,
        uint8_t dest_mac[],
        uint8_t src_mac[],
        uint8_t sender_ip[],
        uint8_t target_ip[],
        uint8_t target_mac[],
        uint16_t opcode
    );
}

#endif // TOOLS_H
