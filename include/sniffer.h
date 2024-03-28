#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>

struct store{
    u_char dest[100];
    u_char src[100];
    int dPack;
    int dPackSize;
    int spack;
};


#endif // SNIFFER_H