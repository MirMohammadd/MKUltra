#ifndef SETTINGS_H
#define SETTINGS_H


#include <string.h>
#include <stdint.h>
#include <pcap.h>

char* interface = "any";

int offline = 0;
int interval = 5;           // the interval after which livefeed is displayed
int N = 3;    

char ebuf[PCAP_ERRBUF_SIZE];// the error buffer used in the pcap functions 
pcap_t* descr;              // the descriptor used in the main function

struct store list[1000];    // the list of structs used for storing the configuration of the talkers
int count2 = 0;    


int compare2(const void *a,const void *b){
    return ( ((struct store*)b)->dpacksize - ((struct store*)a)->dpacksize );

}

#endif // SETTINGS_H