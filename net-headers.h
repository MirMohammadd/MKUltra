#include <string.h>

/*
 * structs y funciones para las cabeceras de los distintos protocolos de TCP/IP
 * No es portable, supone:
 * -- little-endian
 * -- sizeof(int) == 4
 * -- sizeof(short) == 2
 */

/*
 * ==============
 * Capa de enlace
 * ==============
 * Ethernet
 */

#define ETHERNET_ADDR_SIZE 6
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_ADDR_STRLEN 18

struct ethernet{
    unsigned char dst_addr[ETHERNET_ADDR_SIZE]; // direccion MAC destino
    unsigned char src_addr[ETHERNET_ADDR_SIZE]; // direccion MAC origen
    unsigned short int type; // que protocolo esta encapsulando
};

#define ETHERNET_TYPE_IPV4 0x0800
#define ETHERNET_NAME_IPV4 "IPv4"
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_NAME_ARP "ARP"

#define ETHERNET_NAME_UNKNOWN "UNKNOWN"

unsigned short int ETHERNET_TYPE_NUMBER_ARRAY[] = {
ETHERNET_TYPE_IPV4,
ETHERNET_TYPE_ARP
};

unsigned char *ETHERNET_TYPE_DESCRIPTION_ARRAY[] = {
ETHERNET_NAME_IPV4,
ETHERNET_NAME_ARP
};

/*
 * Determina el nombre del protocolo que sigue a la trama
 * Ethernet dependiendo del numero ethernet.type
 * Los numeros validos estan en el array ETHERNET_TYPE_NUMBER_ARRAY
 * y el nombre del protocolo en el array ETHERNET_TYP_DESCRIPTION_ARRAY
 * return "UNKNOWN" si el numero es desconocido
 */
unsigned char *ETHERNET_GET_TYPE_NAME(unsigned short int type){
    int i;
    unsigned short int type_hw = ntohs(type);

    for(i = 0; i < sizeof(ETHERNET_TYPE_NUMBER_ARRAY)/sizeof(unsigned short int); i++){
        if(type_hw == ETHERNET_TYPE_NUMBER_ARRAY[i]){
            break;
        } 
    }
    
    if(i == sizeof(ETHERNET_TYPE_NUMBER_ARRAY)/sizeof(unsigned short int)){
        return ETHERNET_NAME_UNKNOWN;
    }

    return ETHERNET_TYPE_DESCRIPTION_ARRAY[i];
}

/*
 * Crea un string con el formato xx:xx:xx:xx:xx:xx
 */
void ETHERNET_ADDR_TO_STR(unsigned char *eth_addr, char *destination){
    int i, cnt;
    cnt = sprintf(destination, "%02x", eth_addr[0]);
    for(i = 1; i < ETHERNET_ADDR_SIZE; i++){
        cnt += sprintf(destination+cnt, ":%02x", eth_addr[i]);
    }
}

/*
 * ARP
 */

struct arp{
    unsigned short int hardware_type;
    unsigned short int protocol_type;
    unsigned char hardware_addr_length;
    unsigned char protocol_addr_length;
    unsigned short int opcode;
    unsigned char sender_hardware_addr[ETHERNET_ADDR_SIZE];
    // por defecto gcc mete aqui padding de 2bytes !
    unsigned int sender_protocol_addr;
    unsigned char target_hardware_addr[ETHERNET_ADDR_SIZE];
    // aqui tambien mete padding de 2bytes !
    unsigned int target_protocol_addr;
} __attribute__((packed)); // decir a gcc que use el minimo de memoria para evitar el padding.

/*
 * ===========
 * Capa de red
 * ===========
 * IP
 */

struct ip{
    unsigned char version_and_ihl;
    unsigned char type_of_service;
    unsigned short int total_length;
    unsigned short int identification;
    unsigned short int flags_and_fragment_offset;
    unsigned char time_to_live;
    unsigned char protocol;
    unsigned short int header_checksum;
    unsigned int src_addr;
    unsigned int dst_addr;
};

#define IP_PROTOCOL_ICMP 0x01
#define IP_PROTNAME_ICMP "ICMP"
#define IP_PROTOCOL_TCP 0x06
#define IP_PROTNAME_TCP "TCP"
#define IP_PROTOCOL_UDP 0x11
#define IP_PROTNAME_UDP "UDP"

#define IP_PROTNAME_UNKNOWN "UNKNOWN"

unsigned char IP_PROTOCOL_NUMBER_ARRAY[] = {
IP_PROTOCOL_ICMP,
IP_PROTOCOL_TCP,
IP_PROTOCOL_UDP
};

unsigned char *IP_PROTOCOL_DESCRIPTION_ARRAY[] = {
IP_PROTNAME_ICMP,
IP_PROTNAME_TCP,
IP_PROTNAME_UDP
};

/*
 * Determina el nombre del protocolo que sigue a la trama
 * IP dependiendo del numero ip.protocol
 * Los numeros validos estan en el array IP_PROTOCOL_NUMBER_ARRAY
 * y el nombre del protocolo en el array IP_PROTOCOL_DESCRIPTION_ARRAY
 * return "UNKNOWN" si el numero es desconocido
 */
unsigned char *IP_GET_PROTOCOL_NAME(unsigned char protocol){
    int i;

    for(i = 0; i < sizeof(IP_PROTOCOL_NUMBER_ARRAY)/sizeof(unsigned char); i++){
        if(protocol == IP_PROTOCOL_NUMBER_ARRAY[i]){
            break;
        } 
    }
    
    if(i == sizeof(IP_PROTOCOL_NUMBER_ARRAY)/sizeof(unsigned char)){
        return IP_PROTNAME_UNKNOWN;
    } 
    return IP_PROTOCOL_DESCRIPTION_ARRAY[i];
} 

unsigned char IP_GET_VERSION(unsigned char version_and_ihl){
    return version_and_ihl >> 4;
}

unsigned char IP_GET_IHL(unsigned char version_and_ihl){
    return version_and_ihl & 0x0F;
}

unsigned char IP_GET_FLAG_RESERVED(unsigned short int flags_and_fragment_offset){
    return (ntohs(flags_and_fragment_offset) >> 15) & 0x01;
}

unsigned char IP_GET_FLAG_DF(unsigned short int flags_and_fragment_offset){
    return (ntohs(flags_and_fragment_offset) >> 14) & 0x01;
}

unsigned char IP_GET_FLAG_MF(unsigned short int flags_and_fragment_offset){
    return (ntohs(flags_and_fragment_offset) >> 13) & 0x01;
}

unsigned short int IP_GET_FRAGMENT_OFFSET(unsigned short int flags_and_fragment_offset){
    return ntohs(flags_and_fragment_offset) & 0x1FFF;
}

void IP_GET_SET_FLAGS(unsigned short int flags_and_fragment_offset, char *destination){
    strcpy(destination, "\0");
    if(IP_GET_FLAG_RESERVED(flags_and_fragment_offset)){
        strcat(destination, "RF ");
    } 
    if(IP_GET_FLAG_DF(flags_and_fragment_offset)){
        strcat(destination, "DF ");
    }
    if(IP_GET_FLAG_MF(flags_and_fragment_offset)){
        strcat(destination, "MF ");
    }
}

/*
 * ICMP
 */

struct icmp{
    unsigned char type;
    unsigned char code;
    unsigned short int checksum;
    unsigned int rest_of_header;
};

/*
 * ==================
 * Capa de transporte
 * ==================
 */

/* TCP */

struct tcp{
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned int seq_number;
    unsigned int ack_number;
    unsigned short int data_offset_and_flags;
    unsigned short int window;
    unsigned short int checksum;
    unsigned short int urgent_pointer;
};

unsigned char TCP_GET_DATA_OFFSET(unsigned short int data_offset_and_flags){
    return ntohs(data_offset_and_flags) >> 12;
}

unsigned char TCP_GET_FLAG_FIN(unsigned short int data_offset_and_flags){
    return ntohs(data_offset_and_flags) & 0x01;
}

unsigned char TCP_GET_FLAG_SYN(unsigned short int data_offset_and_flags){
    return (ntohs(data_offset_and_flags) >> 1) & 0x01;
}

unsigned char TCP_GET_FLAG_RST(unsigned short int data_offset_and_flags){
    return (ntohs(data_offset_and_flags) >> 2) & 0x01;
}

unsigned char TCP_GET_FLAG_PSH(unsigned short int data_offset_and_flags){
    return (ntohs(data_offset_and_flags) >> 3) & 0x01;
}

unsigned char TCP_GET_FLAG_ACK(unsigned short int data_offset_and_flags){
    return (ntohs(data_offset_and_flags) >> 4) & 0x01;
}

unsigned char TCP_GET_FLAG_URG(unsigned short int data_offset_and_flags){
    return (ntohs(data_offset_and_flags) >> 5) & 0x01;
}

void TCP_GET_SET_FLAGS(unsigned short int data_offset_and_flags, char *destination){
    strcpy(destination, "\0");
    if(TCP_GET_FLAG_URG(data_offset_and_flags)){
        strcat(destination, "URG ");
    } 
    if(TCP_GET_FLAG_ACK(data_offset_and_flags)){
        strcat(destination, "ACK ");
    } 
    if(TCP_GET_FLAG_PSH(data_offset_and_flags)){
        strcat(destination, "PSH ");
    } 
    if(TCP_GET_FLAG_RST(data_offset_and_flags)){
        strcat(destination, "RST ");
    } 
    if(TCP_GET_FLAG_SYN(data_offset_and_flags)){
        strcat(destination, "SYN ");
    } 
    if(TCP_GET_FLAG_FIN(data_offset_and_flags)){
        strcat(destination, "FIN ");
    } 
}

/* UDP */

struct udp{
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned short int length; // tamaño en bytes del datagrama udp icluido los datos (minimo 8)
    unsigned short int checksum;
};