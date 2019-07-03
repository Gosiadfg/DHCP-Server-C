#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/udp.h>     
#include <linux/ip.h>
#include <libnet.h>

struct dhcp_packet {
	u_int8_t  op;          //operacja, typ nag³ówka, 1 = BOOTREQUEST, 2 = BOOTREPLY
	u_int8_t  htype;       //typ sprzêtu (karty sieciowej) 1-28, 1 = Ethernet
	u_int8_t  hlen;        //d³ugoœæ adresu sprzêtowego, 6 = Ethernet 10 Mbps
	u_int8_t  hops;        //liczba skoków (poœrednicz¹cych routerów), opcjonalne
    u_int32_t xid;         //identyfikator transakcji, gdy MAC niezrozumia³y
    u_int16_t secs;        //liczba sekund, od wys³ania BOOTREQUEST
    u_int16_t flags;       //flagi, broadcast
    u_int32_t ciaddr;      //IP klienta, nieobowi¹zkowe, u¿ywane gdy odœwie¿any adres
    u_int32_t yiaddr;      //przydzielone IP klienta, rêczne/automatyczne/dynamiczne
    u_int32_t siaddr;      //IP serwera
    u_int32_t giaddr;      //IP bramki
    u_int8_t chaddr[16];   //MAC klienta
    u_int8_t sname[64];    //nazwa serwera, opcjonalne
    u_int8_t file[128];    //plik startowy, mechanizm ciasteczek
    char options[308]; //opcje producenta 0-254
};

char* errbuf;
pcap_t* handle;
struct ethhdr* fhead;
struct iphdr* fhead2;
struct udphdr* fhead3;
char* type;
u_char buf[512];
int printsize;
int i=0;
const u_char *dhcp_bytes;
struct dhcp_packet* request;
int check;
int check_set;
libnet_t *ln;
libnet_ptag_t t;
libnet_ptag_t ip;
libnet_ptag_t udp;
libnet_ptag_t dhcp;
u_char options[38];
u_long options_len;
char errbuf2[LIBNET_ERRBUF_SIZE];
u_int32_t target_ip_addr, src_ip_addr;
struct libnet_ether_addr* src_hw_addr;
struct libnet_stats ls;
u_char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char str[INET_ADDRSTRLEN]; //16
//char *dns_ip[2] = {"150.254.5.4","150.254.5.11"}; // cat /etc/resolv.conf
char gateway_ip[] = "0.0.0.0"; //route
//char network_mask[] = "255.255.255.0";
u_int32_t first_address;
u_int32_t last_address;
char first_adr[]="192.168.1.1";
char last_adr[]="192.168.1.99";
u_int32_t yiaddr;

void cleanup() {
  pcap_close(handle);
  free(errbuf);
}

void stop(int signo) {
  exit(EXIT_SUCCESS);
}

struct record{
	u_int32_t addr;
	u_int8_t chaddr;
};

struct record pool[99];

void init_pool(){

    uint8_t vals[]={192,168,1,0}; 
    char buf[16] = {0};

    while (vals[3] < 99) {
        vals[3]++;
        snprintf(buf, 16, "%d.%d.%d.%d", vals[0],vals[1],
                                        vals[2],vals[3]);
	pool[vals[3]-1].addr = inet_addr(buf);
	pool[vals[3]-1].chaddr = '\0';
    }
}

u_int32_t get_yiaddr(){
	
	for (int i = 0; i < 99; i++){
		if (pool[i].chaddr == '\0'){
			inet_ntop(AF_INET, &(pool[i].addr), str, INET_ADDRSTRLEN);
			return pool[i].addr;
		}
   	 }
	return 0;
}

int set_yiaddr(u_int32_t address, u_int8_t *chaddr){
	for (int i = 0; i < 99; i++){
		if (pool[i].addr == address){
			pool[i].chaddr=*chaddr;
			return 1;
		}
    }
	return 0;
}

void dhcp_discover(){  

	options[0] = LIBNET_DHCP_MESSAGETYPE;
	options[1] = 1;
	options[2] = LIBNET_DHCP_MSGOFFER;
	options[3] = 1; //subnet mask
	options[4] = 4;
	options[5] = 0xFF; //255.255.255.0
	options[6] = 0xFF; 
	options[7] = 0xFF; 
	options[8] = 0x00; 
	options[9] = 3; //router 
	options[10] = 4; 
	options[11] = 0x0a; //10.0.2.15 
	options[12] = 0x00; 
	options[13] = 0x02; 
	options[14] = 0x0f; 
	options[15] = 51; // lease time 
	options[16] = 4; 
	options[17] = 0x00; 
	options[18] = 0x00; 
	options[19] = 0x00; 
	options[20] = 0x3C;  //60s
	options[21] = 54; //server ip 
	options[22] = 4; 
	options[23] = 0x0a; //10.0.2.15 
	options[24] = 0x00;
	options[25] = 0x02; 
	options[26] = 0x0f; 
	options[27] = 6; //dns server 
	options[28] = 8; 
	options[29] = 0x96; // "150.254.5.4"
	options[30] = 0xfe; 
	options[31] = 0x05;
	options[32] = 0x04; 
	options[33] = 0x96;  //"150.254.5.11" 
	options[34] = 0xfe;
	options[35] = 0x05; 
	options[36] = 0x0b; 
	options[37] = LIBNET_DHCP_END;

        options_len = 38;

	yiaddr = get_yiaddr();
	inet_ntop(AF_INET, &yiaddr, str, INET_ADDRSTRLEN);

	dhcp = libnet_build_dhcpv4(
                LIBNET_DHCP_REPLY,            
                1,                              
                6,                              
                0,                              
                ntohl(request->xid),                    
                0,                              
                0x8000,                        
                0,                              
                ntohl(yiaddr),                             
                ntohl(src_ip_addr),                             
                0,                              
                request->chaddr,      
                NULL,                           
                NULL,                           
                options,                        
                options_len,                    
                ln,                              
                0);        
}
void dhcp_request (){  
	
	int check_set = set_yiaddr(yiaddr,request->chaddr);
	if (check_set == 1) options[2] = LIBNET_DHCP_MSGACK;
	else options[2] = LIBNET_DHCP_MSGNACK;

	options[0] = LIBNET_DHCP_MESSAGETYPE;
	options[1] = 1;
	//options[2] = LIBNET_DHCP_MSGACK;
	options[3] = 1; //subnet mask
	options[4] = 4;
	options[5] = 0xFF; //255.255.255.0
	options[6] = 0xFF; 
	options[7] = 0xFF; 
	options[8] = 0x00; 
	options[9] = 3; //router 
	options[10] = 4; 
	options[11] = 0x0a; //10.0.2.15 
	options[12] = 0x00; 
	options[13] = 0x02; 
	options[14] = 0x0f; 
	options[15] = 51; // lease time 
	options[16] = 4; 
	options[17] = 0x00; 
	options[18] = 0x00; 
	options[19] = 0x00; 
	options[20] = 0x3C;  //60s
	options[21] = 54; //server ip 
	options[22] = 4; 
	options[23] = 0x0a; //10.0.2.15 
	options[24] = 0x00;
	options[25] = 0x02; 
	options[26] = 0x0f; 
	options[27] = 6; //dns server 
	options[28] = 8; 
	options[29] = 0x96; // "150.254.5.4"
	options[30] = 0xfe; 
	options[31] = 0x05;
	options[32] = 0x04; 
	options[33] = 0x96;  //"150.254.5.11" 
	options[34] = 0xfe;
	options[35] = 0x05; 
	options[36] = 0x0b; 
	options[37] = LIBNET_DHCP_END;

        options_len = 38;

	dhcp = libnet_build_dhcpv4(
                LIBNET_DHCP_REPLY,            
                1,                              
                6,                              
                0,                              
                ntohl(request->xid),                    
                0,                              
                0x8000,                        
                0,                              
                ntohl(yiaddr),                             
                ntohl(src_ip_addr),                             
                0,                              
                request->chaddr,      
                NULL,                           
                NULL,                           
                options,                        
                options_len,                    
                ln,                              
                0); 
}

void dhcp_decline (){}

void dhcp_release (){  

	/*for (int i = 0; i < 99; i++)
    {
		if (pool[i].addr == request.ciaddr && pool[i].chaddr == request.chaddr){
			pool[i].addr = NULL;
			strcpy(pool[i].chaddr,NULL);
			break;
		}
    }*/
}

void dhcp_inform (){}

void check_option(){

	char buf[512];
	check=0;

	switch (request->options[6]) {

	case 1:
        printf("Received DISCOVER. Preparing OFFER.\n");
	dhcp_discover();            
	break;

	case 3:
	  printf("Received REQUEST. Preparing ACK or NACK.\n");
	  dhcp_discover();
	    break;

	case 4:
	    printf("Received DECLINE.\n");
	    dhcp_decline(); 
            check=1;
	    break;

	case 7:
	    printf("Received RELEASE.\n");
	    dhcp_release();
	    check=1;
	    break;

	case 8:
	    printf("Received INFORM.\n");
	    dhcp_inform();
	    check=1;
	    break;

	default: 
		check=1;
		memcpy(&buf,&request,sizeof(request));
		printf("Switch received: %s \n",buf);
	}

   printf("XID: 0x%X \n",ntohl(request->xid));
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

 fhead = (struct ethhdr*) bytes;

  if(ntohs(fhead->h_proto)==0x0800){ //ipv4

	fhead2= (struct iphdr*)(bytes + sizeof(struct ethhdr));

	if(fhead2->protocol==17){ //udp

		fhead3= (struct udphdr*)(bytes + sizeof(struct iphdr)+ sizeof(struct ethhdr)); 

		if(ntohs(fhead3->source)==68 && ntohs(fhead3->dest)==67){ //dhcp
           		//printf("DHCP [%dB of %dB]\n", h->caplen, h->len);

		dhcp_bytes=bytes + sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr);
		request=(struct dhcp_packet*)dhcp_bytes;

		// while (i<h->len){
		//	printf ("%02X", dhcp_bytes[i]);
		//	i++;
		//	printf("\n");
		//}

		init_pool();
		check_option();

		if(check==0){
			
udp = libnet_build_udp(
		        67,                             
		        68,                            
		        LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len,  
		        0,                              
		        NULL,                           
		        0,                              
		        ln,                              
		        0);                             
		
		ip = libnet_build_ipv4(
		        LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H
		        + options_len,                  
		        0x10,                           
		        0,                              
		        0,                             
		        16,                             
		        IPPROTO_UDP,                    
		        0,                             
		        src_ip_addr,                         
		        inet_addr("255.255.255.255"),   
		        NULL,                           
		        0,                              
		        ln,                             
		        0);                             
		
		t = libnet_autobuild_ethernet(
		        enet_dst,                       
		        ETHERTYPE_IP,                   
		        ln);                             
			
		libnet_write(ln);
 			   
		libnet_stats(ln, &ls);
		fprintf(stderr, "Packets sent:  %lld\n"
			    "Packet errors: %lld\n",
			    (long long)ls.packets_sent, (long long)ls.packet_errors);
		libnet_destroy(ln);
		//free(options);
		}
	} 
	}
  }
}

int main(int argc, char** argv) {
  ln = libnet_init(LIBNET_LINK, argv[1], errbuf2);
  src_ip_addr = libnet_get_ipaddr4(ln);
  src_hw_addr = libnet_get_hwaddr(ln);
  first_address=inet_addr(first_adr);
  last_address=inet_addr(last_adr);
  //inet_ntop(AF_INET, &(first_address), str, INET_ADDRSTRLEN);

  atexit(cleanup);
  signal(SIGINT, stop);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(argv[1], errbuf);
  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_activate(handle);
  pcap_loop(handle, -1, trap, NULL);
}