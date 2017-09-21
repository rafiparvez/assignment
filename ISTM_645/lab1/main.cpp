#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#include <map>
#include <set>
#include <iostream>
//#include "net.h"
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
	//#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	#define TH_SYN(th)	(((th)->th_flags & 0x02) >> 1)
	#define TH_FIN(th)	((th)->th_flags & 0x01)
		u_char th_flags;
//	#define TH_FIN 0x01
//	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

using namespace std;
map<pair<int,int>,string> flow;
// last = 1 response
// last = 2 request
map<pair<int,int>,int> last;
//convert the ip address to a readable string
string ip_to_string(int ip)
{
	char s[20] ="";
	string result = "";
	
	sprintf(s,"%d", ip &  127);
	result.append(s);
	result.append(".");
	sprintf(s,"%d", (ip &  ( 127 << 8)) >> 8);
	result.append(s);
	result.append(".");
	sprintf(s,"%d", (ip &  ( 127 << 16 )) >> 16);
	result.append(s);
	result.append(".");
	sprintf(s,"%d",  (ip & ( 127  << 24)) >> 24 );
	result.append(s);
	return result;
}
//if the users choices matchs the port number
bool match(int port, int protocal)
{
	if( port == 80 && protocal == 1)
		return true;
	if( port == 21 && protocal == 2)
		return true;
	if( port == 20 && protocal == 2)
		return true;
	if( port == 23 && protocal == 3)
		return true;

	return false;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


void callback(u_char* prot, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
    int size_payload;

	// u_char * packet is pointer to the first byte of a chunk of data containing the entire packet
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */
    u_int size_ip;
    u_int size_tcp; 
    ethernet = (const struct sniff_ethernet*)(packet);
    ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
 //Invalid IP header length
    if (size_ip < 20)
    {
	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	return;
    } 
    tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
//Invalid TCP header length
    //you need to add your our code in this part
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return ;
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	
	/*
	printf("TCP SRC port: %u\n", ntohs(tcp->th_sport));
	printf("TCP DST port: %u\n", ntohs(tcp->th_dport));
	printf("FLAGS: %u\n", tcp->th_flags);
	*/
	
    
// add the packet paylod into a hash table, entry is set according to a pair {ip,port}
    for (uint i=  SIZE_ETHERNET + size_ip + size_tcp; i < pkthdr->len; i++)
    { 
		map<pair<int,int>,string>::iterator it;
	    	string s  = "";
		int ip_addr;
		if ( match(ntohs(tcp->th_sport),*prot)) // determine if it's the server
		{
    		ip_addr =  ip->ip_src.s_addr;
			if ( ! flow.count({ip_addr,ntohs(tcp->th_dport)}))
				flow.insert( { {ip_addr,ntohs(tcp->th_dport)},string() });
			it = flow.find({ip_addr,ntohs(tcp->th_dport)});
			s.append(it->second);
			if ( i == SIZE_ETHERNET + size_ip + size_tcp)
			{
				if ( last.count({ip_addr,ntohs(tcp->th_dport)}))
				{
					auto ii =  last.find({ip_addr,ntohs(tcp->th_dport)});
					if ( ii->second != 1)
						s.append("\nServer Response:\n");
				}
				else
					s.append("\nServer Response:\n");
			}
			flow.erase({ip_addr,ntohs(tcp->th_dport)});
			if ( isprint(packet[i]) || packet[i] == '\n')//if the byte is printable
				s.push_back(packet[i]);
			else
			{	
				char temp[4];
				sprintf(temp," %d ",packet[i]);
				s.append(temp);

			}
			flow.insert( { {ip_addr,ntohs(tcp->th_dport)},s });
			
			if ( last.count({ip_addr,ntohs(tcp->th_dport)}))
					last.erase({ip_addr,ntohs(tcp->th_dport)});
			 last.insert({{ip_addr,ntohs(tcp->th_dport)},1});
		}
		else if (match(ntohs(tcp->th_dport),*prot)) //determine if it's the client
		{
         // you need to add your our code in this part
        }
     } 

return; 
}


int main(int argc,char **argv)
{
    cout<<"Hello World"<<endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    u_char prot;                   /* protocol number*/
    unsigned char *packet;
    struct pcap_pkthdr header;	/*header that pcap gives us */
	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 2 )
	{
		fprintf(stderr, "Usage: %s trace file path\n", argv[1]);
		exit(1);
	}
    printf("Protocol to analyze:1 (http),2 (ftp),3 (telnet):\n");
    scanf("%c",&prot);
    descr = pcap_open_offline(argv[1], errbuf);
    if (descr == NULL)
    {
	fprintf(stderr, "error reading pcap file: %s\n", errbuf);
	return 1;
    }
// process the packet
    if ( pcap_loop(descr, -1, callback,&prot) == -1){
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
        }
    if (prot == 1)
	printf("Protocal HTTP:\n");
    else if (prot == 2)
	printf("Protocal FTP:\n");
    else if (prot == 3)
	printf("Protocal TELNET:\n");

// Go through the hash map and output the combined payload from every entry.

    for(auto it = flow.begin(); it != flow.end(); it++)
    {
	cout << "Session Between Server IP:" << ip_to_string(it->first.first) << " and  Local Client Port:" << it->first.second << ":" << endl;
	cout << it->second << endl;
        cout << endl;
        cout << endl;
    }

}
