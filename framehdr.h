/*
* Credit to Tim Carstens for the contents of this file
* http://www.tcpdump.org/pcap.html
*/

#ifndef FRAMEHDR_H
#define FRAMEHDR_H

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN   6

/* Ethernet header */
struct ethernet_hdr {
	unsigned char  dhost[ETHER_ADDR_LEN];  /* Destination host address */
	unsigned char  shost[ETHER_ADDR_LEN];  /* Source host address */
	unsigned short type;                   /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_hdr {
	unsigned char vhl;            /* Version and header length */
	unsigned char tos;            /* Type of service */
	unsigned short len;           /* Total length */
	unsigned short id;            /* Identification */
	unsigned short off;           /* Fragment offset field */
	unsigned char ttl;            /* Time to live */
	unsigned char p;              /* Protocol */
	unsigned short ip_sum;        /* Checksum */
	unsigned int src, dst;         /* Source and dest address */
};
#define IP_HL(ip)      ((((ip)->vhl) & 0x0f) * 4)  /* Gets length of the IP header, use with (ip_hdr *) */

/* TCP header */
typedef unsigned int tcp_seq;

struct tcp_hdr {
	unsigned short sport;   /* Source port */
	unsigned short dport;   /* Destination port */
	tcp_seq seq;            /* Sequence number */
	tcp_seq ack;            /* Acknowledgement number */
	unsigned char offx2;    /* Data offset, rsvd */

	unsigned char flags;
	unsigned short win;      /* Window */
	unsigned short sum;      /* Checksum */
	unsigned short urp;      /* Urgent pointer */
};
#define TH_OFF(th)   ((((th)->offx2 & 0xf0) >> 4) * 4)	/* Gets length of the TCP header, use with (tcp_hdr *) */
#endif
