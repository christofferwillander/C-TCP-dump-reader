/*
* Programmer: Christoffer Willander		Date completed: December 18th, 2017
* Instructor: Carina Nilsson			Class: DV1550
*
* Network dump reader
*/

#include "framehdr.h"
#include <stdio.h>
#include <stdlib.h>
#pragma warning(disable:4996)

#define MAX_STR_LEN 30 /* Maximum file name length */
#define ETH_HDR_LEN 14 /* Predefined ethernet header length */

void printPayload(int pckNr, char *payload) /* Prints payload and package number */
{
	printf("\nPkt %d\n", pckNr);
	printf("------\n");
	printf("Payload: %s\n", payload);
}

void printIP(unsigned char *srcIP, unsigned char *dstIP) /* Prints source and destination IP byte by byte*/
{
	printf("Source: %d.%d.%d.%d\n", srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
	printf("Destination: %d.%d.%d.%d\n", dstIP[0], dstIP[1], dstIP[2], dstIP[3]);
}

int main()
{
	char fileName[MAX_STR_LEN]; /* Holds file name */
	char discard[1]; /* Char array to discard /n from line breaks in file */

	int pckSize = 0; /* Holds the size of each individual package */
	int pckNr = 0; /* Holds package number */

	int ipHdrSize, tcpHdrSize; /* Holds the size of ip/tcp headers */

	void *ptr; /* Void pointer to which the package is read into */
	char *charPtr; /* Char pointer used for type cast from void pointer in order to perform pointer arithmetics */

	printf("What file do you want to use?\n");
	scanf("%s", &fileName);
	getchar();

	FILE* networkDumpFile = fopen(fileName, "rb"); /* Loading file (read binary) */

	if (networkDumpFile == NULL) /* If file is not found */
	{
		printf("An error occured whilst trying to open the file %s for reading.", fileName);
		exit(1);
	}

	while (fscanf(networkDumpFile, "%d", &pckSize) != EOF) /* Iterates while fscanf does not return EOF - scans for package size and stores in variable pckSize */
	{
		fscanf(networkDumpFile, "%c", &discard); /* Discards the /n and moves file pointer forward */

		ptr = malloc(pckSize*(sizeof(char))); /* Allocating memory for void pointer (ptr) */
		fread(ptr, pckSize, 1, networkDumpFile); /* Reading package into void pointer (ptr) */

		struct ethernet_hdr *ethernetHdr; /* Ethernet part */
		ethernetHdr = ((struct ethernet_hdr*)ptr); /* Type casting void pointer (ptr) to struct ethernet_hdr* */

		struct ip_hdr *ipHdr; /* IP part */
		charPtr = ((char*)ptr) + ETH_HDR_LEN; /* Converting void ptr to char ptr - performing pointer arithemeticts (+ ETH_HDR_LEN) */
		ipHdr = ((struct ip_hdr*)charPtr); /* Type casting char pointer (charPtr) to struct ip_hdr* */
		ipHdrSize = IP_HL(ipHdr); /* Extracting IP header length - storing in variable ipHdrSize */
		
		unsigned char *ipSrc = (unsigned char*)&ipHdr->src; /* Storing source IP in *ipSrc */
		unsigned char *ipDst = (unsigned char*)&ipHdr->dst; /* Storing destination IP in *ipDst */

		struct tcp_hdr *tcpHdr; /* TCP part */
		charPtr += ipHdrSize; /* Performing pointer arithmetics (+ ipHdrSize) */
		tcpHdr = ((struct tcp_hdr*)charPtr); /* Type casting char pointer (charPtr) to struct tcp_hdr* */
		tcpHdrSize = TH_OFF(tcpHdr); /* Extracting TCP header length - storing in variable tcpHdrSize */
		charPtr += tcpHdrSize; /* Performing pointer arithmetics (+ tcpHdrSize) */
		
		pckNr++; /* Incrementing package number used in printPayload */
		printPayload(pckNr, charPtr); /* Printing payload */
		printIP(ipSrc, ipDst); /* Printing source and destination IPs */
		free(ptr); /* Freeing memory used by ptr */
	}

	fclose(networkDumpFile); /* Closing file */

	getchar();
	return 0;
}