// Standard C include file for I/O functions
#include <stdio.h>

// Include files for libpcap functions
#include <pcap.h>

// Includes struct of ethernet, ip and tcp header
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;
	char *dev = "enp1s0"; // device
	struct ether_header *eptr; // struct of ethernet header

	/* live sniffing from device.

       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - max size of packets to capture
       promisc - set promiscous mode or not, 0 is off
       to_ms   - time to wait in ms before timeout, do not use -1
       errbuf  - error buffer
	 */
	if ((fp = pcap_open_live(dev, BUFSIZ, 0, 10, errbuf)) == NULL)
	{
		printf("Error in pcap_open_live(): %s\n\n\n", errbuf);
		return -1;
	}
	
	/* Retrieve the packets */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{	
		/* cast packet into ethernet header struct */
		eptr = (struct ether_header *) pkt_data;

		if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ipptr; // struct of ip header
			ipptr = (struct iphdr *) &pkt_data[14]; // byte 14 is always ip header
			int source_ip = ntohl(ipptr->saddr);  // source ip address
			int dest_ip = ntohl(ipptr->daddr); // destination ip address
			int ip_hl = (ipptr->ihl)*4; // ip header length
			
			/* identify the transport protocol and set the value to print */
			char *t_proto;
			if (ipptr->protocol == 6) {
				t_proto="TCP";
			} else if (ipptr->protocol == 17) {
				t_proto="UDP";
			} else {
				t_proto="none";
			}

			struct tcphdr *tcphead;

			tcphead = (struct tcphdr *) &pkt_data[14 + ip_hl]; // jump past the ip header
			int source_port = ntohs(tcphead->th_sport);
			int dest_port = ntohs(tcphead->th_dport);
			int tcp_off = ((int)tcphead->th_off)*4;
			char *payload = (char *) &pkt_data[14 + ip_hl + tcp_off];

			if (dest_port == 80) { // check if traffic is http
				/* print timestamp and len 
				printf("%ld:%ld ", header->ts.tv_sec, header->ts.tv_usec);

				/* print source and dest mac */
				printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x --> %02x:%02x:%02x:%02x:%02x:%02x ",
				eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2],
				eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5],
				eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2],
				eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);

				/* Print on screen the IP addresses of each packet, by using bit masking */
				printf("%i.%i.%i.%i --> %i.%i.%i.%i %s %i --> %i\n",
				(source_ip & 0xff000000) >> 24, (source_ip & 0x00ff0000) >> 16, (source_ip & 0x0000ff00) >> 8, source_ip & 0x000000ff,
				(dest_ip & 0xff000000) >> 24, (dest_ip & 0x00ff0000) >> 16, (dest_ip & 0x0000ff00) >> 8, dest_ip & 0x000000ff,
				t_proto,
				source_port,
				dest_port
				);

				printf("%s", payload); // wrong, it should print payload and not anything past it
				printf("\n\n");
			}

 		}
	}
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	pcap_close(fp);
	return 0;
}

