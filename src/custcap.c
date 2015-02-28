
#include "common_define.h"

void got_packet(u_char *arg, const struct pcap_pkthdr * pkthdr, const u_char *packet)
{
    int *counter =(int*)arg;
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
//	printf("\nPacket number %d:\n", *counter);
//	printf("    Recved packet size: %d \n", pkthdr->len);
//	printf("    Captured packet size: %d \n", pkthdr->caplen);
	++(*counter);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
        
        
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
//			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
//			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
//			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
//			printf("   Protocol: IP\n");
			return;
		default:
//			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
 
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
    
    struct PluginData data;
    data.tv =pkthdr->ts;
    data.ip_src =ip->ip_src;
    data.ip_dst =ip->ip_dst;
        
    data.th_sport =tcp->th_sport;
    data.th_dport =tcp->th_dport;
    data.th_flags =tcp->th_flags;
    
    data.th_seq =tcp->th_seq;
    data.th_ack =tcp->th_ack;
    data.th_win =tcp->th_win;
    
    data.size_ip =size_ip;
    data.size_tcp =size_tcp;
    data.size_payload =size_payload;
    
    plugin_myapp_parser_entry(&data);
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char * filter_exp ; //= "host 192.168.17.151 and port 18600";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */    
    int count =0;
    
	if (argc <= 1)
    {
        printf("\nUsage: \n  %s [device] [filter] \n", argv[0]);
        printf("Example: \n  %s eth0 \"host 192.168.17.151 and port 18600\" \n\n", argv[0]);
        
        return 1;
	}
	if (argc >= 2) {
		dev = argv[1];
	}
	if (argc >= 3) {
		filter_exp = argv[2];
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
//	printf("Device: %s    ", dev);
//	printf("Number of packets: %d    ", num_packets);
//	printf("Filter expression: %s    \n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char*)&count);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
    return 0;
}

