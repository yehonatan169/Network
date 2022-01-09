#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>

struct icmpheader
{
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};
struct ethheader
{
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* IP? ARP? RARP? etc */
};
struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length in byte
        iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};
#define IP_HL(ip) (((ip)->iph_ihl) & 0x0f) // 1111 0101 1011 0010 AND 0000 1111 = 0000
#define IP_V(ip) (((ip)->iph_ver) >> 4)

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) // check if its type IP
    {
        // copy the data to an ip header, the buffer includes all the data we need
        struct ipheader *ipHeader = (struct ipheader *)(packet + sizeof(struct ethheader));
        int size = IP_HL(ipHeader) * 4;
        printf("Got a packet\n");
        // check if the protocol is ICMP, ICMP protocol number is 1
        if (ipHeader->iph_protocol == 1)
        {
            // int ipHeaderLen = ipHeader->ihl * 4;
            // copy the icmp header data.
            struct icmpheader *icmpHeader = (struct icmpheader *)(packet + size + sizeof(struct ethheader));
            // print the data
            printf("TYPE:            :   %d\n", icmpHeader->icmp_type);
            printf("CODE:            :   %d\n", icmpHeader->icmp_code);
            printf("Source IP        :   %s\n", inet_ntoa(ipHeader->iph_sourceip));
            printf("Destination IP   :   %s\n", inet_ntoa(ipHeader->iph_destip));
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto ICMP and src host 10.0.2.5 and dst host 10.0.2.4";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // can be change to lo so the myping.c file will worke 

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if(pcap_setfilter(handle, &fp)!=0){
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);

    }
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    return 0;
}
