#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
// #include <netinet/ip.h>
// #include <linux/if_packet.h>
// #include <net/ethernet.h>

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
#define IP_V(ip) (((ip)->ip_ver) >> 4)

struct icmpheader
{
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    const int on = 1;
    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock <0){
        perror("socket() eroor");
    }
    // Step 2: Set socket option.
    int se = setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&on, sizeof(on));
    if (se<0){
        perror("didnt allowed spoof");
    }
    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

int main()
{
    char buffer[1500];
    memset(buffer, 0, 1500);

    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 8;

    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;

    ip->iph_sourceip.s_addr = inet_addr("10.0.2.5");
    ip->iph_destip.s_addr = inet_addr("8.8.8.8");

    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,sizeof(struct icmpheader));
    send_raw_ip_packet(ip);

    return 0;
}
