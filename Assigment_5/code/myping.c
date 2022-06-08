#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/wait.h>

#define SOURCE_IP "127.0.0.1"
#define DESTINATION_IP "127.0.0.1"
#define PACKETSIZE 64
struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

unsigned short checksum(void *b, int len);
int main()
{
    struct packet pckt;
    bzero(&pckt, sizeof(pckt));

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    pckt.hdr.type = ICMP_ECHO;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    pckt.hdr.un.echo.id = 18;

    //make some data to send
    int i;
    for ( i = 0; i < sizeof(pckt.msg) - 1; i++)
        pckt.msg[i] = i + '0';
    pckt.msg[i] = 0; 

    // Calculate the ICMP header checksum
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    // Sequence Number (16 bits): start at 0 the serial number we start to count "pakets"
    pckt.hdr.un.echo.sequence = 0;

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    // The port is irrelant for Networking and therefore was zeroed.
    struct hostent *hname;
    hname = gethostbyname(DESTINATION_IP);//tranzlate the string ip to real ip
    dest_in.sin_addr.s_addr = *(long *)hname->h_addr;

    int sock = -1;
    // to be able to read the raw socket reply we used IPPROTO_ICMP.
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        printf("socket() failed with error");
        return -1;
    }

    struct timeval begin;//timer
    gettimeofday(&begin, NULL);
    //  Send the packet using sendto() for sending datagrams.
    if (sendto(sock, &pckt, sizeof(pckt), 0, (struct sockaddr *)&dest_in, sizeof(dest_in)) == -1)
    {
        printf("sendto() failed with error");
        return -1;
    }
    int len = sizeof(dest_in);
    if (recvfrom(sock, &pckt, sizeof(pckt), 0, (struct sockaddr *)&dest_in, &len) > 0)
    {
        printf("**Got message!**\n");
    }
    struct timeval end;
    gettimeofday(&end, NULL);
    double micro = end.tv_usec - begin.tv_usec;
    double secs = end.tv_sec - begin.tv_sec;

    printf("the time in microseconds %f\n", micro);
    printf("the time in milliseconds %f\n", secs/1000);
    // Close the raw socket descriptor.
    close(sock);
    return 0;
}

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}