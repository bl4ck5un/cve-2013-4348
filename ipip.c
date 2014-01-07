#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <string.h>

#define UDP_PAYLOAD_LEN 10

unsigned short in_cksum(unsigned short *addr, int len);

int main(int argc, char* argv[])
{
    struct iphdr *iph_o, *iph_i;
    struct udphdr *udph;

    struct sockaddr *dst;
    struct sockaddr_in connection;
    char *dst_addr="127.0.0.1";
    char *src_addr="127.1.2.3";

    int sockfd;

    // constructing raw packets
    // inner udp header and data
    size_t iphdr_l  = sizeof(struct iphdr);
    size_t udphdr_l = sizeof(struct udphdr);
    size_t tol_udp  = sizeof(struct udphdr) + UDP_PAYLOAD_LEN;
    size_t tol_ipi  = sizeof(struct iphdr) + tol_udp;
    size_t tol_ipo  = sizeof(struct iphdr) + tol_ipi;

    printf("packet [IP(%d)|IP(%d)|UDP(%d)|data(%d)]\n",
            tol_ipo,
            tol_ipi,
            tol_udp,
            UDP_PAYLOAD_LEN);

    void * packet = malloc(tol_ipo);

    // outter ip header
    iph_o = (struct iphdr*) packet;
    iph_o->ihl      = 0;        // spot
    iph_o->version  = 4;
    iph_o->tot_len  = tol_ipo;  // no need to htons(x), wierd
    iph_o->protocol = 4;        // IPIP
    iph_o->saddr    = inet_addr(src_addr);
    iph_o->daddr    = inet_addr(dst_addr);
    iph_o->check    = in_cksum((unsigned short *)iph_o, iphdr_l); 

    // inner ip header
    iph_i = iph_o + 1;
    iph_i->ihl      = 5;
    iph_i->version  = 4;
    iph_i->tot_len  = htons(tol_ipi);
    iph_i->protocol = 17;    // UDP, see RFC 1700
    iph_i->saddr    = inet_addr(src_addr);
    iph_i->daddr    = inet_addr(dst_addr);
    iph_i->check    = in_cksum((unsigned short *)iph_i, iphdr_l); 


    udph = packet + 2*iphdr_l;
    udph->source    = htons(9999);
    udph->dest      = htons(80);
    udph->len       = htons(tol_udp);
    udph->check     = in_cksum((unsigned short *)udph, udphdr_l);
    memset(udph + 1, 0x90, 10); // set udp payload

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
     /* IP_HDRINCL must be set on the socket so that the kernel does not attempt 
     *  to automatically add a default ip header to the packet*/
    int optval = 1;
    setsockopt(sockfd, IPPROTO_IP,
            IP_HDRINCL, &optval, sizeof(int));

    connection.sin_family       = AF_INET;
    connection.sin_addr.s_addr  = iph_o->daddr;
    //connection.sin_port         = udph->source;
    sendto( sockfd, 
            iph_o, iph_o->tot_len, 
            0,
            (struct sockaddr *)&connection, sizeof(struct sockaddr));
    printf("Sent %d byte packet to %s\n", iph_o->tot_len, dst_addr);
    return 0;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}
