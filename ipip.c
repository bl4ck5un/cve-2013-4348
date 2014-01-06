#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

unsigned short in_cksum(unsigned short *addr, int len);

int main(int argc, char* argv[])
{
    struct iphdr *iph_o, *iph_i;
    struct sockaddr *dst;

    char *dst_addr="127.0.0.1";
    char *src_addr="127.0.0.1";
    int sockfd, optval, addrlen;
    struct sockaddr_in connection;
    iph_o = malloc(2 * sizeof(struct iphdr));

    // outter ip header
    iph_o->ihl         = 0;    // spot
    iph_o->version     = 4;
    iph_o->tot_len     = 2 * sizeof(struct iphdr);
    iph_o->protocol    = 4;    // IPIP
    iph_o->saddr       = inet_addr(src_addr);
    iph_o->daddr       = inet_addr(dst_addr);
    iph_o->check = in_cksum((unsigned short *)iph_o, sizeof(struct iphdr)); 

    // inner ip header
    iph_i = (struct iphdr*) iph_o + 1;
    iph_i->ihl         = 5;
    iph_i->version     = 4;
    iph_i->tot_len     = sizeof(struct iphdr);
    iph_i->protocol    = 0;    // IP
    iph_i->saddr       = inet_addr(src_addr);
    iph_i->daddr       = inet_addr(dst_addr);
    iph_i->check = in_cksum((unsigned short *)iph_i, sizeof(struct iphdr)); 

    if ((sockfd = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
     /* IP_HDRINCL must be set on the socket so that the kernel does not attempt 
     *  to automatically add a default ip header to the packet*/
    setsockopt(sockfd, IPPROTO_IP,
            IP_HDRINCL, &optval, sizeof(int));

    connection.sin_family       = AF_INET;
    connection.sin_addr.s_addr  = iph_o->daddr;
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
