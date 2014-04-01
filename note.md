CVE-2013-4348
=============

IPIP(IP in IP)
--------------
+ RFC 2003
+ RFC 791

Vulnerable Code
---------------

```
again:
    switch (proto) {
    case __constant_htons(ETH_P_IP): {
	const struct iphdr *iph;
	struct iphdr _iph;
ip:
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph || iph->ihl < 5)
	    return false;
	nhoff += iph->ihl * 4; // (1), dead loop here

	ip_proto = iph->protocol; // ip_proto == 4, for IPIP. RFC 2003
	if (ip_is_fragment(iph))
	    ip_proto = 0;

	iph_to_flow_copy_addrs(flow, iph);
	break;
    }   

    switch (ip_proto) {
    case IPPROTO_GRE: {
	/* ... */
    }   
    case IPPROTO_IPIP:
	proto = htons(ETH_P_IP);
	goto ip; // (2) trigger
    case IPPROTO_IPV6:
	/* ... */
    }
```

workflow
---------
1. process outter IP
    - cut off outter IP header
    - offset by iph->ihl (length of outter IP header)
2. process inner header
    - IP again, so `go to` 1.
3. if (iph->ihl == 0), 2->1 would be a dead loop.
