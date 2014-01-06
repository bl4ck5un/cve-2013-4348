bool skb_flow_dissect(const struct sk_buff *skb, struct flow_keys *flow)
{
	int nhoff = skb_network_offset(skb);
	u8 ip_proto;
	__be16 proto = skb->protocol;

	memset(flow, 0, sizeof(*flow));

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

	flow->ip_proto = ip_proto;
	flow->ports = skb_flow_get_ports(skb, nhoff, ip_proto);
	flow->thoff = (u16) nhoff;

	return true;
}
