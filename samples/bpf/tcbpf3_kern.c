/* Copyright (c) 2016 VMware
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <net/ipv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define printk(fmt, ...)    \
({  char ___fmt[] = fmt;    \
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
})

//#include <net/netfilter/nf_conntrack_common.h>
#define IP_CT_ESTABLISHED	0
#define IP_CT_RELATED		1
#define IP_CT_NEW		2

/* Example of a stateful firewall using BPF conntrack
 * - Only allow PING from the connections originates
 *   from this host (zone 0x10)
 * - Attach ct_commit at tc egress, tracking the connection originating
 *   from this host.
 * - Attach ct_lookup at tc ingress, pass when ctinfo == ESTABLISHED,
 *   otherwise drop.
 */

SEC("ct_lookup")
int _ct_lookup(struct __sk_buff *skb)
{
	int ret, flags;
	__u64 proto;
	struct bpf_conntrack_info info;

	proto = load_half(skb, 12);
	if (proto != ETH_P_IP) {
		return TC_ACT_OK;
	} else {
		__u64 ip_proto = load_byte(skb, 14 +
					   offsetof(struct iphdr, protocol));
		if (ip_proto != IPPROTO_ICMP)
			return TC_ACT_OK;
	}
	/* Only process ICMP */

	__builtin_memset(&info, 0x0, sizeof(info));
	info.zone_id = 0x10;
	info.family = NFPROTO_IPV4;

	ret = bpf_skb_ct_lookup(skb, &info, 0);
	if (ret < 0) {
		printk("ct_lookup failed\n");
		return TC_ACT_OK;
	}

	printk("ct_lookup: zone: %d state: %d mark: %x",
		info.zone_id, info.ct_state, info.mark_value);

	if (info.ct_state == IP_CT_ESTABLISHED) {
		printk("allow established connection\n");
		return TC_ACT_OK;
	} else if (info.ct_state == IP_CT_NEW) {
		printk("drop new connection\n");
		return TC_ACT_SHOT;
	} else {
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

SEC("ct_commit")
int _ct_commit(struct __sk_buff *skb)
{
	struct bpf_conntrack_info info;
	int ret, flags;
	__u64 proto;

	proto = load_half(skb, 12);
	if (proto != ETH_P_IP) {
		return TC_ACT_OK;
	} else {
		__u64 ip_proto = load_byte(skb, 14 +
					   offsetof(struct iphdr, protocol));
		if (ip_proto != IPPROTO_ICMP)
			return TC_ACT_OK;
	}
	/* Only process ICMP */
	 __builtin_memset(&info, 0x0, sizeof(info));
	info.zone_id = 0x10;
	info.family = NFPROTO_IPV4;
	info.mark_value = 0x00009487;
	info.mark_mask = 0x0000ffff;

	/* commit this skb to conntrack
	 * so the other direction (icmp echo reply) can pass
	 */
	ret = bpf_skb_ct_commit(skb, &info, 0);
	if (ret < 0) {
		printk("ct_commit failed\n");
		return TC_ACT_OK;
	}

	printk("ct_commit: zone: %d state: %d mark: %x",
		info.zone_id, info.ct_state, info.mark_value);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
