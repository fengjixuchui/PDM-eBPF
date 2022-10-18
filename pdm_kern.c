#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include "bpf_helpers.h"


#ifndef __section
#define __section(x) __attribute__((section(x), used))
#endif

#define DEBUG 1

#ifdef DEBUG
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })
#endif

struct ipv6hdr
{
    __u32 top;
    __u16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u64 saddr1;
    __u64 saddr2;
    __u64 daddr1;
    __u64 daddr2;
};

struct ipv6_destopt_pdm
{
    __u8 type;      /* 0x0F */
    __u8 length;    /* 10 bytes */
    __u8 scaleDTLR; /* Scale Delta Time Last Recieved */
    __u8 scaleDTLS; /* Scale Delta Time Last Sent */
    __u16 PSNTP;    /* Packet Sequence Number This Packet */
    __u16 PSNLR;    /* Packet Sequence Number Last Received */
    __u16 DTLR;     /* Delta Time Last Received */
    __u16 DTLS;     /* Delta Time Last Sent */
    __u8 padn_opt;  /* PADN for Alignment */
    __u8 padn_len;
};

struct dest_opt
{
    __u8 nexthdr;
    __u8 hdrlen;
};

__section("pdm") int pdm_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct ipv6hdr *ipv6_cast;

    // Checking if eth headers are incomplete
    if (data + sizeof(*eth) > data_end)
    {
        bpf_debug("Eth headers incomplete");
        return TC_ACT_SHOT;
    }

    // Allowing IPV4 packets to passthrough without modification
    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        return TC_ACT_OK;
    }

    // Checking if Ip headers are incomplete
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    {
        bpf_debug("IP headers incomplete");
        return TC_ACT_SHOT;
    }

    __u8 nexthdr = 60; // Dest options

    // Increasing the size of the packet
    long ret = bpf_skb_adjust_room(skb, 16, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET);
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    // Set next header
    __u32 nexthdr_location = sizeof(*eth) + 6;
    __u8 old_nexthdr;
    ret = bpf_skb_load_bytes(skb, nexthdr_location, &old_nexthdr, sizeof(old_nexthdr));
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    // Load Payload Size and increment it by size of PDM extension header
    __u32 payload_location = sizeof(*eth) + 4;
    __u16 payload_len;
    ret = bpf_skb_load_bytes(skb, payload_location, &payload_len, sizeof(payload_len));
    payload_len = ntohs(payload_len);
    payload_len += sizeof(struct ipv6_destopt_pdm) + sizeof(struct dest_opt);
    payload_len = htons(payload_len);

    // Setting New Payload length
    ret = bpf_skb_store_bytes(skb, payload_location, &payload_len, sizeof(payload_len), BPF_F_RECOMPUTE_CSUM);
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    // Setting nexthdr to 60
    ret = bpf_skb_store_bytes(skb, nexthdr_location, &nexthdr, sizeof(nexthdr), BPF_F_RECOMPUTE_CSUM);
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    // Setting Destination Options
    struct dest_opt dest_opt = {0};
    dest_opt.nexthdr = old_nexthdr; // Keep the old next header value
    dest_opt.hdrlen = 1;            // 16 Bytes

    // Defining PDM
    struct ipv6_destopt_pdm pdm = {0};
    pdm.type = 0x0F;
    pdm.length = 10;
    pdm.padn_opt = 1;
    pdm.padn_len = 0;

    // Storing Destination Options
    __u32 exthdr_start = sizeof(*eth) + sizeof(struct ipv6hdr);
    ret = bpf_skb_store_bytes(skb, exthdr_start, &dest_opt, sizeof(dest_opt), BPF_F_RECOMPUTE_CSUM);
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    // Storing PDM
    ret = bpf_skb_store_bytes(skb, exthdr_start + sizeof(dest_opt), &pdm, sizeof(pdm), BPF_F_RECOMPUTE_CSUM);
    if (ret)
    {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";