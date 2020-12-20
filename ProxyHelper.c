
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include "ProxyHelper.h"

int FixChecksum(struct sk_buff *skb)
{
    struct iphdr *ipHeader = ip_hdr(skb);
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ipHeader, ipHeader->ihl);

    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0)
    {
        printk(KERN_ERR "Failed to fix checksum\n");
        return -1;
    }

    ipHeader = ip_hdr(skb);
    struct tcphdr *tcpHeader = tcp_hdr(skb);

    /* Fix TCP header checksum */
    __u16 tcplen = (ntohs(ipHeader->tot_len) - ((ipHeader->ihl) << 2));
    tcpHeader->check = 0;
    tcpHeader->check = tcp_v4_check(tcplen, ipHeader->saddr, ipHeader->daddr, csum_partial((char *)tcpHeader, tcplen, 0));

    return 0;
}

int TamperPacket(struct sk_buff *skb, __u32 srcIp, __u32 dstIp, __u16 srcPort, __u16 dstPort)
{
    struct iphdr *ipHeader = ip_hdr(skb);
    if (srcIp)
    {
        ipHeader->saddr = htonl(srcIp);
    }

    if (dstIp)
    {
        ipHeader->daddr = htonl(dstIp);
    }

    struct tcphdr *tcpHeader = tcp_hdr(skb);
    if (srcPort)
    {
        tcpHeader->source = htons(srcPort);
    }

    if (dstPort)
    {
        tcpHeader->dest = htons(dstPort);
    }

    return FixChecksum(skb);
}
