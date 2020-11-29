
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if.h>

#include "FWPacketParser.h"


void ParseUDP(struct sk_buff *rawPacket, packet_t *parsedPacket)
{
    struct udphdr *UDPHeader = udp_hdr(rawPacket);
    parsedPacket->src_port = ntohs(UDPHeader->source);
    parsedPacket->dst_port = ntohs(UDPHeader->dest);
}

void ParseTCP(struct sk_buff *rawPacket, packet_t *parsedPacket, bool *IsXmas)
{
    struct tcphdr *TCPHeader = tcp_hdr(rawPacket);
    parsedPacket->src_port = ntohs(TCPHeader->source);
    parsedPacket->dst_port = ntohs(TCPHeader->dest);
    parsedPacket->ack = TCPHeader->ack ? ACK_YES : ACK_NO;
    *IsXmas = TCPHeader->fin && TCPHeader->urg && TCPHeader->psh;
}

void ParseDirection(const struct nf_hook_state *state, packet_t *parsedPacket, bool *isLoopBack)
{
    char *interface = state->in->name;

    if (strncmp(interface, LOOPBACK_NET_DEVICE_NAME, IFNAMSIZ) == 0)
    {
        *isLoopBack = true;
        return;
    }

    if ((strncmp(interface, IN_NET_DEVICE_NAME, IFNAMSIZ) == 0))
    {
        parsedPacket->direction = DIRECTION_IN;
        return;
    }
    if ((strncmp(interface, OUT_NET_DEVICE_NAME, IFNAMSIZ) == 0))
    {
        parsedPacket->direction = DIRECTION_OUT;
    }
}

bool IsLoopBackIp(__be32 ip)
{
    return (ip >> (IP_BITS - LB_MASK)) == LB_MSByte;
}

int ParsePacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, packet_t *parsedPacket, bool *isLoopBack, bool *isXmas)
{
    if (ntohs(rawPacket->protocol) != ETH_P_IP)
    {
        printk(KERN_INFO "FW Unsupported network protocols.\n");
        return -1;
    }

    *isLoopBack = false;
    ParseDirection(state, parsedPacket, isLoopBack);
    if (*isLoopBack)
    {
        printk(KERN_INFO "Loop back packet.\n");
        return -1;
    }

    struct iphdr *ipHeader = ip_hdr(rawPacket);

    parsedPacket->protocol = ipHeader->protocol;
    parsedPacket->src_ip = ntohl(ipHeader->saddr);
    parsedPacket->dst_ip = ntohl(ipHeader->daddr);

    if (IsLoopBackIp(parsedPacket->dst_ip))
    {
        *isLoopBack = true;
        printk(KERN_INFO "Loop back packet.\n");
        return -1;
    }

    *isXmas = false;
    switch (parsedPacket->protocol)
    {
        case PROT_TCP:
            ParseTCP(rawPacket, parsedPacket, isXmas);
            break;
        case PROT_UDP:
            ParseUDP(rawPacket, parsedPacket);
            break;
        case PROT_ICMP:
            break;
        default:
            printk(KERN_INFO "Unsupported Transport protocol.\n");
            return -1;
    }

    return 0;
}