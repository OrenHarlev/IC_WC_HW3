
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include "FWProxyHelper.h"
#include "fw.h"
#include "FWPacketParser.h"
#include "FWConnectionManager.h"

int FixChecksum(struct sk_buff *skb)
{
    struct iphdr *ipHeader = ip_hdr(skb);
    ipHeader->check = 0;
    ipHeader->check = ip_fast_csum((u8 *)ipHeader, ipHeader->ihl);

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

int TamperPacket(struct sk_buff *skb, __be32 srcIp, __be32 dstIp, __be16 srcPort, __be16 dstPort)
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

bool IsProxyPort(__be16 port)
{
    return port == PORT_HTTP_PROXY ||
           port == PORT_FTP_PROXY  ||
           port == PORT_SMTP_PROXY ||
           port == PORT_ZOOKEPPER_PROXY;
}

bool IsKnownPort(__be16 port)
{
    return port == PORT_HTTP        ||
           port == PORT_FTP_CONTROL ||
           port == PORT_SMTP        ||
           port == PORT_ZOOKEPPER;
}

int RedirectPreRoutPacket(struct sk_buff *skb, packet_t packet)
{
    __be32 localIp = htonl(in_aton(LOCAL_IP));
    switch (packet.dst_port)
    {
        case PORT_HTTP:
            return TamperPacket(skb, 0, localIp, 0, PORT_HTTP_PROXY);
        case PORT_FTP_CONTROL:
            return TamperPacket(skb, 0, localIp, 0, PORT_FTP_PROXY);
        case PORT_SMTP:
            return TamperPacket(skb, 0, localIp, 0, PORT_SMTP_PROXY);
        case PORT_ZOOKEPPER:
            return TamperPacket(skb, 0, localIp, 0, PORT_ZOOKEPPER_PROXY);
        default:
            break;
    }

    localIp = packet.direction == DIRECTION_IN ? htonl(in_aton(OUT_NET_DEVICE_IP)) : htonl(in_aton(IN_NET_DEVICE_IP));
    if (IsKnownPort(packet.src_port))
    {
        return TamperPacket(skb, 0, localIp, 0, 0);
    }
    return 0;
}

int RedirectLocalOutPacket(struct sk_buff *skb, ConnectionManager connectionManager)
{
    packet_t packet;
    bool isLoopBack, isXmas;

    if (ParsePacket(skb, NULL, &packet, &isLoopBack, &isXmas) != 0)
    {
        return 0;
    }

    connection_t connection;
    if (IsProxyPort(packet.src_port))
    {
        if (GetConnectionFromClient(connectionManager, packet.dst_ip, packet.dst_port, &connection))
        {
            return TamperPacket(skb, connection.sIp, 0, connection.sPort, 0);
        }
        return 0;
    }
    else if (IsKnownPort(packet.dst_port))
    {
        if (GetConnectionFromServer(connectionManager, packet.dst_ip, packet.dst_port, packet.src_port, &connection))
        {
            return TamperPacket(skb, connection.cIp, 0, 0, 0);
        }
        return 0;
    }
    return 0;
}