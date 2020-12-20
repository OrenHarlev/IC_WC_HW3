
#ifndef PROXY_HELPER_H
#define PROXY_HELPER_H

#include <linux/skbuff.h>

int TamperPacket(struct sk_buff *skb, __u32 srcIp, __u32 dstIp, __u16 srcPort, __u16 dstPort);

#endif
