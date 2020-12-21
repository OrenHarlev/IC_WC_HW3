
#ifndef FW_PROXY_HELPER_H
#define FW_PROXY_HELPER_H

#include <linux/skbuff.h>
#include "FWPacketParser.h"
#include "FWConnectionManager.h"

int RedirectPreRoutPacket(struct sk_buff *skb, packet_t packet);

int RedirectLocalOutPacket(struct sk_buff *skb, ConnectionManager connectionManager);

#endif
