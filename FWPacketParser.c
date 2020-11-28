
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "FWPacketParser.h"

int ParsePacket(sk_buff *rawPacket, struct nf_hook_state *state, packet_t *parsedPacket, bool *isLoopBack, bool *isXmas){}