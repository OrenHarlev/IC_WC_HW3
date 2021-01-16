
#ifndef FW_PACKET_PARSER_H
#define FW_PACKET_PARSER_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/if.h>
#include "fw.h"

int ParsePacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, packet_t *parsedPacket, bool *isLoopBack, bool *isXmas);

void UpdateLogFromPacket(packet_t packet, log_row_t *logRow);

#endif
