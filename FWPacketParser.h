
#ifndef FW_PACKET_PARSER_H
#define FW_PACKET_PARSER_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/if.h>
#include "fw.h"

// packet relevant data
typedef struct {
    direction_t direction;
    __be32	src_ip;
    __be32	dst_ip;
    __be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __u8	protocol; 			// values from: prot_t
    ack_t	ack; 				// values from: ack_t
} packet_t;

int ParsePacket(sk_buff *rawPacket, struct nf_hook_state *state, packet_t *parsedPacket, bool *isLoopBack, bool *isXmas);

#endif
