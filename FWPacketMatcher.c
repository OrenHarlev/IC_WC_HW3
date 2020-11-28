
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "FWPacketMatcher.h"
#include "fw.h"

int MatchRawPacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, RuleManager ruleManager, log_row_t *actionLog)
{
    packet_t packet;
    if (ParsePacket(rawPacket, &packet, state) != 0)
    {
        // todo error
        return -1;
    }

    // todo handle spacial cases

    return MatchPacket(packet, ruleManager, actionLog);
}
