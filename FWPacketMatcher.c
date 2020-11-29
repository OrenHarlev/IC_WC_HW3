#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "fw.h"
#include "FWPacketMatcher.h"
#include "FWRuleManager.h"
#include "FWPacketParser.h"


int MatchRawPacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, RuleManager ruleManager, Logger logger)
{
    packet_t packet;
    bool isXmas;
    bool isLoopBack;

    printk(KERN_ERR "MatchRawPacket\n");
    if (ParsePacket(rawPacket, state, &packet, &isLoopBack, &isXmas) != 0)
    {
        return NF_DROP;
    }

    if (isLoopBack)
    {
        return NF_ACCEPT;
    }

    log_row_t logRow;
    UpdateLogFromPacket(packet, &logRow);
    if (isXmas)
    {
        logRow.reason = REASON_XMAS_PACKET;
        logRow.action = NF_DROP;
        LogAction(logRow, logger);
        return logRow.action;
    }

    int action = MatchPacket(packet, ruleManager, &logRow);
    if (action != NO_MATCHING_RULE)
    {
        LogAction(logRow, logger);
        return action;
    };

    // accept by default
    logRow.reason = REASON_NO_MATCHING_RULE;
    logRow.action = NF_DROP;
    LogAction(logRow, logger);

    return logRow.action;
}
