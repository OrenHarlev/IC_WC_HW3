#ifndef FW_NETWORK_FILTER_H
#define FW_NETWORK_FILTER_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fw.h"
#include "FWPacketParser.h"
#include "FWRuleManager.h"

int MatchRawPacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, RuleManager ruleManager, log_row_t *actionLog);

#endif
