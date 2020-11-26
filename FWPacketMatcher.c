
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "FWPacketMatcher.h"
#include "fw.h"

int MatchRawPacket(struct sk_buff *rowPacket, const struct nf_hook_state *state, RuleManager ruleManager, log_row_t *actionLog){}
