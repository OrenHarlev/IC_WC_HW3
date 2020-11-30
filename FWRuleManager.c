#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>

#include "FWRuleManager.h"
#include "fw.h"

struct RuleTable
{
    rule_t *rules;
    __u8 NumberOfRules;
};

RuleManager CreateRuleManager(void)
{
    RuleManager ruleManager = kmalloc(sizeof(struct RuleTable), GFP_KERNEL);
    ruleManager->rules = kmalloc(sizeof(rule_t) * MAX_RULES, GFP_KERNEL);
    ruleManager->NumberOfRules = 0;
    return ruleManager;
}

void FreeRuleManager(RuleManager ruleManager)
{
    kfree(ruleManager->rules);
    kfree(ruleManager);
}

bool ValidateRule(rule_t *rule)
{
    switch (rule->direction)
    {
        case DIRECTION_IN:
            break;
        case DIRECTION_OUT:
            break;
        case DIRECTION_ANY:
            break;
        default:
            printk(KERN_ERR "Invalid rule. Invalid direction\n");
            return false;
    }

    if (rule->src_prefix_size > IP_BITS)
    {
        printk(KERN_ERR "Invalid rule. Invalid src_prefix_size - %u\n", rule->src_prefix_size);
        return false;
    }

    if (rule->dst_prefix_size > IP_BITS)
    {
        printk(KERN_ERR "Invalid rule. Invalid dst_prefix_size - %u\n", rule->dst_prefix_size);
        return false;
    }

    if (rule->src_port > PORT_ABOVE_1023)
    {
        printk(KERN_ERR "Invalid rule. Invalid src_port - %u\n", rule->src_port);
        return false;
    }

    if (rule->dst_port > PORT_ABOVE_1023)
    {
        printk(KERN_ERR "Invalid rule. Invalid src_port - %u\n", rule->dst_port);
        return false;
    }

    switch (rule->protocol)
    {
        case PROT_ICMP:
            break;
        case PROT_TCP:
            break;
        case PROT_UDP:
            break;
        case PROT_OTHER:
            break;
        case PROT_ANY:
            break;
        default:
            printk(KERN_ERR "Invalid rule. Invalid protocol - %d\n", rule->protocol);
            return false;
    }

    switch (rule->ack)
    {
        case ACK_YES:
            break;
        case ACK_NO:
            break;
        case ACK_ANY:
            break;
        default:
            printk(KERN_ERR "Invalid rule. Invalid ack\n");
            return false;
    }

    switch (rule->ack)
    {
        case ACK_YES:
            break;
        case ACK_NO:
            break;
        case ACK_ANY:
            break;
        default:
            printk(KERN_ERR "Invalid rule. Invalid ack\n");
            return false;
    }

    if (rule->action != NF_DROP && rule->action != NF_ACCEPT)
    {
        printk(KERN_ERR "Invalid rule. Invalid action\n");
        return false;
    }

    return true;
}

__be32 ConvertToMask(__u8 prefix_size)
{
    return (0xFFFFFFFF << (IP_BITS - prefix_size));
}

int ParseRule(char* rawRule, rule_t *rule)
{
    if ((strchr(rawRule, ' ') - rawRule) > MAX_RULE_NAME)
    {
        printk(KERN_ERR "Failed to parse rule. Rule name is larger then %u\n", MAX_RULE_NAME);
        return -1;
    }

    int res = sscanf(rawRule,
                     "%s %u %u %u %u %u %u %u %u %u %u",
                     rule->rule_name,
                     &rule->direction,
                     &rule->src_ip,
                     &rule->src_prefix_size,
                     &rule->dst_ip,
                     &rule->dst_prefix_size,
                     &rule->protocol,
                     &rule->src_port,
                     &rule->dst_port,
                     &rule->ack,
                     &rule->action);

    if (res != RULE_ARGS)
    {
        printk(KERN_ERR "Failed to parse rule. Missing rule args %u out of %u\n", res, RULE_ARGS);
        return -1;
    }

    if (!ValidateRule(rule))
    {
        printk(KERN_ERR "Failed to parse rule. Rule args are invalid\n");
        return -1;
    }

    rule->src_prefix_mask = ConvertToMask(rule->src_prefix_size);
    rule->dst_prefix_mask = ConvertToMask(rule->dst_prefix_size);

    return 0;
}

ssize_t UpdateRules(char *rawRulesTable, size_t count, RuleManager ruleManager)
{
    __u8 ruleNumber = 0;
    rule_t tempTable[MAX_RULES];

    char *rule;
    while (((rule = strsep(&rawRulesTable, "\n")) != NULL))
    {
        if (strlen(rule) == 0)
        {
            continue;
        }

        ruleNumber++;
        if (ruleNumber > MAX_RULES)
        {
            printk(KERN_ERR "FW Rules update failed. Too many rules, max rules number is %u\n", MAX_RULES);
            return -1;
        }

        if (ParseRule(rule, tempTable + (ruleNumber - 1)) != 0)
        {
            printk(KERN_ERR "FW Rules update failed. Failed to parse rule number %u\n", ruleNumber);
            return -1;
        }
    }

    memcpy(ruleManager->rules, tempTable, sizeof(rule_t) * MAX_RULES);
    ruleManager->NumberOfRules = ruleNumber;

    printk(KERN_INFO "FW Rules update succeeded. Number of rules - %u\n", ruleNumber);
    return count;
}

ssize_t GetRawRules(RuleManager ruleManager, char* buff)
{
    ssize_t offset = 0;
    __u8 i = 0;
    for (; i < ruleManager->NumberOfRules; i++)
    {
        rule_t curRule = ruleManager->rules[i];
        offset += snprintf(buff + offset,
                            PAGE_SIZE - offset,
                            "%s %u %pI4h/%u %pI4h/%u %u %u %u %u %u\n",
                            curRule.rule_name,
                            curRule.direction,
                            &curRule.src_ip,
                            curRule.src_prefix_size,
                            &curRule.dst_ip,
                            curRule.dst_prefix_size,
                            curRule.protocol,
                            curRule.src_port,
                            curRule.dst_port,
                            curRule.ack,
                            curRule.action);
    }

    return offset;
}

bool MatchRule(packet_t packet, rule_t rule)
{
    return
        (rule.direction == DIRECTION_ANY || packet.direction == rule.direction) &&
        (rule.protocol == PROT_ANY || packet.protocol == rule.protocol) &&
        (packet.protocol != PROT_TCP || rule.ack == ACK_ANY || packet.ack == rule.ack) &&
        (packet.protocol == PROT_ICMP || rule.dst_port == PORT_ANY || (rule.dst_port == PORT_ABOVE_1023 && packet.dst_port >= PORT_ABOVE_1023) || packet.dst_port == rule.dst_port) &&
        (packet.protocol == PROT_ICMP || rule.src_port == PORT_ANY || (rule.src_port == PORT_ABOVE_1023 && packet.src_port >= PORT_ABOVE_1023) || packet.src_port == rule.src_port) &&
        (rule.dst_ip == IP_ANY || ((packet.dst_ip & rule.dst_prefix_mask) == (rule.dst_ip & rule.dst_prefix_mask))) &&
        (rule.src_ip == IP_ANY || ((packet.src_ip & rule.src_prefix_mask) == (rule.src_ip & rule.src_prefix_mask)));
}

void UpdateLogFromPacket(packet_t packet, log_row_t *logRow)
{
    logRow->protocol = packet.protocol;
    logRow->src_ip = packet.src_ip;
    logRow->dst_ip = packet.dst_ip;
    logRow->src_port = packet.src_port;
    logRow->dst_port = packet.dst_port;
}

int MatchPacket(packet_t packet, RuleManager ruleManager, log_row_t *logRow)
{
    __u8 i = 0;
    for (; i < ruleManager->NumberOfRules; i++)
    {
        rule_t curRule = ruleManager->rules[i];
        if (MatchRule(packet, curRule))
        {
            logRow->reason = i + 1;
            logRow->action = curRule.action;
            return logRow->action;
        }
    }

    return NO_MATCHING_RULE;
}





