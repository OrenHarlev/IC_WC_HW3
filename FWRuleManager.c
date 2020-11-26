#include <linux/kernel.h>
#include "FWRuleManager.h"
#include "fw.h"

struct RuleTable
{
    rule_t *rules;
    __u8 NumberOfRules;
};

RuleManager CreateRuleManager(){}

void FreeRuleManager(RuleManager ruleManager){}

ssize_t UpdateRules(const char *rawRulesTable, size_t count, RuleManager ruleManager){}

__u8 GetNumberOfRules(RuleManager ruleManager){}

ssize_t GetRawRules(RuleManager ruleManager, char* buff)
{
    char* rawRules;
    // todo parse rules.
    scnprintf(buff, PAGE_SIZE, "%s", rawRules);
}

int MatchPacket(packet_t packet, RuleManager ruleManager, log_row_t *logRow){}

int ParseRules(char* rules, rule_t *rulesTable, __u8 *numberOfRules){}

int ParseRule(char* rawRule, rule_t *rule){}

