
#ifndef FW_RULE_MANAGER_H
#define FW_RULE_MANAGER_H

#include "fw.h"

#define NO_MATCHING_RULE (-1)

typedef struct RuleTable *RuleManager;

RuleManager CreateRuleManager(void);

void FreeRuleManager(RuleManager ruleManager);

ssize_t UpdateRules(char *rawRulesTable, size_t count, RuleManager ruleManager);

ssize_t GetRawRules(RuleManager ruleManager, char* buff);

unsigned int MatchPacket(packet_t packet, RuleManager ruleManager, log_row_t *logRow);

#endif
