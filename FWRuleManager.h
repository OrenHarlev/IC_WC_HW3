
#ifndef FW_RULE_MANAGER_H
#define FW_RULE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

#define NO_MATCHING_RULE (-1)

typedef struct RuleTable *RuleManager;

RuleManager CreateRuleManager();

void FreeRuleManager(RuleManager ruleManager);

ssize_t UpdateRules(const char *rawRulesTable, size_t count, RuleManager ruleManager);

__u8 GetNumberOfRules(RuleManager ruleManager);

ssize_t GetRawRules(RuleManager ruleManager, char* buff);

int MatchPacket(packet_t packet, RuleManager ruleManager, log_row_t *logRow);

void UpdateLogFromPacket(packet_t packet, log_row_t *logRow);

#endif
