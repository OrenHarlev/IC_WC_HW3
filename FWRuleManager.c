#include "FWRuleManager.h"
#include "fw.h"

int UpdateRules(const char *rawRulesTable){}

__u8 GetNumberOfRules(){}

int GetRules(rule_t *rulesTable){}

__u8 MatchPacket(packet_t packet, char* ruleNameBuff){};

int GetRawRules(char *buff){}

int ParseRules(char* rules, rule_t *rulesTable, __u8 *numberOfRules){}

int ParseRule(char* rawRule, rule_t *rule){}

