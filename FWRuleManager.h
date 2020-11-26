
#ifndef FW_RULE_MANAGER_H
#define FW_RULE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

int UpdateRules(const char *rawRulesTable);

__u8 GetNumberOfRules();

int GetRules(rule_t *rulesTable);

__u8 MatchPacket(packet_t packet, char* ruleNameBuff);

#endif
