#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "fw.h"
#include "FWPacketParser.h"
#include "FWRuleManager.h"
#include "FWConnectionManager.h"
#include "FWPacketMatcher.h"
#include "FWProxyHelper.h"

bool IsTcpNonSynPacket(packet_t packet)
{
    return packet.protocol == PROT_TCP && packet.ack == ACK_YES;
}

bool IsFtpDataSynPacket(packet_t packet)
{
    return packet.protocol == PROT_TCP &&
           packet.src_port == PORT_FTP_DATA &&
           packet.ack == ACK_NO &&
           packet.syn;
}

unsigned int MatchRawPacket(struct sk_buff *rawPacket, const struct nf_hook_state *state, RuleManager ruleManager, ConnectionManager connectionManager, Logger logger)
{
    packet_t packet;
    bool isXmas;
    bool isLoopBack;

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

    if (IsTcpNonSynPacket(packet) || IsFtpDataSynPacket(packet))
    {
        MatchAndUpdateConnection(packet, connectionManager, &logRow);
    }
    else
    {
        MatchPacket(packet, ruleManager, &logRow);

        // Adding a new connection to the table if not exist
        if (packet.protocol == PROT_TCP && logRow.action == NF_ACCEPT)
        {
            MatchAndUpdateConnection(packet, connectionManager, &logRow);
        }
    }

    LogAction(logRow, logger);

    if (logRow.action == NF_ACCEPT)
    {
        // todo handle error and print if redirected
        RedirectPreRoutPacket(rawPacket, packet);
    }

    return logRow.action;
}
