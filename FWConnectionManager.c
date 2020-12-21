#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/klist.h>
#include <linux/ktime.h>
#include <linux/slab.h>

#include "FWPacketParser.h"
#include "fw.h"
#include "FWConnectionManager.h"

#define CONNECTION_EXPIRATION_TIME_SEC 600
#define CONNECTION_IDENTIFIER_SIZE 5

typedef struct
{
    connection_t connection;
    __be16 deepInspectionPort;
    ktime_t timestamp;
    struct klist_node node;
} ConnectionRecord;

struct ConnectionList
{
    ktime_t connectionTimeout;
    struct klist *list;
};

bool IsClosed(connection_t connection)
{
    return connection.cState == CLOSED && connection.sState == CLOSED;
}

ConnectionManager CreateConnectionManager(void)
{
    ConnectionManager connectionManager = kmalloc(sizeof(struct ConnectionList), GFP_KERNEL);
    if (connectionManager == NULL)
    {
        return connectionManager;
    }

    connectionManager->list = kmalloc(sizeof(struct klist), GFP_KERNEL);
    if (connectionManager->list == NULL)
    {
        kfree(connectionManager);
        return NULL;
    }

    klist_init(connectionManager->list, NULL, NULL);
    connectionManager->connectionTimeout = ktime_set(CONNECTION_EXPIRATION_TIME_SEC, 0);

    return connectionManager;
}

bool IsTimedOut(ConnectionManager connectionManager, ktime_t time)
{
    return ktime_after(ktime_get_real(), ktime_add(time, connectionManager->connectionTimeout));
}

void RemoveConnection(ConnectionRecord *connectionRecord)
{
    klist_del(&connectionRecord->node);
    kfree(connectionRecord);
}

ssize_t ResetConnections(ConnectionManager connectionManager)
{
    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(connectionManager->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        RemoveConnection((ConnectionRecord*)container_of(listNode, ConnectionRecord, node));
    }

    klist_iter_exit(&iterator);
    return 0;
}

void FreeConnectionManager(ConnectionManager connectionManager)
{
    ResetConnections(connectionManager);
    kfree(connectionManager->list);
    kfree(connectionManager);
}

void UpdateConnectionFromClientPacket(connection_t *connection, packet_t packet)
{
    connection->cIp = packet.src_ip;
    connection->sIp = packet.dst_ip;
    connection->cPort = packet.src_port;
    connection->sPort = packet.dst_port;
}

bool MatchClientPacketToConnection(packet_t packet, connection_t connection)
{
    return packet.src_ip == connection.cIp     &&
           packet.dst_ip == connection.sIp     &&
           packet.src_port == connection.cPort &&
           packet.dst_port == connection.sPort;
}

bool MatchServerPacketToConnection(packet_t packet, connection_t connection)
{
    return packet.src_ip == connection.sIp     &&
           packet.dst_ip == connection.cIp     &&
           packet.src_port == connection.sPort &&
           packet.dst_port == connection.cPort;
}

bool MatchPacketToConnection(packet_t packet, connection_t connection, bool *isClient)
{
    if (MatchClientPacketToConnection(packet, connection))
    {
        *isClient = true;
        return true;
    }
    if (MatchServerPacketToConnection(packet, connection))
    {
        *isClient = false;
        return true;
    }
    return false;
}

ConnectionRecord* FindConnection(ConnectionManager connectionManager, packet_t packet, bool *isClient)
{
    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(connectionManager->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        ConnectionRecord *connectionRecord = container_of(listNode, ConnectionRecord, node);

        // If connection is not active, remove it.
        if (IsTimedOut(connectionManager, connectionRecord->timestamp) || IsClosed(connectionRecord->connection))
        {
            RemoveConnection(connectionRecord);
            continue;
        }

        // check if packet match to the connection
        if (MatchPacketToConnection(packet, connectionRecord->connection, isClient))
        {
            klist_iter_exit(&iterator);
            return connectionRecord;
        }
    }
    klist_iter_exit(&iterator);
    return NULL;
}

void AddConnection(ConnectionManager connectionManager, packet_t packet, __be16 deepInspectionPort)
{
    ConnectionRecord *connectionRecord;
    bool isClient; // not used in this function.
    if (deepInspectionPort == 0)
    {
        connectionRecord = kmalloc(sizeof(ConnectionRecord), GFP_KERNEL);
        klist_add_head(&connectionRecord->node, connectionManager->list);
        UpdateConnectionFromClientPacket(&connectionRecord->connection, packet);
        connectionRecord->connection.cState = SYN_SENT;
        connectionRecord->connection.sState = LISTEN;
    }
    else
    {
        connectionRecord = FindConnection(connectionManager, packet, &isClient);
        if (connectionRecord == NULL)
        {
            printk(KERN_ERR "Failed to update deep inspection port, connection not in table.\n");
            return;
        }
    }

    connectionRecord->timestamp = ktime_get_real();
    connectionRecord->deepInspectionPort = deepInspectionPort;
}

int ParseConnection(const char* rawConnection, packet_t *packet, __be16 *deepInspectionPort)
{
    int res = sscanf(rawConnection,
                     "%u %u %u %u %u",
                     &packet->src_ip,
                     &packet->dst_ip,
                     &packet->src_port,
                     &packet->dst_port,
                     deepInspectionPort);

    if (res != CONNECTION_IDENTIFIER_SIZE)
    {
        printk(KERN_ERR "Failed to parse connection. Missing rule args %u out of %u\n", res, CONNECTION_IDENTIFIER_SIZE);
        return -1;
    }

    return 0;
}

ssize_t AddRawConnection(const char *rawPacket, size_t count, ConnectionManager connectionManager)
{
    packet_t packet;
    __be16 deepInspectionPort;
    if (ParseConnection(rawPacket, &packet, &deepInspectionPort) != 0)
    {
        printk(KERN_ERR "FW Connection update failed. Failed to parse connection");
        return -1;
    }
    AddConnection(connectionManager, packet, deepInspectionPort);
    return count;
}

bool IsDeepInspectionPort(__be16 port)
{
    return port == PORT_HTTP || port == PORT_FTP_CONTROL;
}

bool MatchAndUpdateStateListen(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != LISTEN)
    {
        printk(KERN_ERR "Invalid state. expected state LISTEN.\n");
        return false;
    }
    if (*otherState != SYN_SENT && !IsDeepInspectionPort(packet.src_port))
    {
        printk(KERN_ERR "Invalid state. server can be in LISTEN state only when client in SYN_SEND.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // sending syn-ack after receiving syn
    if (packet.ack == ACK_YES && packet.syn)
    {
        *state = SYN_RCVD;
        return true;
    }

    return false;
}

bool MatchAndUpdateStateSynSent(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != SYN_SENT)
    {
        printk(KERN_ERR "Invalid state. expected state SYN_SENT.\n");
        return false;
    }
    if ((*otherState) != LISTEN && (*otherState) != SYN_RCVD && !IsDeepInspectionPort(packet.dst_port))
    {
        printk(KERN_ERR "Invalid state. client can be in SYN_SENT state only when server in LISTEN or SYN_RCVD.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // resend of syn packet
    if (packet.syn && packet.ack == ACK_NO)
    {
        return true;
    }
    // last stage of 3-way hand shake - sending ack after receiving syn-ack
    if ((*otherState == SYN_RCVD || IsDeepInspectionPort(packet.dst_port)) && packet.ack == ACK_YES && !packet.syn)
    {
        *state = ESTABLISHED;
        return true;
    }

    return false;
}

bool MatchAndUpdateStateSynRsvd(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != SYN_RCVD)
    {
        printk(KERN_ERR "Invalid state. expected state SYN_RCVD.\n");
        return false;
    }
    if ((*otherState) != SYN_SENT && (*otherState) != ESTABLISHED && !IsDeepInspectionPort(packet.src_port))
    {
        printk(KERN_ERR "Invalid state. server can be in SYN_RCVD state only when client in SYN_SENT or ESTABLISHED.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // resending syn-ack
    if ((*otherState == SYN_SENT || IsDeepInspectionPort(packet.src_port)) && packet.ack == ACK_YES && packet.syn)
    {
        return true;
    }
    // connection established
    if ((*otherState == ESTABLISHED || IsDeepInspectionPort(packet.src_port))&& !packet.syn && !packet.fin)
    {
        *state = ESTABLISHED;
        return true;
    }
    // active close
    if (packet.fin)
    {
        *state = FIN_WAIT;
        return true;
    }

    return false;
}

bool MatchAndUpdateStateEstablished(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != ESTABLISHED)
    {
        printk(KERN_ERR "Invalid state. expected state ESTABLISHED.\n");
        return false;
    }
    if ((*otherState) != SYN_RCVD && (*otherState) != ESTABLISHED && (*otherState) != FIN_WAIT && !IsDeepInspectionPort(packet.src_port) && !IsDeepInspectionPort(packet.dst_port))
    {
        printk(KERN_ERR "Invalid state. state can be ESTABLISHED only when the other side  in SYN_RCVD, ESTABLISHED or FIN_WAIT.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // no packet in this state should be a syn packet
    if (packet.syn)
    {
        return false;
    }
    // active close
    if (packet.fin)
    {
        if (*otherState == FIN_WAIT || *otherState == CLOSED)
        {
            *state = CLOSED;
        }
        else
        {
            *state = FIN_WAIT;
        }
        return true;
    }
    // passive close - sending ack after syn received
    if (*otherState == FIN_WAIT && packet.ack == ACK_YES)
    {
        *state = CLOSE_WAIT;
        return true;
    }
    return true;
}

bool MatchAndUpdateStateFinWait(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != FIN_WAIT)
    {
        printk(KERN_ERR "Invalid state. expected state FIN_WAIT.\n");
        return false;
    }
    if ((*otherState) == LISTEN && !IsDeepInspectionPort(packet.dst_port))
    {
        printk(KERN_ERR "Invalid state. state can't be FIN_WAIT when the other side in LISTEN.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // no packet in this state should be a syn packet
    if (packet.syn)
    {
        return false;
    }
    // resending fin
    if (packet.fin)
    {
        return true;
    }
    // closing - sending ack after syn received
    if (((*otherState) == FIN_WAIT || (*otherState) == CLOSED || IsDeepInspectionPort(packet.dst_port) || IsDeepInspectionPort(packet.src_port)) && packet.ack == ACK_YES)
    {
        *state = CLOSED;
        return true;
    }

    return false;
}

bool MatchAndUpdateStateCloseWait(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != CLOSE_WAIT)
    {
        printk(KERN_ERR "Invalid state. expected state CLOSE_WAIT.\n");
        return false;
    }
    if ((*otherState) != FIN_WAIT && (*otherState) != CLOSED && !IsDeepInspectionPort(packet.src_port) && !IsDeepInspectionPort(packet.dst_port))
    {
        printk(KERN_ERR "Invalid state. state can be CLOSE_WAIT only when the other side in FIN_WAIT or CLOSED.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // no packet in this state should be a syn packet
    if (packet.syn)
    {
        return false;
    }
    // closing
    if (packet.fin)
    {
        *state = CLOSED;
        return true;
    }

    return false;
}

// todo change to use connectionRecord
bool MatchAndUpdateState(state_t *state, packet_t packet, state_t *otherState)
{
    switch (*state)
    {
        case LISTEN:
            return MatchAndUpdateStateListen(state, packet, otherState);
        case SYN_SENT:
            return MatchAndUpdateStateSynSent(state, packet, otherState);
        case SYN_RCVD:
            return MatchAndUpdateStateSynRsvd(state, packet, otherState);
        case ESTABLISHED:
            return MatchAndUpdateStateEstablished(state, packet, otherState);
        case FIN_WAIT:
            return MatchAndUpdateStateFinWait(state, packet, otherState);
        case CLOSE_WAIT:
            return MatchAndUpdateStateCloseWait(state, packet, otherState);
        case CLOSED:
            return false;
    }
    return false;
}

unsigned int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow)
{
    bool isClient;
    ConnectionRecord *connectionRecord = FindConnection(connectionManager, packet, &isClient);

    if (connectionRecord != NULL) // found matching connection
    {
        state_t *state = isClient ? &connectionRecord->connection.cState : &connectionRecord->connection.sState;
        state_t *otherState = isClient ? &connectionRecord->connection.sState : &connectionRecord->connection.cState;

        // check if the packet match to the connection state
        if (MatchAndUpdateState(state, packet, otherState))
        {
            connectionRecord->timestamp = ktime_get_real();
            logRow->action = NF_ACCEPT;
            logRow->reason = REASON_ACTIVE_CONNECTION;
        }
        else // packet don't match connection state.
        {
            logRow->action = NF_DROP;
            logRow->reason = REASON_STATE_DONT_MATCH;
        }
    }
    else
    {
        // If it is a syn packet, adding a new connection to the table
        if (packet.syn && packet.ack == ACK_NO)
        {
            AddConnection(connectionManager, packet, 0);
        }
        else // no matching connection
        {
            logRow->action = NF_DROP;
            logRow->reason = REASON_NO_MATCHING_CONNECTION;
        }
    }

    return logRow->action;
}

ssize_t ReadConnections(ConnectionManager connectionManager, char* buff)
{
    ssize_t offset = 0;
    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(connectionManager->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        ConnectionRecord *connectionRecord = container_of(listNode, ConnectionRecord, node);
        connection_t connection = connectionRecord->connection;

        offset += snprintf(buff + offset,
                           PAGE_SIZE - offset,
                           "%lld %pI4h %pI4h %u %u %u %u %u\n",
                           connectionRecord->timestamp,
                           &connection.cIp,
                           &connection.sIp,
                           connection.cPort,
                           connection.sPort,
                           connection.cState,
                           connection.sState,
                           connectionRecord->deepInspectionPort);
    }

    klist_iter_exit(&iterator);
    return offset;
}

bool GetConnectionFromClient(ConnectionManager connectionManager, __be32 cIp, __be16 cPort, connection_t *connection)
{
    // todo
}

bool GetConnectionFromServer(ConnectionManager connectionManager, __be32 sIp, __be16 sPort, __be16 deepInspectionPort, connection_t *connection)
{
    // todo
}