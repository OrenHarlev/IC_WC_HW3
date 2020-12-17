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

typedef enum
{
    LISTEN,
    SYN_RCVD,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
    CLOSED,
} state_t;

typedef struct
{
    __be32	cIp;
    __be32	sIp;
    __be16	cPort; 			// number of port or 0 for any or port 1023 for any port number > 1023
    __be16	sPort; 			// number of port or 0 for any or port 1023 for any port number > 1023
    state_t cState;
    state_t sState;
} connection_t;

typedef struct
{
    connection_t connection;
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
    connectionManager->nextReadNode = NULL;

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

int AddConnection(ConnectionManager connectionManager, packet_t packet)
{
    ConnectionRecord *connectionRecord = kmalloc(sizeof(ConnectionRecord), GFP_KERNEL);

    UpdateConnectionFromClientPacket(&connectionRecord->connection, packet);

    connectionRecord->connection.cState = SYN_SENT;
    connectionRecord->connection.sState = LISTEN;

    connectionRecord->timestamp = ktime_get_real();

    klist_add_head(&connectionRecord->node, connectionManager->list);

    return 0;
}

bool MatchAndUpdateStateListen(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != LISTEN)
    {
        printk(KERN_ERR "Invalid state. expected state LISTEN.\n");
        return false;
    }
    if (*otherState != SYN_SENT)
    {
        printk(KERN_ERR "Invalid state. server can be in LISTEN state only when client in SYN_SEND.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
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
    if ((*otherState) != LISTEN && (*otherState) != SYN_RCVD)
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
    // last stage of 3-way hand shake
    if (*otherState == SYN_RCVD && packet.ack == ACK_YES && !packet.syn)
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
    if ((*otherState) != SYN_SENT && (*otherState) != ESTABLISHED)
    {
        printk(KERN_ERR "Invalid state. server can be in SYN_RCVD state only when client in SYN_SENT or ESTABLISHED.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // resending syn-ack
    if (*otherState == SYN_SENT && packet.ack == ACK_YES && packet.syn)
    {
        return true;
    }
    // connection established
    if (*otherState == ESTABLISHED && !packet.syn && !packet.fin)
    {
        *state = ESTABLISHED;
        return true;
    }
    // active closing connection
    if (packet.fin)
    {
        *state = FIN_WAIT_1;
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
    if ((*otherState) != SYN_RCVD && (*otherState) != ESTABLISHED && (*otherState) != FIN_WAIT_1)
    {
        printk(KERN_ERR "Invalid state. state can be ESTABLISHED only when the other side  in SYN_RCVD, ESTABLISHED or FIN_WAIT_1.\n");
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
        *state = FIN_WAIT_1;
        return true;
    }
    // passive close
    if (*otherState == FIN_WAIT_1 && packet.ack == ACK_YES)
    {
        *state = CLOSE_WAIT;
        if (packet.fin)
        {
            *state = LAST_ACK;
        }
        return true;
    }
    return true;
}


bool MatchAndUpdateStateFinWait1(state_t *state, packet_t packet, state_t *otherState)
{
    if (*state != FIN_WAIT_1)
    {
        printk(KERN_ERR "Invalid state. expected state FIN_WAIT_1.\n");
        return false;
    }
    if ((*otherState) == LISTEN)
    {
        printk(KERN_ERR "Invalid state. state can't be FIN_WAIT_1 when the other side in LISTEN.\n");
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
    // todo change to one closing state
    if (*otherState == FIN_WAIT_1 && packet.ack == ACK_YES)
    {
        *state = CLOSING;
        return true;
    }
    if ((*otherState == CLOSING || *otherState == TIME_WAIT || *otherState == LAST_ACK) && packet.ack == ACK_YES)
    {
        *state = TIME_WAIT;
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
    if ((*otherState) != FIN_WAIT_1 && (*otherState) != FIN_WAIT_2)
    {
        printk(KERN_ERR "Invalid state. state can be CLOSE_WAIT only when the other side in FIN_WAIT.\n");
        *state = CLOSED;
        *otherState = CLOSED;
        return false;
    }
    // no packet in this state should be a syn packet
    if (packet.syn)
    {
        return false;
    }
    // closing todo change last_ack to close
    if (packet.fin)
    {
        *state = LAST_ACK;
        return true;
    }

    return false;
}

// todo remove fin_wait_2
bool MatchAndUpdateStateFinWait2(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != FIN_WAIT_2)
    {
        // todo error
        return false;
    }
    if (packet.syn)
    {
        // todo close connection?
        return false;
    }
    if (packet.ack == ACK_YES)
    {
        *state = TIME_WAIT;
        return true;
    }
    // todo close connection?
    return false;
}

bool MatchAndUpdateStateClosing(state_t *state, packet_t packet, state_t otherState)
{
    return false;
}

bool MatchAndUpdateStateTimeWait(state_t *state, packet_t packet, state_t otherState)
{
    return false;
}

bool MatchAndUpdateStateCloseLastAck(state_t *state, packet_t packet, state_t otherState)
{
    return false;
}

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
        case FIN_WAIT_1:
            return MatchAndUpdateStateFinWait1(state, packet, otherState);
        case FIN_WAIT_2:
            return MatchAndUpdateStateFinWait2(state, packet, otherState);
        case CLOSING:
            return MatchAndUpdateStateClosing(state, packet, otherState);
        case TIME_WAIT:
            return MatchAndUpdateStateTimeWait(state, packet, otherState);
        case CLOSE_WAIT:
            return MatchAndUpdateStateCloseWait(state, packet, otherState);
        case LAST_ACK:
            return MatchAndUpdateStateCloseLastAck(state, packet, otherState);
        case CLOSED:
            return false;
    }
}

int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow)
{
    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(connectionManager->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        bool isClient;
        ConnectionRecord *connectionRecord = container_of(listNode, ConnectionRecord, node);

        // If connection is not active, remove it.
        if (IsTimedOut(connectionManager, connectionRecord->timestamp) || IsClosed(connectionRecord->connection))
        {
            RemoveConnection(connectionRecord);
            continue;
        }


        if (MatchPacketToConnection(packet, connectionRecord->connection, &isClient))
        {
            state_t *state = isClient ? &connectionRecord->connection.cState : &connectionRecord->connection.sState;
            state_t *otherState = isClient ? &connectionRecord->connection.sState : &connectionRecord->connection.cState;
            if (MatchAndUpdateState(state, packet, otherState))
            {
                connectionRecord->timestamp = ktime_get_real();
                logRow->action = NF_ACCEPT;
                logRow->reason = REASON_ACTIVE_CONNECTION;
            }
            else
            {
                logRow->action = NF_DROP;
                logRow->reason = REASON_STATE_DONT_MATCH;
            }

            klist_iter_exit(&iterator);
            return logRow->action;
        }
    }

    // If it is a syn packet, adding a new connection to the table
    if (packet.syn && packet.ack == ACK_NO)
    {
        AddConnection(connectionManager, packet);
    }
    else // no matching connection
    {
        logRow->action = NF_DROP;
        logRow->reason = REASON_NO_MATCHING_CONNECTION;
    }

    klist_iter_exit(&iterator);
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
                           "%lld %pI4h %pI4h %u %u %u %u\n",
                           connectionRecord->timestamp,
                           &connection.cIp,
                           &connection.sIp,
                           connection.cPort,
                           connection.sPort,
                           connection.cState,
                           connection.sState);
    }

    klist_iter_exit(&iterator);
    return offset;
}