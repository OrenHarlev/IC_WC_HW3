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

#define CONNECTION_ROW_MAX_PRINT_SIZE (128)

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
    struct klist_node node;
} ConnectionRecord;

struct ConnectionList
{
    struct klist *list;
};

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
    connectionManager->nextReadNode = NULL;

    ResetConnectionReader(connectionManager);

    return connectionManager;
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
    // todo handle case were connection exist

    ConnectionRecord *connectionRecord = kmalloc(sizeof(ConnectionRecord), GFP_KERNEL);
    if (connectionRecord == NULL)
    {
        // todo error
        return -1;
    }

    UpdateConnectionFromClientPacket(&connectionRecord->connection, packet);

    connectionRecord->connection.cState = SYN_SENT;
    connectionRecord->connection.sState = LISTEN;

    klist_add_head(&connectionRecord->node, connectionManager->list);

    return 0;
}

bool MatchAndUpdateStateListen(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != LISTEN)
    {
        // todo error
        return false;
    }
    if (otherState != SYN_SENT)
    {
        // todo close connection?
        return false;
    }
    if (packet.ack == ACK_YES && packet.syn)
    {
        *state = SYN_RCVD;
        return true;
    }
    // todo close connection?
    return false;
}

bool MatchAndUpdateStateSynSent(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != SYN_SENT)
    {
        // todo error
        return false;
    }
    if (otherState == SYN_RCVD && packet.ack == ACK_YES && !packet.syn)
    {
        *state = ESTABLISHED;
        return true;
    }
    else if (otherState == LISTEN && packet.ack == ACK_NO && packet.syn)
    {
        return true;
    }

    // todo close connection?
    return false;
}

bool MatchAndUpdateStateSynRsvd(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != SYN_RCVD)
    {
        // todo error
        return false;
    }
    if (otherState == ESTABLISHED && !packet.syn && !packet.fin)
    {
        *state = ESTABLISHED;
        return true;
    }
    if (otherState == SYN_SENT && packet.ack == ACK_YES && packet.syn)
    {
        return true;
    }
    if (packet.fin)
    {
        *state = FIN_WAIT_1;
        return true;
    }

    // todo close connection?
    return false;
}

bool MatchAndUpdateStateEstablished(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != ESTABLISHED)
    {
        // todo error
        return false;
    }
    if (packet.syn)
    {
        // todo close connection?
        return false;
    }
    if (packet.fin)
    {
        *state = FIN_WAIT_1;
        return true;
    }
    if (otherState == FIN_WAIT_1 || otherState == FIN_WAIT_2)
    {
        *state = CLOSE_WAIT;
        return true;
    }
    return true;
}

bool MatchAndUpdateStateFinWait1(state_t *state, packet_t packet, state_t otherState)
{
    if (*state != FIN_WAIT_1)
    {
        // todo error
        return false;
    }
    if (packet.syn)
    {
        // todo close connection?
        return false;
    }
    if (packet.fin)
    {
        return true;
    }
    if (otherState == FIN_WAIT_1 && packet.ack == ACK_YES)
    {
        *state = CLOSING;
        return true;
    }
    if ((otherState == CLOSING || otherState == TIME_WAIT || otherState == LAST_ACK) && packet.ack == ACK_YES)
    {
        *state = TIME_WAIT;
        return true;
    }
    // todo handle other in CLOSE_WAIT
    // todo close connection?
    return false;
}

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

bool MatchAndUpdateStateCloseWait(state_t *state, packet_t packet, state_t otherState)
{
    if (packet.fin)
    {
        *state = LAST_ACK;
        return true;
    }
    // todo close connection?
    return false;
}

bool MatchAndUpdateStateCloseLastAck(state_t *state, packet_t packet, state_t otherState)
{
    return false;
}

bool MatchAndUpdateState(state_t *state, packet_t packet, state_t otherState)
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
        if (MatchPacketToConnection(packet, connectionRecord->connection, &isClient))
        {
            state_t *state = isClient ? &connectionRecord->connection.cState : &connectionRecord->connection.sState;
            state_t otherState = isClient ? connectionRecord->connection.sState : connectionRecord->connection.cState;
            if (MatchAndUpdateState(state, packet, otherState))
            {
                logRow->action = NF_ACCEPT;
                logRow->reason = REASON_ACTIVE_CONNECTION;
                // todo remove if connection closed.
                // todo update matching connection.
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

    klist_iter_exit(&iterator);
    logRow->action = NF_DROP;
    logRow->reason = REASON_NO_MATCHING_CONNECTION;
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
                           "%pI4h %pI4h %u %u %u %u\n",
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