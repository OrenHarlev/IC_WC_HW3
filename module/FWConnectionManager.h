#ifndef FW_STATE_MANAGER_H
#define FW_STATE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

typedef enum
{
    LISTEN = 1,
    SYN_SENT = 2,
    SYN_RCVD = 3,
    ESTABLISHED = 4,
    FIN_WAIT = 5, // this state includes FIN_WAIT_1 and FIN_WAIT_2 since as a gate-way they are logically the same.
//  FIN_WAIT_2,
            CLOSE_WAIT = 6,
//  CLOSING,
//  TIME_WAIT,
//  LAST_ACK,
            CLOSED = 7, // CLOSING, TIME_WAIT, LAST_ACK will be considered as CLOSED since we are not expecting more packets from those states
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

typedef struct ConnectionList *ConnectionManager;

ConnectionManager CreateConnectionManager(void);

void FreeConnectionManager(ConnectionManager connectionManager);

ssize_t ReadConnections(ConnectionManager connectionManager, char* buff);

ssize_t AddRawConnection(const char *rawPacket, size_t count, ConnectionManager connectionManager);

unsigned int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow);

bool GetConnectionFromClient(ConnectionManager connectionManager, __be32 cIp, __be16 cPort, connection_t *connection);

bool GetConnectionFromServer(ConnectionManager connectionManager, __be32 sIp, __be16 sPort, __be16 deepInspectionPort, connection_t *connection);

#endif
