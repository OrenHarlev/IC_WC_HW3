#ifndef FW_STATE_MANAGER_H
#define FW_STATE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

typedef struct ConnectionList *ConnectionManager;

ConnectionManager CreateConnectionManager(void);

void FreeConnectionManager(ConnectionManager connectionManager);

ssize_t ReadConnections(ConnectionManager connectionManager, char* buff);

ssize_t AddRawConnection(char *rawPacket, size_t count, ConnectionManager connectionManager);

int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow);

#endif
