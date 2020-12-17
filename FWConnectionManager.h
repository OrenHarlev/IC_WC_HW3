#ifndef FW_STATE_MANAGER_H
#define FW_STATE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

typedef struct ConnectionList *ConnectionManager;

ConnectionManager CreateConnectionManager(void);

void FreeConnectionManager(ConnectionManager connectionManager);

ssize_t ReadConnections(ConnectionManager connectionManager, char* buff);

int AddConnection(ConnectionManager connectionManager, packet_t packet);

int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow);

#endif
