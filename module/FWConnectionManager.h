#ifndef FW_STATE_MANAGER_H
#define FW_STATE_MANAGER_H

#include "fw.h"
#include "FWPacketParser.h"

typedef struct ConnectionList *ConnectionManager;

ConnectionManager CreateConnectionManager(void);

void FreeConnectionManager(ConnectionManager connectionManager);

ssize_t ReadConnections(ConnectionManager connectionManager, char* buff);

ssize_t AddRawConnection(const char *rawPacket, size_t count, ConnectionManager connectionManager);

unsigned int MatchAndUpdateConnection(packet_t packet, ConnectionManager connectionManager, log_row_t *logRow);

bool GetConnectionFromClient(ConnectionManager connectionManager, __be32 cIp, __be16 cPort, connection_t *connection);

bool GetConnectionFromServer(ConnectionManager connectionManager, __be32 sIp, __be16 sPort, __be16 deepInspectionPort, connection_t *connection);

#endif
