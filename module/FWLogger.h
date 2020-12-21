#ifndef FWLOGER_H
#define FWLOGER_H

#include <linux/kernel.h>
#include "fw.h"
#include "FWPacketParser.h"


typedef struct LogList *Logger;

Logger CreateLogger(void);

void FreeLogger(Logger logger);

int LogAction(log_row_t logRow, Logger logger);

ssize_t ReadLogs(char* buff, size_t length, Logger logger);

int ResetLogReader(Logger logger);

ssize_t ResetLogs(Logger logger);

#endif
