#ifndef FWLOGER_H
#define FWLOGER_H

#include <linux/kernel.h>
#include "fw.h"


typedef struct LogRecord *Logger;

Logger CreateLogger();

void FreeLogger(Logger logger);

int LogAction(log_row_t logRow, Logger logger);

ssize_t ReadLogs(char* buff, size_t length, Logger logger);

int ResetLogReader(Logger logger);

ssize_t ResetLogs(Logger logger);

#endif
