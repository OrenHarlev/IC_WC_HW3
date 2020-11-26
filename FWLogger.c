
#include "FWLogger.h"
#include <linux/kernel.h>

typedef struct
{
    log_row_t logRow;
} LogNode;

struct LogRecord
{
};

Logger CreateLogger(){}

void FreeLogger(Logger logger){}

int LogAction(log_row_t logRow, Logger logger){}

ssize_t ReadLogs(char* buff, size_t length, Logger logger){}

int ResetLogReader(Logger logger){}

ssize_t ResetLogs(Logger logger){}
