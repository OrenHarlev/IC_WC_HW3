
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

bool MatchRecords(log_row_t recordX, log_row_t recordY){}

int LogAction(log_row_t logRow, Logger logger)
{
    // todo find row in list
    // if in list update row
    // else allocate new log_raw and add to start of the list
    return 0;
}

ssize_t ReadLogs(char* buff, size_t length, Logger logger){}

int ResetLogReader(Logger logger){}

ssize_t ResetLogs(Logger logger){}
