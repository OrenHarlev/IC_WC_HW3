#ifndef FWLOGER_H
#define FWLOGER_H

#include "fw.h"

typedef struct
{
    log_row_t logRow;

} LogNode;
int LogAction(log_row_t* logRow);

int ReadLogs(char* buff);

int ResetLogs();

#endif
