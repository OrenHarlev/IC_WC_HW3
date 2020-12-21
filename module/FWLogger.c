#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/klist.h>
#include <linux/ktime.h>
#include <linux/slab.h>

#include "fw.h"
#include "FWLogger.h"
#include "FWPacketParser.h"

#define LOG_ROW_MAX_PRINT_SIZE (256)

struct LogList
{
    struct klist *list;
    struct klist_node *nextReadNode;
};

typedef struct
{
    log_row_t log;
    struct klist_node node;
} LogRecord;

Logger CreateLogger(void)
{
    Logger logger = kmalloc(sizeof(struct LogList), GFP_KERNEL);
    if (logger == NULL)
    {
        return logger;
    }

    logger->list = kmalloc(sizeof(struct klist), GFP_KERNEL);
    if (logger->list == NULL)
    {
        kfree(logger);
        return NULL;
    }

    klist_init(logger->list, NULL, NULL);
    logger->nextReadNode = NULL;

    ResetLogReader(logger);

    return logger;
}

void FreeLogger(Logger logger)
{
    ResetLogs(logger);
    kfree(logger->list);
    kfree(logger);
}

bool MatchRecords(log_row_t recordX, log_row_t recordY)
{
    return recordX.reason == recordY.reason     &&
           recordX.src_ip == recordY.src_ip     &&
           recordX.dst_ip == recordY.dst_ip     &&
           recordX.src_port == recordY.src_port &&
           recordX.dst_port == recordY.dst_port &&
           recordX.protocol == recordY.protocol &&
           recordX.action == recordY.action;
}

int LogAction(log_row_t logRow, Logger logger)
{
    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(logger->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        LogRecord *logRecord = container_of(listNode, LogRecord, node);
        if (MatchRecords(logRecord->log, logRow))
        {
            logRecord->log.count++;
            logRecord->log.timestamp = ktime_get_real();
            klist_iter_exit(&iterator);
            return 0;
        }
    }

    LogRecord *newLogRecord = kmalloc(sizeof(LogRecord), GFP_KERNEL);
    if (newLogRecord == NULL)
    {
        return -1;
    }

    memcpy(&newLogRecord->log, &logRow, sizeof(log_row_t));
    newLogRecord->log.timestamp = ktime_get_real();
    newLogRecord->log.count = 1;

    klist_add_head(&newLogRecord->node, logger->list);

    return 0;
}

ssize_t ReadLogs(char* buff, size_t length, Logger logger)
{
    if (logger->nextReadNode == NULL)
    {
        return 0;
    }

    struct klist_iter iterator;
    klist_iter_init_node(logger->list, &iterator, logger->nextReadNode);

    ssize_t buffOffset = 0;
    ssize_t logRowSize;
    char logRow[LOG_ROW_MAX_PRINT_SIZE];

    while(logger->nextReadNode != NULL && buffOffset < length)
    {
        LogRecord *logRecord = container_of(logger->nextReadNode, LogRecord, node);
        log_row_t log = logRecord->log;

        logRowSize = snprintf(logRow,
                 LOG_ROW_MAX_PRINT_SIZE,
                 "%lld %pI4h %pI4h %u %u %u %u %d %u\n",
                 log.timestamp,
                 &log.src_ip,
                 &log.dst_ip,
                 log.src_port,
                 log.dst_port,
                 log.protocol,
                 log.action,
                 log.reason,
                 log.count);

        if (buffOffset + logRowSize > length)
        {
            break;
        }
        snprintf(buff + buffOffset, length - buffOffset, logRow);
        buffOffset += logRowSize;
        logger->nextReadNode = klist_next(&iterator);
    }

    klist_iter_exit(&iterator);
    return buffOffset;
}

int ResetLogReader(Logger logger)
{
    struct klist_iter iterator;

    klist_iter_init(logger->list, &iterator);

    logger->nextReadNode = klist_next(&iterator);
    klist_iter_exit(&iterator);

    return 0;
}

ssize_t ResetLogs(Logger logger)
{
    logger->nextReadNode = NULL;

    struct klist_iter iterator;
    struct klist_node *listNode;
    klist_iter_init(logger->list, &iterator);

    while((listNode = klist_next(&iterator)) != NULL)
    {
        klist_del(listNode);
        kfree(container_of(listNode, LogRecord, node));
    }

    klist_iter_exit(&iterator);
    return 0;
}
