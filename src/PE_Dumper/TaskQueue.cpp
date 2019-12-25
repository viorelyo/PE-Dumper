#include "TaskQueue.h"

LIST_ENTRY* QueueHead;
CRITICAL_SECTION queue_criticalSection;


void InitQueue()
{
    QueueHead = (LIST_ENTRY*)malloc(sizeof(LIST_ENTRY));
    InitializeListHead(QueueHead);
    InitializeCriticalSection(&queue_criticalSection);
}


void PushToQueue(char* Path)
{
    PEFile* peFile = NULL;

    peFile = (PEFile*)malloc(sizeof(PEFile));
    if (NULL == peFile)
    {
        return;
    }
    peFile->path = Path;
    InterlockedInsertTailList(QueueHead, &(peFile->listEntry), &queue_criticalSection);
}


char* PopPathFromQueue()
{
    if (IsListEmpty(QueueHead))
    {
        return NULL;
    }

    LIST_ENTRY* firstEntry = NULL;
    PEFile* peFile = NULL;
    char* path = NULL;
    
    firstEntry = QueueHead->Flink;
    peFile = (PEFile*)CONTAINING_RECORD(firstEntry, PEFile, listEntry);
    if (peFile)
    {
        path = peFile->path;
        RemoveHeadList(QueueHead);
        free(peFile);
        peFile = NULL;
    }
    else
    {
        path = NULL;
    }

    return path;
}


void DestroyQueue()
{
    if (QueueHead)
    {
        free(QueueHead);
        QueueHead = NULL;
    }
    DeleteCriticalSection(&queue_criticalSection);
}