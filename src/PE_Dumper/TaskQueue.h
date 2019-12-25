#pragma once
#include "list.h"

typedef struct
{
    char* path;
    LIST_ENTRY listEntry;
} PEFile, *PPEFile;


void InitQueue();
void PushToQueue(char* Path);
char* PopPathFromQueue();
void DestroyQueue();