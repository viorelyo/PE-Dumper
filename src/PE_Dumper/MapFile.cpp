#include "MapFile.h"
#include <stdio.h>


int MapFile(char* FileName,
    DWORD AccessRights,
    MAP* Map)
{
    DWORD extraFileSize;
    int status;
    DWORD access;

    status = STATUS_SUCCESS;
    access = 0;

    if ((NULL == FileName) || (NULL == Map))
    {
        printf("Invalid parameter(s) \n");
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize Map
    Map->buffer = NULL;
    Map->fileSize = 0;
    Map->hFile = INVALID_HANDLE_VALUE;
    Map->hMap = NULL;

    // open file with CreateFileA and put handle of opened file in Map
    Map->hFile = CreateFileA(FileName,
        AccessRights,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == Map->hFile)
    {
        printf("[ERROR] CreateFileA Failed : %d \n", GetLastError());
        return STATUS_ERROR_FILE_HANDLING;
    }

    // store fileSize 
    Map->fileSize = GetFileSize(Map->hFile, &extraFileSize);
    if (extraFileSize > 0)
    {
        printf("Overflow file size\n");
        status = STATUS_ERROR_FILE_HANDLING;
        goto cleanup;
    }
    if (Map->fileSize == 0)         // Minimal file size
    {
        printf("Size is too low\n");
        status = STATUS_ERROR_FILE_HANDLING;
        goto cleanup;
    }

    if (AccessRights & GENERIC_WRITE)
    {
        access = PAGE_READWRITE;
    }
    else
    {
        access = PAGE_READONLY;
    }

    // CreateFileMapping
    Map->hMap = CreateFileMapping(Map->hFile,
        NULL,
        access,
        0,
        0,
        NULL);
    if (NULL == Map->hMap)
    {
        printf("CreateFileMapping failed %d \n", GetLastError());
        status = STATUS_ERROR_FILE_HANDLING;
        goto cleanup;
    }

    // Calculam AccessRights pentru MapViewOfFile
    if (AccessRights & GENERIC_WRITE)
    {
        access = FILE_MAP_READ | FILE_MAP_WRITE;
    }
    else
    {
        access = FILE_MAP_READ;
    }

    // store into map-buffer MapViewOfFile
    Map->buffer = (BYTE*) MapViewOfFile(Map->hMap,
        access,
        0,
        0,
        0);
    if (NULL == Map->buffer)
    {
        printf("MapViewOfFile failed %d \n", GetLastError());
        status = STATUS_ERROR_FILE_HANDLING;
        goto cleanup;
    }

cleanup:
    if (status < 0)
    {
        UnmapFile(Map);
    }
    return status;
}



void UnmapFile(MAP* Map)
{
    if (NULL == Map)
    {
        printf("Invalid parameter(s) %s %d \n", __FILE__, __LINE__);
        return;
    }

    if (Map->buffer != NULL)
    {
        UnmapViewOfFile(Map->buffer);
        Map->buffer = NULL;
    }

    if (Map->hMap != NULL)
    {
        CloseHandle(Map->hMap);
        Map->hMap = NULL;
    }

    if (Map->hFile != NULL)
    {
        CloseHandle(Map->hFile);
        Map->hFile = INVALID_HANDLE_VALUE;
    }

    Map->fileSize = 0;
}