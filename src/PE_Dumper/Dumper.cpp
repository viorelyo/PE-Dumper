#include "Dumper.h"

extern HANDLE Events[EVENTS_COUNT];
extern HANDLE Threads[MAX_THREAD_COUNT];
extern CRITICAL_SECTION queue_criticalSection;
extern LIST_ENTRY* QueueHead;


int ParsePE(char* FileName, HANDLE hLogFile)
{
    int status = 0;
    PE_INFO peInfo = { 0 };
    MAP map = { 0 };
    
    status = MapFile(FileName,
        GENERIC_READ,
        &map);
    if (0 > status)
    {
        //printf("[ERROR] MapFile failed: %d\n", GetLastError());
        WriteResultsToFile("[ERROR] MapFile failed", hLogFile);
        goto cleanup;
    }

    if (map.fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        WriteResultsToFile("[Error] Size too small for DOS Header", hLogFile);
        return STATUS_ERROR_INVALID_DOS_HEADER;
    }

    // DOS Header Processing
    peInfo.pDOS = (IMAGE_DOS_HEADER*)map.buffer;
    //printf(">> Scanning DOS Header...\n");
    status = ScanDosHeader(peInfo.pDOS, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // NT Header Processing
    if (map.fileSize < (peInfo.pDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
    {
        WriteResultsToFile("[Error] Size too small: Can't find NT Header", hLogFile);
        return STATUS_ERROR_INVALID_NT_HEADER;
    }

    peInfo.pNT = (IMAGE_NT_HEADERS*)((BYTE*)peInfo.pDOS + peInfo.pDOS->e_lfanew);
    //printf(">> Scanning NT Header...\n");
    status = ScanNTHeader(peInfo.pNT, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // File Header Processing
    peInfo.pFileHdr = &peInfo.pNT->FileHeader;
    //printf(">> Scanning File Header...\n");
    status = ScanFileHeader(peInfo.pFileHdr, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // Optional Header Processing
    peInfo.pOptionalHdr = &peInfo.pNT->OptionalHeader;
    //printf(">> Scanning Optional Header...\n");
    status = ScanOptionalHeader(peInfo.pOptionalHdr, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // Section Header Processing
    peInfo.pSectionHdr = (IMAGE_SECTION_HEADER*)((BYTE*)peInfo.pFileHdr + sizeof(IMAGE_FILE_HEADER) + peInfo.pFileHdr->SizeOfOptionalHeader);
    //printf(">> Scanning Section Header...\n");
    status = ScanSectionHeaders(peInfo.pSectionHdr, peInfo.pFileHdr->NumberOfSections, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // Export Directory Processing
    peInfo.pExportDir = ExtractExportDirectory(&peInfo);
    if (NULL == peInfo.pExportDir)
    {
        status = STATUS_ERROR_EXIT_PROGRAM;
        goto cleanup;
    }

    //printf(">> Scanning Export Directory...\n");
    status = ScanExportDirectory(&peInfo, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

    // Import Descriptor Processing
    peInfo.pImportDes = ExtractImportDescriptor(&peInfo);
    if (NULL == peInfo.pImportDes)
    {
        status = STATUS_ERROR_EXIT_PROGRAM;
        goto cleanup;
    }

    //printf(">> Scanning Import Descriptor...\n");
    status = ScanImportDescriptor(&peInfo, hLogFile);
    if (0 > status)
    {
        goto cleanup;
    }

cleanup:
    UnmapFile(&map);

    return status;  
}


/*
* List all files recursively from given path
*/
int ScanDirectory(char* SearchDirectoryPath)
{
    int status = 0;
    size_t lengthOfPath = 0;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA findFileData = { 0 };
    char* path = NULL;
    char directoryPathBuffer[MAX_PATH] = { 0 };

    // Check that the path + "\*\0" (+3 chars) is not longer than MAX_PATH 
    lengthOfPath = strnlen_s(SearchDirectoryPath, MAX_PATH);
    if ((MAX_PATH - 3) < lengthOfPath)
    {
        printf("[Error] Directory path is too long.\n");
        status = STATUS_ERROR_LISTING_DIRECTORY;
        goto cleanup;
    }

    // Prepare DirectoryPathBUffer for FindFirstFile func
    strcpy_s(directoryPathBuffer, MAX_PATH, SearchDirectoryPath);
    strcat_s(directoryPathBuffer, MAX_PATH, "\\*");                   // directoryPathBuffer = "path\*"

    hFind = FindFirstFile(directoryPathBuffer, &findFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        printf("[Error] FindFirstFile failed: %d\n", GetLastError());
        status = STATUS_ERROR_LISTING_DIRECTORY;
        goto cleanup;
    }

    do
    {
        // if is directory look into it
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (('.' != findFileData.cFileName[0]) && strncmp(LOGS_DIRECTORY, findFileData.cFileName, MAX_PATH))         // skip "." and ".." ; exclude LOGS_DIR
            {
                sprintf_s(directoryPathBuffer, "%s\\%s", SearchDirectoryPath, findFileData.cFileName);
                ScanDirectory(directoryPathBuffer);        // recursive call to search in found directory
            }
        }
        else        // if is file
        {
            // Copy found fileName to heap
            path = AppendPath(SearchDirectoryPath, findFileData.cFileName);

            // Add fileName to processing queue
            PushToQueue(path);
            if (0 == SetEvent(Events[0]))       // signal that a fileName was added to the queue so it should be processed
            {
                printf("[Error] SetEvent failed: %d\n", GetLastError());
                return -1;
            }
        }
    } while (0 != FindNextFile(hFind, &findFileData));


cleanup:
    if (INVALID_HANDLE_VALUE != hFind)
    {
        FindClose(hFind);
    }

    return status;
}


/*
* Will be executed by each Thread when was signaled (DoWork function)
*/
int ParseAndLog()
{
    int status = WORK_SUCCESS;
    char* logFileName = NULL;
    char* pathToLogFile = NULL;
    char* path = NULL;
    HANDLE hLogFile = NULL;

    EnterCriticalSection(&queue_criticalSection);
    if (IsListEmpty(QueueHead))
    {
        LeaveCriticalSection(&queue_criticalSection);
        return -1;
    }

    path = PopPathFromQueue();
    printf("Thread: %d is scanning: '%s'\n", GetCurrentThreadId(), path);
    LeaveCriticalSection(&queue_criticalSection);

    // Logging
    logFileName = GenerateLogFileName(path);
    if (NULL == logFileName)
    {
        printf("[Error] Generating logFilename from path failed: %d\n", GetLastError());
        status = ERROR_WORK_FAILED;
        goto cleanup;
    }
    pathToLogFile = AppendPath(LOGS_DIRECTORY, logFileName);
    if (NULL == pathToLogFile)
    {
        printf("[Error] Generating pathToLogFile failed: %d\n", GetLastError());
        status = ERROR_WORK_FAILED;
        goto cleanup;
    }

    hLogFile = CreateFile(pathToLogFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hLogFile)
    {
        printf("[Error] Failed to create logFile: %d\n", GetLastError());
        status = 0;             // just exit from function
        goto cleanup;
    }

    // Parse PE 
    ParsePE(path, hLogFile);

cleanup:
    if (path)
    {
        free(path);
    }
    if (logFileName)
    {
        free(logFileName);
    }
    if (pathToLogFile)
    {
        free(pathToLogFile);
    }
    if (INVALID_HANDLE_VALUE != hLogFile)
    {
        CloseHandle(hLogFile);
    }

    return status;
}


int DumpPEs(char* Path, int nrOfThreads)
{
    CreateEventsAndThreads(nrOfThreads, &ParseAndLog);    
    InitQueue();
    ScanDirectory(Path);

    if (0 == SetEvent(Events[1]))       // there won't be other insertions to queue 
    {
        printf("[Error] SetEvent failed: %d\n", GetLastError());
        return -1;
    }

    WaitForMultipleObjects(nrOfThreads, Threads, TRUE, INFINITE);
    DestroyQueue();
    for (int i = 0; i < EVENTS_COUNT; i++)
    {
        CloseHandle(Events[i]);
    }

    return 0;
}