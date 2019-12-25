#include "FileWriter.h"
#include <stdio.h>
#include <Windows.h>


int WriteResultsToFile(char* DataBuffer)
{
    int status = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char* outputFileName = NULL;
    int lengthOfBuffer = 0;
    DWORD nrBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    // name of the output file
    outputFileName = (char*)calloc(OUTPUT_FILENAME_LEN, sizeof(char));
    if (!outputFileName)
    {
        printf("[Error] Memory allocation failed in WriteResultsToFile\n");
        status = STATUS_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }
    strcpy_s(outputFileName, OUTPUT_FILENAME_LEN, "PE_dumpedData.log");

    hFile = CreateFile(outputFileName,
        FILE_APPEND_DATA,           // open for writeing (append to existing file)
        0,
        NULL,
        OPEN_ALWAYS,                // open existing or create new
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("[Error] CreateFile failed in WriteResultsToFile\n");
        status = STATUS_ERROR_WRITE_FILE;
        goto cleanup;
    }

    lengthOfBuffer = strnlen_s(DataBuffer, MAX_BUFFER_LEN);
    bErrorFlag = WriteFile(hFile, DataBuffer, lengthOfBuffer, &nrBytesWritten, NULL);
    if (FALSE == bErrorFlag)
    {
        printf("[Error] WriteFile failed in WriteResultsToFile\n");
        status = STATUS_ERROR_WRITE_FILE;
        goto cleanup;
    }
    else
    {
        if (nrBytesWritten != lengthOfBuffer)
        {
            printf("[Error] WriteFile failed in WriteResultsToFile (nrBytesWritten != lengthOfBuffer)\n");
            status = STATUS_ERROR_WRITE_FILE;
            goto cleanup;
        }
    }

cleanup:
    if (outputFileName)
    {
        free(outputFileName);
    }
    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }

    return status;
}