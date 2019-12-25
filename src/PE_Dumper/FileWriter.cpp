#include "FileWriter.h"
#include <stdio.h>


int WriteResultsToFile(char* DataBuffer, HANDLE hLogFile)
{
    int status = 0;
    DWORD lengthOfBuffer = 0;
    DWORD nrBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    lengthOfBuffer = (DWORD)strnlen_s(DataBuffer, MAX_BUFFER_LEN);
    bErrorFlag = WriteFile(hLogFile, DataBuffer, lengthOfBuffer, &nrBytesWritten, NULL);
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
    return status;
}