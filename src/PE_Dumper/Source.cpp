#include <stdio.h>
#include "MapFile.h"
#include "Scanner.h"
#include "FileWriter.h"
#include "Extractor.h"
#include "PEInfo.h"


// Error Status
#define STATUS_ERROR_EXIT_PROGRAM -1
#define STATUS_ERROR_LISTING_DIRECTORY -2


int ParsePE(char* FileName)
{
    int status = 0;
    PE_INFO peInfo = { 0 };
    MAP map = { 0 };

    status = MapFile(FileName,
        GENERIC_READ,
        &map);
    if (0 > status)
    {
        printf("[ERROR] MapFile failed\n");
        goto cleanup;
    }

    if (map.fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        printf("[Error] Size too small for DOS Header\n");
        return STATUS_ERROR_INVALID_DOS_HEADER;
    }

    // DOS Header Processing
    peInfo.pDOS = (IMAGE_DOS_HEADER*)map.buffer;
    printf(">> Scanning DOS Header...\n");
    status = ScanDosHeader(peInfo.pDOS);
    if (0 > status)
    {
        goto cleanup;
    }

    // NT Header Processing
    if (map.fileSize < (peInfo.pDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
    {
        printf("[Error] Size too small: Can't find NT Header\n");
        return STATUS_ERROR_INVALID_NT_HEADER;
    }

    peInfo.pNT = (IMAGE_NT_HEADERS*)((BYTE*)peInfo.pDOS + peInfo.pDOS->e_lfanew);
    printf(">> Scanning NT Header...\n");
    status = ScanNTHeader(peInfo.pNT);
    if (0 > status)
    {
        goto cleanup;
    }

    // File Header Processing
    printf(">> Scanning File Header...\n");
    peInfo.pFileHdr = &peInfo.pNT->FileHeader;
    status = ScanFileHeader(peInfo.pFileHdr);
    if (0 > status)
    {
        goto cleanup;
    }

    // Optional Header Processing
    peInfo.pOptionalHdr = &peInfo.pNT->OptionalHeader;
    printf(">> Scanning Optional Header...\n");
    status = ScanOptionalHeader(peInfo.pOptionalHdr);
    if (0 > status)
    {
        goto cleanup;
    }

    // Section Header Processing
    printf(">> Scanning Section Header...\n");
    peInfo.pSectionHdr = (IMAGE_SECTION_HEADER*)((BYTE*)peInfo.pFileHdr + sizeof(IMAGE_FILE_HEADER) + peInfo.pFileHdr->SizeOfOptionalHeader);
    status = ScanSectionHeaders(peInfo.pSectionHdr, peInfo.pFileHdr->NumberOfSections);
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

    printf(">> Scanning Export Directory...\n");
    status = ScanExportDirectory(&peInfo);
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

    printf(">> Scanning Import Descriptor...\n");
    status = ScanImportDescriptor(&peInfo);
    if (0 > status)
    {
        goto cleanup;
    }

cleanup:
    UnmapFile(&map);

    return status;   // successfull processing
}


/*
* List all files recursively from given path
*/
int ScanDirectory(char* SearchDirectoryPath)
{
    int status = 0;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA findFileData = { 0 };
    char directoryPathBuffer[MAX_PATH] = { 0 };
    int lengthOfPath = 0;
    char* bufferToWrite = NULL;

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
        printf("[Error] FindFirstFile failed\n");
        status = STATUS_ERROR_LISTING_DIRECTORY;
        goto cleanup;
    }

    do
    {
        // if is directory look into it
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (('.' != findFileData.cFileName[0]))         // skip "." and ".." 
            {
                printf("%s <DIR>\n", findFileData.cFileName);

                sprintf_s(directoryPathBuffer, "%s\\%s", SearchDirectoryPath, findFileData.cFileName);
                ScanDirectory(directoryPathBuffer);        // recursive call to search in found directory
            }
        }
        else        // if is file
        {
            // ProcessPE on that file and write dumped data to log file 
            sprintf_s(directoryPathBuffer, "%s\\%s", SearchDirectoryPath, findFileData.cFileName);
            printf("[*] Parsing %s ...\n", directoryPathBuffer);
            bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
            sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "-------------------------------------%s-------------------------------------\r\n", directoryPathBuffer);

            WriteResultsToFile(bufferToWrite);

            free(bufferToWrite);

            status = ParsePE(directoryPathBuffer);
            printf("\n");
        }
    } while (0 != FindNextFile(hFind, &findFileData));


cleanup:
    if (INVALID_HANDLE_VALUE != hFind)
    {
        FindClose(hFind);
    }

    return status;
}


int main(int argc, char* argv[])
{
    int status = 0;
    MAP map = { 0 };

    if (argc != 2)
    {
        printf("[Error] Invalid parameters\n");
        printf("Usage: %s path\n", argv[0]);
        return STATUS_ERROR_EXIT_PROGRAM;
    }

    status = ScanDirectory(argv[1]);
    if (0 > status)
    {
        goto cleanup;
    }

cleanup:
    printf("Press any key... \n");
    getchar();

    return 0;
}
