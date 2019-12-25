#include "Scanner.h"
#include "FileWriter.h"
#include <stdlib.h>
#include <stdio.h>
#include "Extractor.h"


#define STRING_ON_STACK_LEN 20


int ScanDosHeader(IMAGE_DOS_HEADER* DosHeader)
{
    char* bufferToWrite = NULL;
    if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic)
    {
        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        strcpy_s(bufferToWrite, MAX_BUFFER_LEN, "[-] No MZ signature found\r\n");

        WriteResultsToFile(bufferToWrite);

        free(bufferToWrite);
        return STATUS_ERROR_INVALID_DOS_HEADER;
    }
    return 0;
}


int ScanNTHeader(IMAGE_NT_HEADERS* NTHeader)
{
    char* bufferToWrite = NULL;
    if (IMAGE_NT_SIGNATURE != NTHeader->Signature)
    {
        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        strcpy_s(bufferToWrite, MAX_BUFFER_LEN, "[-] No PE signature found\r\n");

        WriteResultsToFile(bufferToWrite);

        free(bufferToWrite);
        return STATUS_ERROR_INVALID_NT_HEADER;
    }
    return 0;
}


int ScanFileHeader(IMAGE_FILE_HEADER* FileHeader)
{
    char* bufferToWrite = NULL;

    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\r\nFile Header:\r\n\t * Machine: 0x%04X\r\n\t * NumberOfSections: 0x%04X\r\n\t * SizeOfOptionalHeader: 0x%04X\r\n\t * Characteristics: 0x%04X\r\n",
        FileHeader->Machine,
        FileHeader->NumberOfSections,
        FileHeader->SizeOfOptionalHeader,
        FileHeader->Characteristics);

    WriteResultsToFile(bufferToWrite);

    free(bufferToWrite);
    return 0;
}


int ScanOptionalHeader(IMAGE_OPTIONAL_HEADER* OptionalHeader)
{
    int status = 0;
    char* bufferToWrite = NULL;

    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    if ((IMAGE_NT_OPTIONAL_HDR32_MAGIC == OptionalHeader->Magic) || (IMAGE_ROM_OPTIONAL_HDR_MAGIC == OptionalHeader->Magic))
    {
        sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\r\nOptional Header:\r\n\t * Magic: 0x%04X\r\n\t * AddressOfEntryPoint: 0x%08X\r\n\t * ImageBase: 0x%08X\r\n\t * SectionAlignment: 0x%08X\r\n\t * FileAlignment: 0x%08X\r\n\t * SizeOfImage: 0x%08X\r\n\t * Subsystem: 0x%04X\r\n\t * DllCharacteristics: 0x%04X\r\n\t * SizeOfStackReserve: 0x%08X\r\n\t * SizeOfStackCommit: 0x%08X\r\n\t * SizeOfHeapReserve: 0x%08X\r\n\t * SizeOfHeapCommit: 0x%08X\r\n\t * NumberOfRvaAndSizes: 0x%08X\r\n",
            OptionalHeader->Magic,
            OptionalHeader->AddressOfEntryPoint,
            OptionalHeader->ImageBase,
            OptionalHeader->SectionAlignment,
            OptionalHeader->FileAlignment,
            OptionalHeader->SizeOfImage,
            OptionalHeader->Subsystem,
            OptionalHeader->DllCharacteristics,
            OptionalHeader->SizeOfStackReserve,
            OptionalHeader->SizeOfStackCommit,
            OptionalHeader->SizeOfHeapReserve,
            OptionalHeader->SizeOfHeapCommit,
            OptionalHeader->NumberOfRvaAndSizes
        );
    }
    else
    {
        sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "[-] 64 bit PE file. (Only 32 bit PE files supported.)\r\n");
        status = STATUS_ERROR_INVALID_OPTIONAL_HEADER;
    }
    WriteResultsToFile(bufferToWrite);

    free(bufferToWrite);
    return status;
}


int ScanSectionHeaders(IMAGE_SECTION_HEADER* SectionHeader, DWORD NumberOfSections)
{
    char* bufferToWrite = NULL;

    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\r\nSections:\r\n");

    WriteResultsToFile(bufferToWrite);
    free(bufferToWrite);

    if (NULL == SectionHeader)
    {
        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "[-] Invalid Section Header\r\n");

        WriteResultsToFile(bufferToWrite);
        free(bufferToWrite);

        return STATUS_ERROR_INVALID_SECTION_HEADER;
    }

    // Titles formatting
    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "%-20s %-20s %-20s %-20s\r\n",
        "Name", "FileAddress", "Size", "VirtualSize");

    WriteResultsToFile(bufferToWrite);
    free(bufferToWrite);

    // Enumerating Sections and their informations
    for (DWORD i = 0; i < NumberOfSections; i++)
    {
        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "%-20s 0x%-18X 0x%-18X 0x%-18X\r\n",
            SectionHeader[i].Name,
            SectionHeader[i].PointerToRawData,
            SectionHeader[i].SizeOfRawData,
            SectionHeader[i].Misc.VirtualSize);

        WriteResultsToFile(bufferToWrite);
        free(bufferToWrite);
    }

    return 0;
}


int ScanExportDirectory(PE_INFO* PEInfo)
{
    char* bufferToWrite = NULL;
    DWORD* functionsArray = NULL;
    DWORD fileAddress = 0;
    WORD nameOrdinal = 0;
    BYTE* nameAddress = NULL;
    char undefinedNameString[STRING_ON_STACK_LEN] = "undefined";
    char emptyNameString[1] = "";
    char fileAddressName[STRING_ON_STACK_LEN] = { 0 };
    char* nameDllForwardedTo = NULL;

    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\r\nExports:\r\n");

    WriteResultsToFile(bufferToWrite);
    free(bufferToWrite);

    fileAddress = RVAToFA(PEInfo, (*PEInfo).pExportDir->AddressOfFunctions);
    if (0 == fileAddress)
    {
        printf("[ERROR] Invalid RVA of Address Of Functions in ExportDirectory\n");
        return STATUS_ERROR_INVALID_EXPORT_DIRECTORY;
    }

    functionsArray = (DWORD*)((BYTE*)(*PEInfo).pDOS + fileAddress);

    for (DWORD i = 0; i < (*PEInfo).pExportDir->NumberOfFunctions; i++)
    {
        fileAddress = (DWORD)((BYTE*)(*PEInfo).pDOS + RVAToFA(PEInfo, functionsArray[i]));

        if (fileAddress >(DWORD)(*PEInfo).pDOS)
        {
            sprintf_s(fileAddressName, STRING_ON_STACK_LEN, "0x%08X", fileAddress);
        }
        else
        {
            sprintf_s(fileAddressName, STRING_ON_STACK_LEN, "%s", undefinedNameString);
        }

        nameAddress = ExtractExportedFunctionName(PEInfo, functionsArray[i], &nameOrdinal, &nameDllForwardedTo);

        if (0xFFFFFFFF == (DWORD)nameAddress)
        {
            nameAddress = (BYTE*)undefinedNameString;
        }
        else if (NULL == nameAddress)
        {
            nameAddress = (BYTE*)emptyNameString;
        }

        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        if (NULL != nameDllForwardedTo)
        {
            sprintf_s(bufferToWrite, MAX_BUFFER_LEN, " Ordinal: 0x%X\r\n\t * FileAddress: %s\r\n\t * FunctionName: %s\r\n\t * ForwardedTo: %s\r\n",
                nameOrdinal,
                fileAddressName,
                nameAddress,
                nameDllForwardedTo);
        }
        else
        {
            // if nameDllForwardedTo is NULL then show "-" string
            sprintf_s(bufferToWrite, MAX_BUFFER_LEN, " Ordinal: 0x%X\r\n\t * FileAddress: %s\r\n\t * FunctionName: %s\r\n\t * ForwardedTo: %s\r\n",
                nameOrdinal,
                fileAddressName,
                nameAddress,
                "-");
        }

        WriteResultsToFile(bufferToWrite);
        free(bufferToWrite);
    }

    return 0;
}


int ScanImportDescriptor(PE_INFO* PEInfo)
{
    char* bufferToWrite = NULL;
    BYTE* dllName = NULL;
    DWORD fileAddress = 0;
    IMAGE_THUNK_DATA* thunks = NULL;
    BYTE* functionName = NULL;

    bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
    sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\r\nImports:\r\n");

    WriteResultsToFile(bufferToWrite);
    free(bufferToWrite);

    for (; (0 != (*PEInfo).pImportDes->OriginalFirstThunk) && (0 != (*PEInfo).pImportDes->FirstThunk); (*PEInfo).pImportDes++)
    {
        dllName = ExtractDllName(PEInfo);
        if (NULL == dllName)
        {
            continue;
        }
        fileAddress = RVAToFA(PEInfo, (*PEInfo).pImportDes->FirstThunk);
        if (0 == fileAddress)
        {
            continue;
        }

        // Titles formatting - dllName
        bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));
        sprintf_s(bufferToWrite, MAX_BUFFER_LEN, " %s:\r\n", dllName);

        WriteResultsToFile(bufferToWrite);
        free(bufferToWrite);

        thunks = (IMAGE_THUNK_DATA*)((BYTE*)(*PEInfo).pDOS + fileAddress);
        for (; thunks->u1.Function != 0; thunks++)
        {
            functionName = ExtractFunctionName(PEInfo, thunks);
            bufferToWrite = (char*)calloc(MAX_BUFFER_LEN, sizeof(char));

            if (NULL != functionName)
            {
                sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\t * %s\r\n",
                    functionName);
            }
            else
            {
                sprintf_s(bufferToWrite, MAX_BUFFER_LEN, "\t * 0x%X\r\n",
                    ExtractOrdinal(thunks));
            }

            WriteResultsToFile(bufferToWrite);
            free(bufferToWrite);
        }
    }

    return 0;
}