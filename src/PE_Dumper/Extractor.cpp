#include "Extractor.h"

/*
* Convert Relative Virtual Address to File Addresss
*/
DWORD RVAToFA(PE_INFO* PEInfo, DWORD RVA)
{
    DWORD offset = 0;
    DWORD fileAddress = 0;
    IMAGE_NT_HEADERS* pNT = NULL;
    IMAGE_SECTION_HEADER* SectionHeader = NULL;

    pNT = (*PEInfo).pNT;
    SectionHeader = (*PEInfo).pSectionHdr;

    for (DWORD i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        if ((SectionHeader[i].VirtualAddress <= RVA) && (RVA < (SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)))
        {
            offset = RVA - SectionHeader[i].VirtualAddress;
            fileAddress = SectionHeader[i].PointerToRawData + offset;
            return fileAddress;
        }
    }
    return 0;
}


IMAGE_EXPORT_DIRECTORY* ExtractExportDirectory(PE_INFO* PEInfo)
{
    DWORD fileAddress = 0;
    IMAGE_EXPORT_DIRECTORY* exportDir = NULL;

    fileAddress = RVAToFA(PEInfo, (*PEInfo).pOptionalHdr->DataDirectory->VirtualAddress);
    if (0 == fileAddress)
    {
        return NULL;
    }

    exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)(*PEInfo).pDOS + fileAddress);
    return exportDir;
}


BYTE* ExtractExportedFunctionName(PE_INFO* PEInfo, DWORD FunctionRVA, WORD* NameOrdinal, char** NameDllForwardedTo)
{
    DWORD fileAddress = 0;
    DWORD* addrOfFunctions = NULL;
    DWORD* names = NULL;
    WORD* nameOrdinals = NULL;
    WORD ordinal = 0;
    BYTE* nameAddress = NULL;

    // Get functionsArray
    fileAddress = RVAToFA(PEInfo, (*PEInfo).pExportDir->AddressOfFunctions);
    if (0 == fileAddress)
    {
        return (BYTE*)0xFFFFFFFF; 
    }
    addrOfFunctions = (DWORD*)((BYTE*)(*PEInfo).pDOS + fileAddress);

    // Get nameArray
    fileAddress = RVAToFA(PEInfo, (*PEInfo).pExportDir->AddressOfNames);
    if (0 == fileAddress)
    {
        return (BYTE*)0xFFFFFFFF; 
    }
    names = (DWORD*)((BYTE*)(*PEInfo).pDOS + fileAddress);

    // Get nameOrdinalArray
    fileAddress = RVAToFA(PEInfo, (*PEInfo).pExportDir->AddressOfNameOrdinals);
    if (0 == fileAddress)
    {
        return (BYTE*)0xFFFFFFFF; 
    }
    nameOrdinals = (WORD*)((BYTE*)(*PEInfo).pDOS + fileAddress);

    for (DWORD i = 0; i < (*PEInfo).pExportDir->NumberOfNames; i++)
    {
        ordinal = nameOrdinals[i];

        if (FunctionRVA == addrOfFunctions[ordinal])
        {
            *NameOrdinal = ordinal;
            fileAddress = RVAToFA(PEInfo, names[i]);
            if (0 == fileAddress)
            {
                return (BYTE*)0xFFFFFFFF; 
            }
            nameAddress = (BYTE*)((BYTE*)(*PEInfo).pDOS + fileAddress);

            if ((addrOfFunctions[ordinal] < (*PEInfo).pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) ||
                (addrOfFunctions[ordinal] > ((*PEInfo).pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (*PEInfo).pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)))
            {
                // not forwarded functions
                *NameDllForwardedTo = NULL;
            }
            else
            {
                // forwarded functions
                fileAddress = RVAToFA(PEInfo, addrOfFunctions[ordinal]);
                *NameDllForwardedTo = (char*)((BYTE*)(*PEInfo).pDOS + fileAddress);
            }
            return nameAddress;
        }
    }

    return NULL;
}


IMAGE_IMPORT_DESCRIPTOR* ExtractImportDescriptor(PE_INFO* PEInfo)
{
    IMAGE_DATA_DIRECTORY* importDir = NULL;
    DWORD fileAddress = 0;
    IMAGE_IMPORT_DESCRIPTOR* importDes = NULL;

    importDir = (*PEInfo).pOptionalHdr->DataDirectory + 1;
    fileAddress = RVAToFA(PEInfo, importDir->VirtualAddress);
    if (0 == fileAddress)
    {
        return NULL;
    }

    importDes = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)(*PEInfo).pDOS + fileAddress);
    return importDes;
}


BYTE* ExtractDllName(PE_INFO* PEInfo)
{
    DWORD fileAddress = 0;
    BYTE* dllName = NULL;

    fileAddress = RVAToFA(PEInfo, (*PEInfo).pImportDes->Name);
    if (fileAddress == 0)
    {
        return NULL;
    }

    dllName = (BYTE*)((BYTE*)(*PEInfo).pDOS + fileAddress);
    return dllName;
}


BYTE* ExtractFunctionName(PE_INFO* PEInfo, IMAGE_THUNK_DATA* ThunksData)
{
    DWORD functionRVA = 0;
    DWORD fileAddress = 0;
    IMAGE_IMPORT_BY_NAME* importStruct = NULL;

    functionRVA = (DWORD)ThunksData->u1.Function;
    if (0 != (functionRVA >> 31))
    {
        return NULL;
    }

    fileAddress = RVAToFA(PEInfo, functionRVA);
    if (0 == fileAddress)
    {
        return NULL;
    }

    importStruct = (IMAGE_IMPORT_BY_NAME*)((BYTE*)(*PEInfo).pDOS + fileAddress);
    return (BYTE*)importStruct->Name;
}


DWORD ExtractOrdinal(IMAGE_THUNK_DATA* ThunkData)
{
    DWORD functionRVA = 0;
    if (ThunkData)
    {
        return 0;
    }

    functionRVA = (DWORD)ThunkData->u1.Function;
    if (0 != (functionRVA >> 31))
    {
        return functionRVA & 0xFFFF;
    }

    return 0;
}