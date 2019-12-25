#pragma once
#include <Windows.h>


typedef struct _PE_INFO
{
    IMAGE_DOS_HEADER* pDOS;
    IMAGE_NT_HEADERS* pNT;
    IMAGE_FILE_HEADER* pFileHdr;
    IMAGE_OPTIONAL_HEADER* pOptionalHdr;
    IMAGE_SECTION_HEADER* pSectionHdr;
    IMAGE_EXPORT_DIRECTORY* pExportDir;
    IMAGE_IMPORT_DESCRIPTOR* pImportDes;
} PE_INFO, *PPE_INFO;