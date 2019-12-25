#pragma once
#include <Windows.h>
#include "PEInfo.h"

#define STATUS_ERROR_INVALID_DOS_HEADER -11
#define STATUS_ERROR_INVALID_NT_HEADER -12
#define STATUS_ERROR_INVALID_OPTIONAL_HEADER -13
#define STATUS_ERROR_INVALID_SECTION_HEADER -14
#define STATUS_ERROR_INVALID_EXPORT_DIRECTORY -15


int ScanDosHeader(IMAGE_DOS_HEADER* DosHeader);
int ScanNTHeader(IMAGE_NT_HEADERS* NTHeader);
int ScanFileHeader(IMAGE_FILE_HEADER* FileHeader);
int ScanOptionalHeader(IMAGE_OPTIONAL_HEADER* OptionalHeader);
int ScanSectionHeaders(IMAGE_SECTION_HEADER* SectionHeader, DWORD NumberOfSections);
int ScanExportDirectory(PE_INFO* PEInfo);
int ScanImportDescriptor(PE_INFO* PEInfo);