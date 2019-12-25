#pragma once
#include <Windows.h>
#include "PEInfo.h"


DWORD RVAToFA(PE_INFO* PEInfo, DWORD RVA);
IMAGE_EXPORT_DIRECTORY* ExtractExportDirectory(PE_INFO* PEInfo);
BYTE* ExtractExportedFunctionName(PE_INFO* PEInfo, DWORD FunctionRVA, WORD* NameOrdinal, char** NameDllForwardedTo);
IMAGE_IMPORT_DESCRIPTOR* ExtractImportDescriptor(PE_INFO* PEInfo);
BYTE* ExtractDllName(PE_INFO* PEInfo);
BYTE* ExtractFunctionName(PE_INFO* PEInfo, IMAGE_THUNK_DATA* ThunksData);
DWORD ExtractOrdinal(IMAGE_THUNK_DATA* ThunkData);