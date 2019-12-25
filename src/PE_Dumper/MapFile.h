#ifndef _MAP_H_
#define _MAP_H_

#include <Windows.h>


// Constants
#define STATUS_SUCCESS 0
#define STATUS_ERROR_FILE_HANDLING -1


typedef struct _MAP
{
    HANDLE hFile;
    HANDLE hMap;
    BYTE* buffer;
    DWORD fileSize;
} MAP, *PMAP;


int MapFile(char* FileName,
    DWORD AccessRights,
    MAP* Map);

void UnmapFile(MAP* Map);


#endif // !_MAP_H_