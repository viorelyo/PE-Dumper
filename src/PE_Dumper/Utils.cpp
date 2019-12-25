#include "Utils.h"
#include <string.h>
#include <Windows.h>


char* GenerateLogFileName(char* Path)
{
    size_t pathLength = 0;
    int index = 0;
    char* logFileName = NULL;
    
    pathLength = strnlen_s(Path, MAX_PATH);
    
    logFileName = (char*)calloc(pathLength + 5, sizeof(char));
    if (NULL == logFileName)
    {
        return NULL;
    }

    index = 0;
    while (Path[index])
    {
        if (('\\' == Path[index]) || (':' == Path[index]))
        {
            logFileName[index] = '_';
        }
        else
        {
            logFileName[index] = Path[index];
        }
        index++;
    }
    logFileName[index] = '\0';
    strcat_s(logFileName, pathLength + 5, ".log");

    return logFileName;
}


char* AppendPath(char* Path, char* FileName)
{
    size_t pathLength = 0,
           fileNameLength = 0;
    char* fullPath = NULL;

    pathLength = strlen(Path);
    fileNameLength = strlen(FileName);

    fullPath = (char*)calloc(pathLength + fileNameLength + 2, sizeof(char));
    if (NULL == fullPath)
    {
        return NULL;
    }

    strcpy_s(fullPath, (pathLength + fileNameLength + 2), Path);
    fullPath[pathLength] = '\\';
    fullPath[pathLength + 1] = '\0';
    strcat_s(fullPath, (pathLength + fileNameLength + 2), FileName);    

    return fullPath;
}