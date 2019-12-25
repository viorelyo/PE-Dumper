#pragma once


#define STATUS_ERROR_MEMORY_ALLOCATION -21
#define STATUS_ERROR_WRITE_FILE -22

// Constants
#define OUTPUT_FILENAME_LEN 18
#define MAX_BUFFER_LEN 2048


int WriteResultsToFile(char* DataBuffer);