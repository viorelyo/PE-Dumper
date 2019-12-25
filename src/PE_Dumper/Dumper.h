#pragma once
#include "MapFile.h"
#include "Scanner.h"
#include "FileWriter.h"
#include "Extractor.h"
#include "PEInfo.h"
#include "Threading.h"
#include "TaskQueue.h"
#include "Utils.h"


// Error Status
#define STATUS_ERROR_EXIT_PROGRAM -1
#define STATUS_ERROR_LISTING_DIRECTORY -2


// Constants
#define DEFAULT_NR_OF_THREADS 8


int DumpPEs(char* Path, int nrOfThreads);