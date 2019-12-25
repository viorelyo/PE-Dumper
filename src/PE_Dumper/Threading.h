#pragma once
#include <Windows.h>
#include <stdio.h>

#define EVENTS_COUNT 2
#define MAX_THREAD_COUNT 64

#define ERROR_WORK_FAILED -1
#define WORK_SUCCESS 0

void CreateEventsAndThreads(int nrOfThreads, int(*DoWork)());