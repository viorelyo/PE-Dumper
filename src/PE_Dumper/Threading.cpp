#include "Threading.h"


HANDLE Events[EVENTS_COUNT];
HANDLE Threads[MAX_THREAD_COUNT];

int(*_DoWork)();


DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    BYTE terminated = 0;
    DWORD waitResult = 0;

    UNREFERENCED_PARAMETER(lpParameter);

    while (!terminated)
    {
        waitResult = WaitForMultipleObjects(EVENTS_COUNT, Events, FALSE, INFINITE);
        switch (waitResult)
        {
        case WAIT_OBJECT_0:
            _DoWork();
            break;
        case WAIT_OBJECT_0 + 1:
            if (ERROR_WORK_FAILED == _DoWork())
            {
                terminated = 1;
            }
            break;
        case WAIT_FAILED:
            break;
        default:
            break;
        }
    }

    printf("Thread: %d exiting...\n", GetCurrentThreadId());
    return 0;              
}


void CreateEventsAndThreads(int nrOfThreads, int(*DoWork)())
{
    DWORD threadID = 0;

    _DoWork = DoWork;

    Events[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    for (int i = 1; i < EVENTS_COUNT; i++)
    {
        Events[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (NULL == Events[i])
        {
            printf("[Error] CreateEvent failed: %d\n", GetLastError());
            return;
        }
    }

    for (int i = 0; i < nrOfThreads; i++)
    {
        Threads[i] = CreateThread(NULL, 0, ThreadProc, NULL, 0, &threadID);
        if (NULL == Threads[i])
        {
            printf("[Error] CreateThread failed: %d\n", GetLastError());
            return;
        }
    }
}