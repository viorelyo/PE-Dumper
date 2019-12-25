#include <stdio.h>
#include "Dumper.h"


int main(int argc, char* argv[])
{
    int status = 0;
    int nrOfThreads = DEFAULT_NR_OF_THREADS;
    MAP map = { 0 };

    if ((argc < 2) || (argc > 4))
    {
        printf("[Error] Invalid parameters\n");
        printf("Usage: %s path [nrOfThreads]\n", argv[0]);
        return STATUS_ERROR_EXIT_PROGRAM;
    }
    if (3 == argc)
    {
        nrOfThreads = atoi(argv[2]);       
        if ((nrOfThreads < 1) || (nrOfThreads > MAX_THREAD_COUNT) )
        {
            printf("[Error] Invalid parameter\n");
            printf("Usage: %s path [nr_Threads: <MIN 1, MAX 32>]\n", argv[0]);
            goto cleanup;
        }
    }

    status = DumpPEs(argv[1], nrOfThreads);
    if (0 > status)
    {
        goto cleanup;
    }

cleanup:
    printf("Press any key... \n");
    getchar();

    return 0;
}
