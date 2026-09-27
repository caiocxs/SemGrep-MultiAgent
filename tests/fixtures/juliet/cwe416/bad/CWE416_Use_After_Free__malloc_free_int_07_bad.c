#include "std_testcase.h"

#include <wchar.h>

static int staticFive = 5;

void CWE416_Use_After_Free__malloc_free_int_07_bad()
{
    int * data;

    data = NULL;
    if(staticFive==5)
    {
        data = (int *)malloc(100*sizeof(int));
        if (data == NULL) {exit(-1);}
        {
            size_t i;
            for(i = 0; i < 100; i++)
            {
                data[i] = 5;
            }
        }

        free(data);
    }
    if(staticFive==5)
    {

        printIntLine(data[0]);

    }
}