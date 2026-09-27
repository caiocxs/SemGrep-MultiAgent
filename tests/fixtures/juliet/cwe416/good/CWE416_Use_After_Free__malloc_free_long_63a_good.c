#include "std_testcase.h"

#include <wchar.h>

void CWE416_Use_After_Free__malloc_free_long_63b_goodG2BSink(long * * data);

static void goodG2B()
{
    long * data;

    data = NULL;
    data = (long *)malloc(100*sizeof(long));
    if (data == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            data[i] = 5L;
        }
    }

    CWE416_Use_After_Free__malloc_free_long_63b_goodG2BSink(&data);
}

void CWE416_Use_After_Free__malloc_free_long_63b_goodB2GSink(long * * data);

static void goodB2G()
{
    long * data;

    data = NULL;
    data = (long *)malloc(100*sizeof(long));
    if (data == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            data[i] = 5L;
        }
    }

    free(data);
    CWE416_Use_After_Free__malloc_free_long_63b_goodB2GSink(&data);
}

void CWE416_Use_After_Free__malloc_free_long_63_good()
{
    goodG2B();
    goodB2G();
}