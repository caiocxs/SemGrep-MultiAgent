#include "std_testcase.h"

#include <wchar.h>

static int staticFive = 5;

static void goodB2G1()
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
    if(staticFive!=5)
    {

        printLine("Benign, fixed string");
    }
    else
    {

        ;
    }
}

static void goodB2G2()
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

        ;
    }
}

static void goodG2B1()
{
    int * data;

    data = NULL;
    if(staticFive!=5)
    {

        printLine("Benign, fixed string");
    }
    else
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

    }
    if(staticFive==5)
    {

        printIntLine(data[0]);

    }
}

static void goodG2B2()
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

    }
    if(staticFive==5)
    {

        printIntLine(data[0]);

    }
}

void CWE416_Use_After_Free__malloc_free_int_07_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
}