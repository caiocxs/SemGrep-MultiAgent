#include "std_testcase.h"

#include <wchar.h>

void CWE416_Use_After_Free__malloc_free_long_63b_badSink(long * * dataPtr)
{
    long * data = *dataPtr;

    printLongLine(data[0]);

}