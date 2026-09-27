#include "std_testcase.h"

#include <wchar.h>

void CWE416_Use_After_Free__malloc_free_char_01_bad()
{
    char * data;

    data = NULL;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    memset(data, 'A', 100-1);
    data[100-1] = '\0';

    free(data);

    printLine(data);

}