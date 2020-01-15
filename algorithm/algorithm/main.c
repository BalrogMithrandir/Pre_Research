#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "Sort.h"

int main()
{
    TYPE A[1000] = {58, 37, 58,31, 63,99, 72,40,84,35};//{1,2,3,4,5,6,8,9,10};

    int i;
#if 1
    srand((unsigned int)(time(NULL)));
    for (i = 0; i < sizeof(A)/sizeof(TYPE); i++)
        A[i] = rand()%MAX_VALUE;
#endif
    for (i = 0; i < sizeof(A)/sizeof(TYPE); i++)
        printf("A[%d] %d\n", i, A[i]);

    //MaxHeapSort(A, sizeof(A)/sizeof(int));
    //MergetSort(A, sizeof(A)/sizeof(TYPE));
    //QuickSort(A, sizeof(A)/sizeof(TYPE));
    //InserSort(A, sizeof(A)/sizeof(TYPE));
    //BubbleSort(A, sizeof(A)/sizeof(TYPE));
    CountSort(A, sizeof(A)/sizeof(TYPE));
    printf("after ----------\n\n\n");

    for (i = 0; i < sizeof(A)/sizeof(TYPE); i++)
        printf("A[%d] %d\n", i, A[i]);
    return 0;
}
