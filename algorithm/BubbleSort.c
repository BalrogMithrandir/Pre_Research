#include <stdio.h>
#include "Sort.h"



void BubbleSort(TYPE *A, int Len)
{
    int i;
    int j;
    for (i = 0; i <= Len-1; i++)
    {
        for (j = Len-1; j > i; j--)
        {
            if (A[j] > A[j-1])
            {
                ExchangeElementOfArray(A, j, j-1);
            }
        }
    }
}
