#include <stdio.h>
#include "Sort.h"


void InserSort(TYPE *A, int Len)
{
    int i;
    int j;
    for (i = 1; i < Len; i++)
    {
        for (j = i-1; j >= 0; j--)
        {
            if (A[j+1] > A[j])
            {
                ExchangeElementOfArray(A, j+1, j);
            }
        }
    }
}
