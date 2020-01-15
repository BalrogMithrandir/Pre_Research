#include <stdio.h>
#include "Sort.h"

void CountSort(TYPE *A, int Len)
{
    int B[MAX_VALUE] = {0};
    TYPE *C = malloc(sizeof(TYPE)*Len);
    int i;
    for (i = 0; i < Len; i++)
    {
        B[A[i]]++;
    }
    for (i = 1; i < MAX_VALUE; i++)
    {
        B[i] += B[i-1];
    }

    for (i = Len-1; i >= 0; i--)
    {
        C[B[A[i]]-1] = A[i];
        B[A[i]]--;
    }
    memcpy(A, C, sizeof(TYPE)*Len);
    free(C);
}
