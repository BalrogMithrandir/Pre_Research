#include <stdio.h>
#include "Sort.h"
#define PARENT(i) (((i)-1)/2)
#define LEFT(i)   (((i)<<1) + 1)
#define RIGHT(i)  (((i)<<1) + 2)


void ExchangeElementOfArray(TYPE *A, int Index1, int Index2)
{
    TYPE Temp = A[Index1];
    A[Index1] = A[Index2];
    A[Index2] = Temp;
}

/*sink the element Index to keep the feature of max heap*/
void MaxHeapify(TYPE *A, int Len, int Index)
{
    int LeftIndex = LEFT(Index);
    int RightIndex = RIGHT(Index);
    int LargestIndex = Index;

    if (LeftIndex < Len && A[LeftIndex] > A[Index])
    {
        LargestIndex = LeftIndex;
    }
    if (RightIndex < Len && A[RightIndex] > A[LargestIndex])
    {
        LargestIndex = RightIndex;
    }

    if (LargestIndex != Index)
    {
        ExchangeElementOfArray(A, LargestIndex, Index);
        MaxHeapify(A, Len, LargestIndex);
    }
}


void MaxHeapBuild(TYPE *A, int Len)
{
    int i;
    for (i = Len/2; i >= 0; i--)
    {
        MaxHeapify(A, Len, i);
    }
}

void MaxHeapSort(TYPE *A, int Len)
{
    int i;
    for (i = 0; i < Len; i++)
    {
        MaxHeapBuild(A+i, Len-i);
    }
}
