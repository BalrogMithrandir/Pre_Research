#include <stdio.h>
#include "Sort.h"

int SplitArray(TYPE *A, int l, int r)
{
    int Index = l;
    int End = r;
    int Ruler = A[r];
    int RulerIndex = l;
    if (l == r)
    {
        return l;
    }

    while(Index != End)
    {
        if (A[Index] < Ruler)
        {
            A[End] = A[Index];
            A[Index] = A[End-1];
            End--;
        }
        else
        {
            RulerIndex++;
            Index++;
        }
    }
    A[RulerIndex] = Ruler;
    return RulerIndex;
}

void QuickSplitAndMerge(TYPE *A, int l, int r)
{
    int RulerIndex;
    if (l == r)
    {
        return;
    }
    RulerIndex = SplitArray(A, l, r);
    if (RulerIndex > l)
    {
        QuickSplitAndMerge(A, l, RulerIndex-1);
    }
    if (RulerIndex < r)
    {
        QuickSplitAndMerge(A, RulerIndex+1, r);
    }
}

void QuickSort(TYPE *A, int Len)
{
    QuickSplitAndMerge(A, 0, Len-1);
}
