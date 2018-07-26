#include <stdio.h>
#include "Sort.h"

void Merge(TYPE *A, int p, int q, int r)
{
    int TotalLen = r-p+1;
    int Left = p;
    int Right = q+1;
    int Index = 0;

    if (p >= r)
    {
        return;
    }

    TYPE *Merge = malloc(sizeof(TYPE)*TotalLen);

    while(Left <= q && Right <= r)
    {
        if (A[Left] >= A[Right])
        {
            Merge[Index++] = A[Left++];
        }
        else
        {
            Merge[Index++] = A[Right++];
        }
    }

    if (Left <= q)
    {
        memcpy(&Merge[Index], &A[Left], sizeof(TYPE)*(q-Left+1));
    }
    else
    {
        memcpy(&Merge[Index], &A[Right], sizeof(TYPE)*(r-Right+1));
    }
    memcpy(&A[p], Merge, sizeof(TYPE)*TotalLen);
    free(Merge);
}

void SplitAndMerge(TYPE *A, int l, int r)
{
    int mid;

    if (l == r)
    {
        return;
    }

    mid = (l+r)/2;
    SplitAndMerge(A, l, mid);
    SplitAndMerge(A, mid+1, r);
    Merge(A, l, mid, r);
}

void MergetSort(TYPE *A, int Len)
{
    SplitAndMerge(A, 0, Len-1);
}

