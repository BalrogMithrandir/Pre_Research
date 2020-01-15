#ifndef __SORT__H__
#define __SORT__H__

typedef unsigned int TYPE;

#define MAX_VALUE 2000

void ExchangeElementOfArray(TYPE *A, int Index1, int Index2);
void BubbleSort(TYPE *A, int Len);
void InserSort(TYPE *A, int Len);
void MaxHeapSort(TYPE *A, int Len);
void MergetSort(TYPE *A, int Len);
void QuickSort(TYPE *A, int Len);
void CountSort(TYPE *A, int Len);
#endif // __SORT__H__
