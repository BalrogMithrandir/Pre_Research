#include <stdio.h>

#define MAX_INT32(a, b) ((int)(a) >= (int)(b) ? (int)(a) : (int)(b))
#define MIN_INT32(a, b) ((int)(a) <= (int)(b) ? (int)(a) : (int)(b))
#define MIN_VAL_INT32 (0x80000000)
#define MAX_VAL_INT32 (0x7fffffff)
double findMedianSortedArrays(int* nums1, int nums1Size, int* nums2, int nums2Size) {
    int i_Max;
    int i_Min;
    int i, j;
    int l1, l2;
    int r1, r2;
    int l, r;

    i_Max = nums1Size;
    i_Min = 0;

    if(0 == nums1Size && 0 == nums2Size)
    {
        return 0;
    }

    while(1)
    {
        i = (i_Max+i_Min)/2;
        j = (nums1Size+nums2Size+1)/2 -i;
        if (j < 0)
        {
            i_Max = i-1;
            continue;
        }
        else if (j > nums2Size)
        {
            i_Min = i+1;
            continue;
        }
        else
        {
            if ((i == nums1Size) || (j == 0)) /*j=0 => i>0; i=nums1Size => j<num2Size*/
            {
                if (nums1[i-1] <= nums2[j])
                {
                    break;
                }
                i_Max = i-1;
                continue;
            }
            else if ((j == nums2Size) || (i == 0)) /*j=nums2Size => i< num1Size*/
            {
                if (nums2[j-1] <= nums1[i])
                {
                    break;
                }
                i_Min = i+1;
                continue;
            }
            else if ((nums1[i-1] <= nums2[j]) && (nums2[j-1] <= nums1[i]))
            {
                break;
            }
            else if(nums1[i-1] > nums2[j])
            {
                i_Max = i-1;
                continue;
            }
            else if(nums2[j-1] > nums1[i])
            {
                i_Min = i+1;
                continue;
            }
        }
    }
    l1 = (i == 0 ? MIN_VAL_INT32 : nums1[i-1]);
    l2 = (j == 0 ? MIN_VAL_INT32 : nums2[j-1]);
    r1 = (i == nums1Size ? MAX_VAL_INT32 : nums1[i]);
    r2 = (j == nums2Size ? MAX_VAL_INT32 : nums2[j]);
    l = MAX_INT32(l1, l2);
    r = MIN_INT32(r1, r2);

    if ((i+j) == (nums1Size+nums2Size-i-j))
    {
        return (double)(l+r)/2;
    }
    else if ((i+j) < (nums1Size+nums2Size-i-j))
    {
        return (double)r;
    }
    else
    {
        return (double)l;
    }
}

void main()
{
    int a[2] = {1,2};
    int b[2] = {3,4};
    printf("%f\n", findMedianSortedArrays(a, 2, b, 2));
    return;
}