#include <stdio.h>
#define MAX_INT32 0x000000007fffffff
#define MIN_INT32 0xffffffff80000000
int myAtoi(char* str) {
    long long int result = 0;
    int FindSignFlag= 0;
    int FindNumFlag = 0;
    int Sign = 1;
    char c = 0;
    char *p = NULL;

    if (NULL == str)
        return 0;

    p = str;
    c = *p;
    while ('\0' != c)
    {
        if (('0' > c) || ('9' < c))
        {
            if (1 == FindNumFlag || 1 == FindSignFlag)
            {
                break;
            }
            else if (('+' == c) || ('-' == c))
            {
                if (0 == FindSignFlag)
                {
                    FindSignFlag = 1;
                    Sign = ('+' == c ? 1 : (-1));
                }
                else
                    return 0;
            }
            else if (' ' != c)
            {
                break;
            }
        }
        else
        {
            FindNumFlag = 1;
            result = result*10 + c - '0';
        }

        if ((-1 == Sign) && (result > ((long long unsigned int)MAX_INT32+1)))
        {
            return (int)MIN_INT32;
        }
        else if ((1 == Sign) && (result > (long long unsigned int)MAX_INT32))
        {
            return (int)MAX_INT32;
        }

        p++;
        c = *p;
    }
    return (int)(result*Sign);
}

void testAtoi()
{
    int i;
    int result;
    char a[][100] =
    {
        "",
        "42",
        "-42",
        "   -42",
        " hell42",
        "hhell-42",
        "hee+42",
        "hehk -12345678909",
        "3243432432433",
        "-10heh10"
        "  hell 10"
    };

    for (i = 0; i < 11; i++)
    {
        result = myAtoi(a[i]);
        printf("%s is %d\n", a[i],result );
    }

}
