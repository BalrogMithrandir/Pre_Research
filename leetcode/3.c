#include <stdio.h>
int FindRepeatIndexOfString(char *ToFind, char *Start, char *End, char **RepeatIndex)
{
    char *pCurr = Start;
    while(pCurr <= End)
    {
        if (*ToFind == *pCurr)
        {
            *RepeatIndex = pCurr;
            return 1;
        }
        pCurr++;
    }
    return 0;
}
int lengthOfLongestSubstring(char* s) {
    int CurrL = 0;
    int MaxL;
    char *Start, *End, *Curr;
    char *Repeat;

    if (s == NULL)
        return 0;

    Start = s;
    End = s;
    Curr = s+1;
    MaxL = 1;
    while('\0' != *Curr)
    {
        if (1 == FindRepeatIndexOfString(Curr, Start, End, &Repeat))
        {
            MaxL = (MaxL >= CurrL ? MaxL : CurrL);
            Start = Repeat+1;
        }
        End++;
        Curr++;
        CurrL = End - Start + 1;
    }
    MaxL = (MaxL >= CurrL ? MaxL : CurrL);
    return MaxL;
}

void main()
{
    char a[] = "abcabcbb";
    printf("%d\n", lengthOfLongestSubstring(a));
    return;
}