#include "misc_utils.h"

int atoi(const char *string)
{
    int res = 0;
    while (*string>='0' && *string <='9')
    {
		res *= 10;
		res += *string-'0';
		string++;
    }

    return res;
}

int console_changed = 0;
