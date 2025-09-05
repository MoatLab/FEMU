/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <string.h>
#include <stdlib.h>

char* strdup (const char* s)
{
    size_t slen = strlen(s);
    char* result = malloc(slen + 1);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, s, slen+1);
    return result;
}
