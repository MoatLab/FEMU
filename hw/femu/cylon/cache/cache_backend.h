#ifndef __CYLON_CACHE_BACKEND_H
#define __CYLON_CACHE_BACKEND_H

#include "qemu/osdep.h"

/* DER cache backend state */
typedef struct CylonCacheBackend {
    void    *buf_space;
    int64_t buf_size;     /* bytes */
    uint64_t hpa_base;
} CylonCacheBackend;

struct FemuCtrl;

/* Fill backend from n (initial params only); mmap if cache_backend_dev set. */
int cylon_cache_backend_init(struct FemuCtrl *n, CylonCacheBackend *out);
void cylon_cache_backend_fini(CylonCacheBackend *b);


#endif
