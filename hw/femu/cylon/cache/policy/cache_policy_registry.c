#include "cache_policy.h"

static const CachePolicy *policies[CACHE_POLICY_MAX];

void cache_policy_register(int policy_id, const CachePolicy *policy)
{
    if (policy_id >= 0 && policy_id < CACHE_POLICY_MAX && policy) {
        policies[policy_id] = policy;
    }
}

const CachePolicy *cache_policy_get(int policy_id)
{
    if (policy_id >= 0 && policy_id < CACHE_POLICY_MAX) {
        return policies[policy_id];
    }
    return NULL;
}

void cache_policy_register_all(void)
{
    cache_policy_fifo_register();
    cache_policy_lifo_register();
    cache_policy_clock_register();
    cache_policy_s3fifo_register();
}
