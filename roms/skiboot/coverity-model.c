void __attribute__((noreturn)) _abort(void) {
	__coverity_panic__();
}

void *__memalign(size_t blocksize, size_t bytes, const char *location) {
	__coverity_alloc__(bytes);
}

void mem_free(struct mem_region *region, void *mem, const char *location) {
	__coverity_free__(mem);
}

void lock_caller(struct lock *l, const char *caller)
{
	__coverity_exclusive_lock_acquire__(l);
}

void unlock(struct lock *l) {
	__coverity_exclusive_lock_release__(l);
}

static inline void cpu_relax(void) {
	__coverity_sleep__();
}
