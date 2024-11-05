// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __LOCK_H
#define __LOCK_H

#include <stdbool.h>
#include <processor.h>
#include <cmpxchg.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>

#ifdef DEBUG_LOCKS_BACKTRACE
#include <stack.h>

#define LOCKS_BACKTRACE_MAX_ENTS	60
#endif

struct lock {
	/* Lock value has bit 63 as lock bit and the PIR of the owner
	 * in the top 32-bit
	 */
	uint64_t lock_val;

	/*
	 * Set to true if lock is involved in the console flush path
	 * in which case taking it will suspend console flushing
	 */
	bool in_con_path;

	/* file/line of lock owner */
	const char *owner;

#ifdef DEBUG_LOCKS_BACKTRACE
	struct bt_entry bt_buf[LOCKS_BACKTRACE_MAX_ENTS];
	struct bt_metadata bt_metadata;
#endif

	/* linkage in per-cpu list of owned locks */
	struct list_node list;
};

/* Initializer... not ideal but works for now. If we need different
 * values for the fields and/or start getting warnings we'll have to
 * play macro tricks
 */
#define LOCK_UNLOCKED	{ 0 }

/* Note vs. libc and locking:
 *
 * The printf() family of
 * functions use stack based t buffers and call into skiboot
 * underlying read() and write() which use a console lock.
 *
 * The underlying FSP console code will thus operate within that
 * console lock.
 *
 * The libc does *NOT* lock stream buffer operations, so don't
 * try to scanf() from the same FILE from two different processors.
 *
 * FSP operations are locked using an FSP lock, so all processors
 * can safely call the FSP API
 *
 * Note about ordering:
 *
 * lock() is a full memory barrier. unlock() is a lwsync
 *
 */

extern bool bust_locks;

static inline void init_lock(struct lock *l)
{
	*l = (struct lock)LOCK_UNLOCKED;
}

#define LOCK_CALLER	__FILE__ ":" stringify(__LINE__)

#define try_lock(l)		try_lock_caller(l, LOCK_CALLER)
#define lock(l)			lock_caller(l, LOCK_CALLER)
#define lock_recursive(l)	lock_recursive_caller(l, LOCK_CALLER)

extern bool try_lock_caller(struct lock *l, const char *caller);
extern void lock_caller(struct lock *l, const char *caller);
extern void unlock(struct lock *l);

extern bool lock_held_by_me(struct lock *l);

/* The debug output can happen while the FSP lock, so we need some kind
 * of recursive lock support here. I don't want all locks to be recursive
 * though, thus the caller need to explicitly call lock_recursive which
 * returns false if the lock was already held by this cpu. If it returns
 * true, then the caller shall release it when done.
 */
extern bool lock_recursive_caller(struct lock *l, const char *caller);

/* Called after per-cpu data structures are available */
extern void init_locks(void);

/* Dump the list of locks held by this CPU */
extern void dump_locks_list(void);

/* Clean all locks held by CPU (and warn if any) */
extern void drop_my_locks(bool warn);

#endif /* __LOCK_H */
