#ifndef __KPATCH_CORO__
#define __KPATCH_CORO__

#include <setjmp.h>

#include "list.h"

struct kpatch_process;

struct kpatch_coro_ops {
	int (*find_coroutines)(struct kpatch_process *proc);
};

struct kpatch_coro {
	struct list_head list;
	sigjmp_buf env;
};

int kpatch_init_coroutine(struct kpatch_process *proc);

int kpatch_find_coroutines(struct kpatch_process *proc);
void kpatch_free_coroutines(struct kpatch_process *proc);

struct kpatch_coro *kpatch_coro_new(struct kpatch_process *proc);
void kpatch_coro_free(struct kpatch_coro *c);

void *_UCORO_create(struct kpatch_coro *, pid_t);
void _UCORO_destroy(void *);

#endif
