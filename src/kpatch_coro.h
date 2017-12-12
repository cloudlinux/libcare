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

void *_UCORO_create(struct kpatch_coro *coro, pid_t pid);
void _UCORO_destroy(void *arg);

int kpatch_coroutines_init(struct kpatch_process *proc);
int kpatch_coroutines_find(struct kpatch_process *proc);
void kpatch_coroutines_free(struct kpatch_process *proc);

#endif
