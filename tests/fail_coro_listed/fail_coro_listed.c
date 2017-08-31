#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>

#include <ucontext.h>
#include <setjmp.h>

/* This test mimics QEMU usage of coroutine-ucontext.c:
 * 1. Use `makecontext` to initialize context with a separate stack.
 * 2. Use `siglongjmp`/`sigsetjmp` pair to use that context.
 */

typedef struct CoroutineUContext CoroutineUContext;

struct CoroutineUContext {
	void (*entry)(void *);
	void *entry_arg;

	/* align structure properly */
	void *a1;
	void *a2;
	CoroutineUContext *list_next;
	void *stack_orig;

	void *stack;
	sigjmp_buf env;

	sigjmp_buf caller;
};


CoroutineUContext *coroutines_list = NULL;
unsigned int coroutines_list_offset = offsetof(CoroutineUContext, list_next);
unsigned int coroutine_env_offset = offsetof(CoroutineUContext, env);

#include "../fail_coro/fail_coro_common.c"

static void
func(void *arg)
{
	const char *str = arg;

	while (1) {
		printf("%s\n", str);
		coroutine_yield();
	}
}

void listed_coroutine_exec(CoroutineUContext *co)
{
	CoroutineUContext *p = coroutines_list;

	while (p && p != co)
		p = p->list_next;

	if (p == NULL) {
		co->list_next = coroutines_list;
		coroutines_list = co;
	}

	coroutine_exec(co);
}

void listed_coroutine_free(CoroutineUContext *co)
{
	CoroutineUContext **prev = &coroutines_list;

	while (*prev) {
		if (*prev == co) {
			*prev = co->list_next;
			break;
		}

		prev = &(*prev)->list_next;
	}

	coroutine_free(co);
}

int
main(void)
{
	CoroutineUContext *co1, *co2;

	co1 = coroutine_new(func, "Hello from UNPATCHED");
	co2 = coroutine_new(func, "From UNPATCHED Hello 2");

	while (1) {
		listed_coroutine_exec(co1);
		listed_coroutine_exec(co2);
		sleep(1);
	}

	listed_coroutine_free(co1);
	listed_coroutine_free(co2);

	return 0;
}
