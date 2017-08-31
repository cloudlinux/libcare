#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ucontext.h>
#include <setjmp.h>

/* This test mimics QEMU usage of coroutine-ucontext.c:
 * 1. Use `makecontext` to initialize context with a separate stack.
 * 2. Use `siglongjmp`/`sigsetjmp` pair to use that context.
 */

typedef struct {
	void (*entry)(void *);
	void *entry_arg;

	/* align structure properly */
	void *a1;
	void *a2;
	void *a3;
	void *stack_orig;

	void *stack;
	sigjmp_buf env;

	sigjmp_buf caller;
} CoroutineUContext;

#include "fail_coro_common.c"

static void
func(void *arg)
{
	const char *str = arg;

	while (1) {
		printf("%s\n", str);
		coroutine_yield();
	}
}

int
main(void)
{
	CoroutineUContext *co;

	co = coroutine_new(func, "Hello from UNPATCHED");

	while (1) {
		coroutine_exec(co);
		sleep(1);
	}

	coroutine_free(co);

	return 0;
}
