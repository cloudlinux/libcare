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
	void *a4;

	void *stack;
	sigjmp_buf env;

	sigjmp_buf caller;
} CoroutineUContext;

union cc_arg {
	void *p;
	int i[2];
};

asm (
"coroutine_trampoline:\n"
"push   %rbx\n"
"mov    %edi,%edi\n"
"sub    $0x20,%rsp\n"
"mov	%fs:0x28,%rax\n"
"mov    %rax,0x18(%rsp)\n"
"xor    %eax,%eax\n"
"mov    %rsi,%rax\n"
"xor    %esi,%esi\n"
"shl    $0x20,%rax\n"
"or     %rax,%rdi\n"
"mov    %rdi,0x8(%rsp)\n"
"mov    %rdi,(%rsp)\n"
"add    $0x38,%rdi\n"
"callq  __sigsetjmp\n"
"test   %eax,%eax\n"
"je     2f\n"
"nopl   0x0(%rax)\n"
"1:"
"mov    (%rsp),%rbx\n"
"mov    0x8(%rbx),%rdi\n"
"callq  *(%rbx)\n"
"mov    0x10(%rbx),%rsi\n"
"mov    $0x2,%edx\n"
"mov    %rbx,%rdi\n"
"jmp    1b\n"
"2:"
"mov    0x8(%rsp),%rax\n"
"mov    $0x1,%esi\n"
"mov    0x8(%rax),%rdi\n"
"callq  siglongjmp\n"
);

extern void coroutine_trampoline(void);

static CoroutineUContext *co;

static void coroutine_yield(void)
{
	if (!sigsetjmp(co->env, 0))
		siglongjmp(co->caller, 1);
}

static void
func(void *arg)
{
	const char *str = arg;

	while (1) {
		printf("%s\n", str);
		coroutine_yield();
	}
}

#define PAGE_SIZE	4096
#define PAGE_MASK	(PAGE_SIZE - 1)

int
main(void)
{
	const size_t stack_size = 1 << 14;
	ucontext_t uc, old_uc;
	sigjmp_buf old_env;
	union cc_arg arg = { 0 };
	void *stack;

	if (getcontext(&uc) == -1)
		abort();

	co = malloc(sizeof(*co));
	if (co == NULL)
		abort();

	stack = malloc(stack_size);
	if (stack == NULL)
		abort();

	co->stack = (void *)((unsigned long)(stack + PAGE_SIZE - 1) & ~PAGE_MASK);

	co->entry_arg = &old_env;

	uc.uc_link = &old_uc;
	uc.uc_stack.ss_sp = co->stack;
	uc.uc_stack.ss_size = stack_size - (co->stack - stack) & ~PAGE_MASK;
	uc.uc_stack.ss_flags = 0;

	printf("func=%p co=%p old_uc=%p uc=%p stack=%p ssize=%lx\n", func, co, &old_uc, &uc, co->stack,
	       uc.uc_stack.ss_size);

	arg.p = co;

	makecontext(&uc, (void (*)(void))coroutine_trampoline,
		    2, arg.i[0], arg.i[1]);

	if (!sigsetjmp(old_env, 0)) {
		swapcontext(&old_uc, &uc);
	}

	co->entry = func;
	co->entry_arg = "Hello from UNPATCHED";

	while (1) {
		if (!sigsetjmp(co->caller, 0)) {
			siglongjmp(co->env, 1);
		}
		sleep(1);
	}

	free(stack);
	free(co);

	return 0;
}
