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

union cc_arg {
	void *p;
	int i[2];
};

/*
 * Reproduce the exact stack layout expected by the coroutine-detection
 * algorithm. Since different versions of GCC produce different machine code
 * we had to place the asm code there.
 *
 * The following is the C code:
 */

#if 0
static void coroutine_trampoline(int i0, int i1)
{
    union cc_arg arg;
    CoroutineUContext *self;
    Coroutine *co;

    arg.i[0] = i0;
    arg.i[1] = i1;
    self = arg.p;
    co = &self->base;

    /* Initialize longjmp environment and switch back the caller */
    if (!sigsetjmp(self->env, 0)) {
        siglongjmp(*(sigjmp_buf *)co->entry_arg, 1);
    }

    while (true) {
        co->entry(co->entry_arg);
        /* qemu_coroutine_switch(co, co->caller, COROUTINE_TERMINATE); */
    }
}
#endif

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

static CoroutineUContext *running_co;

static void coroutine_yield(void)
{
	if (!sigsetjmp(running_co->env, 0))
		siglongjmp(running_co->caller, 1);
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

CoroutineUContext *coroutine_new(void (*entry)(void *),
				 void *entry_arg)
{
	CoroutineUContext *co;
	const size_t stack_size = 1 << 14;
	ucontext_t uc, old_uc;
	sigjmp_buf old_env;
	union cc_arg arg = { 0 };
	void *stack;

	if (getcontext(&uc) == -1)
		return NULL;

	co = malloc(sizeof(*co));
	if (co == NULL)
		return NULL;

	stack = malloc(stack_size);
	if (stack == NULL)
		return NULL;

	co->stack_orig = stack;
	co->stack = (void *)((unsigned long)(stack + PAGE_SIZE - 1) & ~PAGE_MASK);

	co->entry_arg = &old_env;

	uc.uc_link = &old_uc;
	uc.uc_stack.ss_sp = co->stack;
	uc.uc_stack.ss_size = stack_size - (co->stack - stack) & ~PAGE_MASK;
	uc.uc_stack.ss_flags = 0;

	printf("func=%p co=%p old_uc=%p uc=%p stack=%p ssize=%lx\n",
	       func, co, &old_uc, &uc, co->stack, uc.uc_stack.ss_size);

	arg.p = co;

	makecontext(&uc, (void (*)(void))coroutine_trampoline,
		    2, arg.i[0], arg.i[1]);

	if (!sigsetjmp(old_env, 0)) {
		swapcontext(&old_uc, &uc);
	}

	co->entry = entry;
	co->entry_arg = entry_arg;

	return co;
}

void coroutine_free(CoroutineUContext *co)
{
	free(co->stack_orig);
	free(co);
}

void coroutine_exec(CoroutineUContext *co)
{
	running_co = co;

	if (!sigsetjmp(co->caller, 0)) {
		siglongjmp(co->env, 1);
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
