
#include <ucontext.h>
#include <setjmp.h>

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
".text\n"
".type	coroutine_trampoline, @function\n"
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
".size	coroutine_trampoline, .-coroutine_trampoline\n"
);

extern void coroutine_trampoline(void);

static CoroutineUContext *running_co;

static void coroutine_yield(void)
{
	if (!sigsetjmp(running_co->env, 0))
		siglongjmp(running_co->caller, 1);
}

#define PAGE_SIZE	4096
#define PAGE_MASK	(PAGE_SIZE - 1)

static CoroutineUContext *coroutine_new(void (*entry)(void *),
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

	co = calloc(1, sizeof(*co));
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

	printf("entry=%p co=%p old_uc=%p uc=%p stack=%p ssize=%lx\n",
	       entry, co, &old_uc, &uc, co->stack, uc.uc_stack.ss_size);

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

static void coroutine_free(CoroutineUContext *co)
{
	free(co->stack_orig);
	free(co);
}

static void coroutine_exec(CoroutineUContext *co)
{
	running_co = co;

	if (!sigsetjmp(co->caller, 0)) {
		siglongjmp(co->env, 1);
	}

	running_co = NULL;
}
