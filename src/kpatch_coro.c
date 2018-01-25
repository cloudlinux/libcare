#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libunwind-ptrace.h>

#include <sys/utsname.h>

#include <asm/prctl.h>

#include "kpatch_user.h"
#include "kpatch_coro.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "kpatch_ptrace.h"
#include "kpatch_log.h"

/* Indicates that the next CORO flavours should be tried */
#define CORO_SEARCH_NEXT	(1<<31)

static struct kpatch_coro *
kpatch_coro_new(struct kpatch_process *proc)
{
	struct kpatch_coro *c;

	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));
	list_init(&c->list);
	list_add(&c->list, &proc->coro.coros);
	return c;
}

static void
kpatch_coro_free(struct kpatch_coro *c)
{
	list_del(&c->list);
	free(c);
}


/*
 * Finding coroutines in CentOS7 default QEMU.
 */

/*
 * The following is UGLY, but here is the thing.
 * QEMU does not maintain a full list of all coroutines.
 * Some of them may be obtained from a list of throttled
 * or overlapped I/O requests, some of them from some other
 * lists but in general it's not possible to find all coroutines
 * through some lists. So we are going to scan [heap] for them.
 *
 * How it works:
 * 0) makecontext() which is used to create coroutine context
 *    leaves some known marker (__start_context address) on
 *    the stack.
 * 1) QEMU in CentOS7 uses tcmalloc, which allocates page-aligned
 *    addresses for big allocation. So coroutines stack is always
 *    page aligned. And it uses sbrk() by default, so no need to
 *    scan for mmap()'ed areas.
 * 2) There is a pointer to CoroutineUContext on the stack as well,
 *    wich can be used to obtain saved register and eventually
 *    do backtrace.
 *
 * Stack layout for coroutine (last 8 longs):
 *
 * (gdb) x/8gx 0x555558d2ffc0
 * 0x555558d2ffc0: [1] 0x0000555556ce2500      [2] 0x0000555556ce2500
 * 0x555558d2ffd0: [3] 0x0000000000000000      [4] 0x927f952074baf100
 * 0x555558d2ffe0: [5] 0x0000555558d2fff0      [6] 0x00007ffff10f2110
 * 0x555558d2fff0: [7] 0x00007fffffffb6c0      [8] 0x0000000000000000
 *
 * [1] and [2] are pointers to CoroutineUContext
 * [3] and [8] are some garbage
 * [4] is a stack protector cookie, not interesting for us
 * [5] is a pointer to [7]
 * [6] is the __start_context address
 * [7] is a pointer to previous context, should be within [stack].
 *     But coroutines can be created from threads as well, so [stack]
 *     may differ. We are not going to check for it.
 *
 * So we are going to find [6] in [heap], sanity check it based on
 * other data nearby and if everything is Ok -> we've found our
 * coroutine.
 *
 * This may really be slow for huge [heap]. Ideally, what we need to
 * do is:
 *
 *   - hook qemu right after start
 *   - track every created coroutine and record its address
 *   - as soon as we need to apply new patch we already have
 *     all the coroutines
 *
 * This approach requires some constantly running service and
 * some kind of persistency (to allow kernelcare updates). This
 * service also can listen to netlink events about new processes.
 */
#define PTR_DEMANGLE(ptr, key) ((((ptr) >> 0x11) | ((ptr) << 47)) ^ key)
#define JB_RBX 0
#define JB_RBP 1
#define JB_R12 2
#define JB_R13 3
#define JB_R14 4
#define JB_R15 5
#define JB_RSP 6
#define JB_RIP 7

#define GLIBC_TLS_PTR_GUARD 0x30

#define STACK_OFFSET_UC_LINK (2 * sizeof(long))
#define STACK_OFFSET_START_CONTEXT (3 * sizeof(long))
#define STACK_OFFSET_UC_LINK_PTR (4 * sizeof(long))
#define STACK_OFFSET_COROUTINE_UCONTEXT (7 * sizeof(long))
#define STACK_OFFSET_COROUTINE (8 * sizeof(long))

#define UCONTEXT_OFFSET_JMPBUF 0x38

#define UCONTEXT_OFFSET_UC_STACK_SS_SP		offsetof(ucontext_t, uc_stack.ss_sp)
#define UCONTEXT_OFFSET_UC_STACK_SS_SIZE	offsetof(ucontext_t, uc_stack.ss_size)

asm ("makecontext_call:\n"
     "mov %rsp, %rbp\n"
     "and $-16, %rbp\n"
     /* ucontext_t is 0x3a8 bytes */
     "sub $0x400, %rbp\n"
     /* TODO interpolate these from the calculations above */

     /* set uc_stack.ss_sp and uc_stack.ss_size */
     /* TODO magic -128 is used below as well */
     "lea -128(%rbp), %rbx\n"
     "movq %rbx, 0x10(%rbp)\n"
     "movq $128, 0x20(%rbp)\n"
     "mov %rbp, %rdi\n"
     "mov $0x100, %rsi\n"
     "xor %rdx, %rdx\n"
     /* call `makecontext` */
     "call *%rax\n"
     "int3\n"
     "makecontext_call_end:");

extern unsigned char makecontext_call, makecontext_call_end;

static int
locate_start_context_symbol(struct kpatch_process *proc,
			    unsigned long *pstart_context)
{
	struct object_file *olibc;
	struct user_regs_struct regs;
	int rv;
	unsigned long makecontext;

	olibc = kpatch_process_get_obj_by_regex(proc, "^libc-.*\\.so");
	if (olibc == NULL) {
		kpdebug("FAIL. Can't find libc\n");
		return -1;
	}

	rv = kpatch_resolve_undefined_single_dynamic(olibc,
						     "makecontext",
						     &makecontext);
	makecontext = vaddr2addr(olibc, makecontext);
	if (rv < 0 || makecontext == 0) {
		kpdebug("FAIL. Can't find makecontext\n");
		return -1;
	}

	regs.rax = makecontext;
	rv = kpatch_execute_remote(proc2pctx(proc),
				   &makecontext_call,
				   &makecontext_call_end - &makecontext_call,
				   &regs);
	if (rv < 0) {
		kpdebug("FAIL. Can't execute makecontext\n");
		return -1;
	}

	rv = kpatch_process_mem_read(proc,
				     regs.rbp - STACK_OFFSET_START_CONTEXT,
				     pstart_context,
				     sizeof(*pstart_context));
	if (rv < 0) {
		kpdebug("FAIL. Can't peek __start_context address\n");
		return -1;
	}
	return rv;
}

static int is_test_target(struct kpatch_process *proc,
			  const char *procname)
{
	return strcmp(proc->comm, procname) == 0;
}

static int get_ptr_guard(struct kpatch_process *proc,
			 unsigned long *ptr_guard)
{
	int ret;
	unsigned long tls;

	ret = kpatch_arch_prctl_remote(proc2pctx(proc), ARCH_GET_FS, &tls);
	if (ret < 0) {
		kpdebug("FAIL. Can't get TLS base value\n");
		return -1;
	}
	ret = kpatch_process_mem_read(proc,
				      tls + GLIBC_TLS_PTR_GUARD,
				      ptr_guard,
				      sizeof(*ptr_guard));
	if (ret < 0) {
		kpdebug("FAIL. Can't get pointer guard value\n");
		return -1;
	}

	return 0;
}

int is_centos7_qemu(struct kpatch_process *proc)
{
	struct utsname uts;

	if (uname(&uts))
		return 0;

	if (strncmp(proc->comm, "qemu-", 5))
		return 0;

	if (strncmp(uts.release, "3.10.0-", 7))
		return 0;

	if (!strstr(uts.release, "el7.x86_64"))
		return 0;

	return 1;
};


static int qemu_centos7_find_coroutines(struct kpatch_process *proc)
{
	struct object_file *oheap, *tcmalloc;
	struct process_mem_iter *iter;
	struct kpatch_coro *coro;
	struct vm_area heap;
	unsigned long __start_context, ptr_guard, cur;
	int ret;

	if (!is_test_target(proc, "fail_coro") && !is_centos7_qemu(proc))
		return CORO_SEARCH_NEXT;

	kpdebug("Looking for coroutines in QEMU %d...\n", proc->pid);
	oheap = kpatch_process_get_obj_by_regex(proc, "^\\[heap\\]$");
	tcmalloc = kpatch_process_get_obj_by_regex(proc, "^libtcmalloc.*\\.so\\.4.*");
	if (!oheap) {
		kpdebug("FAIL. Can't find [heap](%p)\n", oheap);
		return -1;
	}

	/* NOTE(pboldin) We accurately craft stack for test so we
	 * don't need tcmalloc installed and used
	 */
	if (!tcmalloc && !is_test_target(proc, "fail_coro")) {
		kpdebug("FAIL. Can't find tcmalloc lib. Full [heap] scan is not "
			"implemented yet");
		return -1;
	}
	heap = list_first_entry(&oheap->vma, struct obj_vm_area, list)->inmem;

	ret = locate_start_context_symbol(proc, &__start_context);
	if (ret < 0) {
		kpdebug("FAIL. Can't locate_start_context_symbol\n");
		return CORO_SEARCH_NEXT;
	}

	ret = get_ptr_guard(proc, &ptr_guard);
	if (ret < 0) {
		kpdebug("FAIL. Can't get_ptr_guard\n");
		return -1;
	}

	iter = kpatch_process_mem_iter_init(proc);
	if (iter == NULL) {
		kpdebug("FAIL. Can't allocate process memory iterator.\n");
		return -1;
	}

	for (cur = heap.start; cur < heap.end; cur += PAGE_SIZE) {
		unsigned long val, val2;
		unsigned long ptr = cur + PAGE_SIZE;
		unsigned long *regs;

		val = PEEK_ULONG(ptr - STACK_OFFSET_START_CONTEXT);
		if (val != __start_context)
			continue;
		val = PEEK_ULONG(ptr - STACK_OFFSET_UC_LINK_PTR);
		if (val != (unsigned long)(ptr - STACK_OFFSET_UC_LINK))
			continue;
		val = PEEK_ULONG(ptr - STACK_OFFSET_COROUTINE);
		val2 = PEEK_ULONG(ptr - STACK_OFFSET_COROUTINE_UCONTEXT);
		if (val != val2)
			continue;
		kpdebug("Found a coroutine at %lx\n", val);

		coro = kpatch_coro_new(proc);
		if (!coro) {
			kpdebug("FAIL. Can't alloc coroutine\n");
			ret = -1;
			break;
		}
		ret = kpatch_process_mem_read(proc,
					      val + UCONTEXT_OFFSET_JMPBUF,
					      &coro->env,
					      sizeof(coro->env));
		if (ret < 0) {
			kpdebug("FAIL. Can't get coroutine registers\n");
			break;
		}

		regs = (unsigned long *)coro->env[0].__jmpbuf;
		regs[JB_RBP] = PTR_DEMANGLE(regs[JB_RBP], ptr_guard);
		regs[JB_RSP] = PTR_DEMANGLE(regs[JB_RSP], ptr_guard);
		regs[JB_RIP] = PTR_DEMANGLE(regs[JB_RIP], ptr_guard);
	}

	kpatch_process_mem_iter_free(iter);

	return ret;
}

/*
 * Finding coroutines in CentOS7 QEMU LibCare enabled.
 */
static int qemu_cloudlinux_find_coroutines(struct kpatch_process *proc)
{
	int rv, i;

	unsigned long coroutines_list, coroutine, ptr_guard;
	int coroutines_list_offset, coroutine_env_offset;

	struct variable_desc {
		const char *name;
		void *data;
		unsigned long size;
	} variables[] = {
		{
			"coroutines_list",
			&coroutines_list,
			sizeof(coroutines_list)
		},
		{
			"coroutines_list_offset",
			&coroutines_list_offset,
			sizeof(coroutines_list_offset)
		},
		{
			"coroutine_env_offset",
			&coroutine_env_offset,
			sizeof(coroutine_env_offset)
		}
	};
	struct object_file *exec_obj;

	if (!is_test_target(proc, "fail_coro_listed") && !is_centos7_qemu(proc))
		return CORO_SEARCH_NEXT;

	exec_obj = kpatch_process_get_obj_by_regex(proc, proc->comm);
	if (exec_obj == NULL) {
		kpdebug("FAIL. Can't find main object\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(variables); i++) {
		unsigned long addr;
		struct variable_desc *variable = &variables[i];

		rv = kpatch_resolve_undefined_single_dynamic(exec_obj,
							     variable->name,
							     &addr);
		if (rv < 0) {
			kpdebug("FAIL. Can't find symbol %s\n", variable->name);
			return i == 0 ? CORO_SEARCH_NEXT : -1;
		}

		rv = kpatch_process_mem_read(proc,
					     exec_obj->load_offset + addr,
					     variable->data,
					     variable->size);
		if (rv < 0) {
			kpdebug("FAIL. can't read symbol %s\n", variable->name);
			return -1;
		}
	}

	rv = get_ptr_guard(proc, &ptr_guard);
	if (rv < 0) {
		kpdebug("FAIL. Can't get_ptr_guard\n");
		return -1;
	}

	coroutine = coroutines_list;

	kpdebug("coroutines_list = %lx, coroutines_list_offset = %d, coroutine_env_offset = %d\n",
		coroutines_list, coroutines_list_offset, coroutine_env_offset);

	while (coroutine) {
		struct kpatch_coro *coro;
		unsigned long *regs;

		coro = kpatch_coro_new(proc);
		if (!coro) {
			kpdebug("FAIL. Can't alloc coroutine\n");
			return -1;
		}
		rv = kpatch_process_mem_read(proc,
					     coroutine + coroutine_env_offset,
					     &coro->env,
					     sizeof(coro->env));
		if (rv < 0) {
			kpdebug("FAIL. Can't get coroutine registers\n");
			return -1;
		}

		regs = (unsigned long *)coro->env[0].__jmpbuf;
		regs[JB_RBP] = PTR_DEMANGLE(regs[JB_RBP], ptr_guard);
		regs[JB_RSP] = PTR_DEMANGLE(regs[JB_RSP], ptr_guard);
		regs[JB_RIP] = PTR_DEMANGLE(regs[JB_RIP], ptr_guard);

		rv = kpatch_process_mem_read(proc, coroutine + coroutines_list_offset,
					     &coroutine, sizeof(coroutine));
		if (rv < 0) {
			kpdebug("FAIL. Can't get coroutine next\n");
			return -1;
		}
		kpdebug("coroutine = %lx\n", coroutine);
	}

	return 0;
}

static int fail_if_uses_coroutines(struct kpatch_process *proc)
{
	/* TODO(pboldin): check whether `makecontext`, `setjmp` or another
	 * coroutine-related functions are used and fail then.
	 */
	if (is_test_target(proc, "fail_coro_listed") ||
	    is_test_target(proc, "fail_coro") ||
	    is_centos7_qemu(proc)) {
		kperr("Process %s(%d) uses coroutines but we were unable to find them\n",
		      proc->comm, proc->pid);
		return -1;
	}

	return 0;
}

static struct kpatch_coro_ops kpatch_coro_flavours[] = {
	{
		.find_coroutines = qemu_cloudlinux_find_coroutines
	},
	{
		.find_coroutines = qemu_centos7_find_coroutines
	},
	{
		.find_coroutines = fail_if_uses_coroutines,
	},
};


/*
 * Due to bug in libunwind, the following layout is not possible:
 * struct UCORO_info {
 * 	void *upt;
 *	struct kpatch_coro *coro;
 * };
 *
 * Because it sometimes does nested callbacks and passes not the original
 * argument, but the one the was given as an arguement to the callback:
 *
 * (gdb) bt
 * #0  0x000000000040c837 in _UPT_access_mem ()
 * #1  0x000000000040c263 in _UCORO_access_mem (as=0x6130b0, addr=140000404342312, val=0x7fffffffd650, write=0, arg=0x628800) at kpatch_coro.c:258
 * #2  0x00007ffff79b30a0 in dwarf_readu8 (a=<optimized out>, arg=0x628800, valp=<synthetic pointer>, addr=<synthetic pointer>, as=0x6130b0)
 *     at ../include/dwarf_i.h:144
 * #3  dwarf_readu16 (arg=0x628800, val=<synthetic pointer>, addr=<synthetic pointer>, a=0x6130b0, as=0x6130b0) at ../include/dwarf_i.h:161
 * #4  dwarf_readu32 (arg=0x628800, val=<synthetic pointer>, addr=<synthetic pointer>, a=0x6130b0, as=0x6130b0) at ../include/dwarf_i.h:179
 * #5  dwarf_reads32 (arg=0x628800, val=<synthetic pointer>, addr=<synthetic pointer>, a=0x6130b0, as=0x6130b0) at ../include/dwarf_i.h:241
 * #6  remote_lookup (arg=0x628800, e=0x7fffffffd640, rel_ip=-2584508, table_size=<optimized out>, table=<optimized out>, as=0x6130b0)
 *     at dwarf/Gfind_proc_info-lsb.c:804
 *#7  _Ux86_64_dwarf_search_unwind_table (as=0x6130b0, ip=140000401719704, di=0x628818, pi=0x7fffffffde70, need_unwind_info=1, arg=0x628800)
 *    at dwarf/Gfind_proc_info-lsb.c:881
 * #8  0x000000000040cd1b in _UPT_find_proc_info ()
 * #9  0x000000000040c122 in _UCORO_find_proc_info (as=0x6130b0, ip=140000401719704, pi=0x7fffffffde70, need_unwind_info=1, arg=0x6287e0) at kpatch_coro.c:230
 * #10 0x00007ffff79af505 in fetch_proc_info (c=c@entry=0x7fffffffdd10, ip=140000401719704, need_unwind_info=need_unwind_info@entry=1) at dwarf/Gparser.c:422
 * #11 0x00007ffff79b1802 in uncached_dwarf_find_save_locs (c=0x7fffffffdd10) at dwarf/Gparser.c:826
 * #12 _Ux86_64_dwarf_find_save_locs (c=c@entry=0x7fffffffdd10) at dwarf/Gparser.c:851
 * #13 0x00007ffff79b2a59 in _Ux86_64_dwarf_step (c=c@entry=0x7fffffffdd10) at dwarf/Gstep.c:34
 * #14 0x00007ffff79aa5f1 in _Ux86_64_step (cursor=0x7fffffffdd10) at x86_64/Gstep.c:71
 * #15 0x0000000000405445 in kpatch_verify_safety_single (o=0x63bac0, cur=0x7fffffffdd10, retip=0x0, paranoid=0) at kpatch_user.c:637
 * #16 0x00000000004055c4 in kpatch_verify_safety (o=0x63bac0, retips=0x6287c0) at kpatch_user.c:667
 * #17 0x000000000040597d in kpatch_ensure_safety (o=0x63bac0) at kpatch_user.c:733
 * #18 0x0000000000405d66 in kpatch_apply_patches (ks=0x613010) at kpatch_user.c:809
 * #19 0x000000000040645d in kpatch_process_patches (ks=0x613010) at kpatch_user.c:1000
 * #20 0x0000000000406951 in cmd_patch_user (argc=1, argv=0x7fffffffe3f0) at kpatch_user.c:1162
 * #21 0x00000000004036e3 in main (argc=4, argv=0x7fffffffe3d8) at kpatch_ctl.c:457
 *
 * That's why I had to do this hack
 */
struct UCORO_info {
	union {
		void *upt;
		char dummy[256];
	};
	struct kpatch_coro *coro;
};

void *_UCORO_create(struct kpatch_coro *coro, pid_t pid)
{
	struct UCORO_info *info;
	void *upt;

	upt = _UPT_create(pid);
	if (!upt)
		return NULL;
	info = realloc(upt, sizeof(*info));
	if (!info) {
		_UPT_destroy(upt);
		return NULL;
	}

	info->coro = coro;
	return (void *)info;
}

void _UCORO_destroy(void *arg)
{
	struct UCORO_info *info = (struct UCORO_info *)arg;

	_UPT_destroy(info);
}

static int
_UCORO_access_reg(unw_addr_space_t as, unw_regnum_t reg, unw_word_t *val,
		      int write, void *arg)
{
	struct UCORO_info *info = (struct UCORO_info *)arg;
	unsigned long *regs = (unsigned long *)info->coro->env[0].__jmpbuf;

	if (write) {
		kperr("_UCORO_access_reg: write is not implemeneted (%d)\n", reg);
		return -UNW_EINVAL;
	}
	switch (reg) {
		case UNW_X86_64_RBX:
			*val = regs[JB_RBX]; break;
		case UNW_X86_64_RBP:
			*val = regs[JB_RBP]; break;
		case UNW_X86_64_R12...UNW_X86_64_R15:
			*val = regs[reg - UNW_X86_64_R12 + JB_R12]; break;
		case UNW_X86_64_RSP:
			*val = regs[JB_RSP]; break;
		case UNW_X86_64_RIP:
			*val = regs[JB_RIP]; break;
		default:
			return _UPT_access_reg(as, reg, val, write, arg);
	}
	return 0;
}

static unw_accessors_t _UCORO_accessors = {
	_UPT_find_proc_info,
	_UPT_put_unwind_info,
	_UPT_get_dyn_info_list_addr,
	_UPT_access_mem,
	_UCORO_access_reg,
	_UPT_access_fpreg,
	_UPT_resume,
	_UPT_get_proc_name,
};

int kpatch_coroutines_init(struct kpatch_process *proc)
{
	proc->coro.unwd = NULL;

	list_init(&proc->coro.coros);

	/* Freshly started binary can't have coroutines */
	if (proc->is_just_started)
		return 0;

	proc->coro.unwd = unw_create_addr_space(&_UCORO_accessors, __LITTLE_ENDIAN);
	if (!proc->coro.unwd) {
		kplogerror("Can't create libunwind address space\n");
		return -1;
	}
	return 0;
}

int kpatch_coroutines_find(struct kpatch_process *proc)
{
	int i, rv;

	/* Freshly started binary can't have coroutines */
	if (proc->is_just_started)
		return 0;

	for (i = 0; i < ARRAY_SIZE(kpatch_coro_flavours); i++) {
		struct kpatch_coro_ops *ops = &kpatch_coro_flavours[i];

		rv = ops->find_coroutines(proc);
		if (rv == CORO_SEARCH_NEXT)
			continue;

		return rv;
	}
	return 0;
}

void kpatch_coroutines_free(struct kpatch_process *proc)
{
	struct kpatch_coro *c, *tmp;

	if (proc->coro.unwd)
		unw_destroy_addr_space(proc->coro.unwd);

	if (!list_empty(&proc->coro.coros))
		list_for_each_entry_safe(c, tmp, &proc->coro.coros, list) {
			kpatch_coro_free(c);
		}
}
