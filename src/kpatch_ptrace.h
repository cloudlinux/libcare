#ifndef __KPATCH_PTRACE_H__
#define __KPATCH_PTRACE_H__

#include <sys/user.h>

#include "list.h"

struct kpatch_ptrace_ctx {
	int pid;
	int running;
	unsigned long execute_until;
	kpatch_process_t *proc;
	struct list_head list;
};

struct process_mem_iter {
	kpatch_process_t *proc;
	unsigned long base;
	size_t buflen;
	size_t buffer_size;
	char buffer[];
};

struct process_mem_iter *
kpatch_process_mem_iter_init(kpatch_process_t *proc);
void kpatch_process_mem_iter_free(struct process_mem_iter *iter);
int kpatch_process_mem_iter_peek_ulong(struct process_mem_iter *iter,
				       unsigned long *dst,
				       unsigned long remote_addr);
int kpatch_process_mem_iter_peek(struct process_mem_iter *iter,
				 void *dst, size_t size,
				 unsigned long remote_addr);

#define REMOTE_PEEK(iter, dst, remote_addr) \
	kpatch_process_mem_iter_peek((iter), &(dst), sizeof(dst),	\
				     (unsigned long)(remote_addr))

#define PEEK_ULONG(p) ({						\
	unsigned long l;						\
	if (kpatch_process_mem_iter_peek_ulong(iter, &l,		\
					       (unsigned long)(p)) < 0) {\
		kpdebug("FAIL. Failed to peek at 0x%lx - %s\n",		\
			(unsigned long)(p), strerror(errno));		\
		return -1;						\
	}								\
	l;								\
})


void kpatch_ptrace_ctx_destroy(struct kpatch_ptrace_ctx *pctx);

int kpatch_ptrace_attach_thread(kpatch_process_t *proc, int tid);
int kpatch_ptrace_detach(struct kpatch_ptrace_ctx *pctx);

int kpatch_ptrace_handle_ld_linux(kpatch_process_t *proc,
				  unsigned long *pentry_point);

int kpatch_ptrace_kickstart_execve_wrapper(kpatch_process_t *proc);
int kpatch_ptrace_get_entry_point(struct kpatch_ptrace_ctx *pctx,
				  unsigned long *pentry_point);

#define EXECUTE_ALL_THREADS	(1 << 0) /* execute all threads not just these
					    having non-zero execute_until */
int kpatch_ptrace_execute_until(kpatch_process_t *proc,
				int timeout_msec,
				int flags);

int kpatch_execute_remote(struct kpatch_ptrace_ctx *pctx,
			  const unsigned char *code,
			  size_t codelen,
			  struct user_regs_struct *pregs);

int kpatch_ptrace_resolve_ifunc(struct kpatch_ptrace_ctx *pctx,
				unsigned long *addr);
unsigned long
kpatch_mmap_remote(struct kpatch_ptrace_ctx *pctx,
		   unsigned long addr,
		   size_t length,
		   int prot,
		   int flags,
		   int fd,
		   off_t offset);
int
kpatch_munmap_remote(struct kpatch_ptrace_ctx *pctx,
		     unsigned long addr,
		     size_t length);
int kpatch_arch_prctl_remote(struct kpatch_ptrace_ctx *pctx, int code, unsigned long *addr);

int
kpatch_process_mem_read(kpatch_process_t *proc,
			unsigned long src,
			void *dst,
			size_t size);
int
kpatch_process_mem_write(kpatch_process_t *proc,
			 void *src,
			 unsigned long dst,
			 size_t size);

int
kpatch_process_memcpy(kpatch_process_t *proc,
		      unsigned long dst,
		      unsigned long src,
		      size_t size);
#endif
