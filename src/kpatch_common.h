#ifndef __KPATCH_COMMON__
#define __KPATCH_COMMON__

struct kp_file {
	struct kpatch_file *patch;
	ssize_t size;
};

#define INIT_KP_FILE()	{ .patch = NULL, .size = -1 }
static inline void
init_kp_file(struct kp_file *kpf)
{
	kpf->patch = NULL;
	kpf->size = -1;
}

#include <errno.h>	/* GNU has TLS errno */

#define ROUND_DOWN(x, m) ((x) & ~((m) - 1))
#define ROUND_UP(x, m) (((x) + (m) - 1) & ~((m) - 1))
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

#define proc2pctx(proc) list_first_entry(&(proc)->ptrace.pctxs,		\
					 struct kpatch_ptrace_ctx, list)
#define ks2pctx(ks) proc2pctx(&((ks)->proc))

int kpatch_open_fd(int fd, struct kp_file *kpatch);
int kpatch_openat_file(int atfd, const char *fname, struct kp_file *kpatch);
int kpatch_open_file(const char *fname, struct kp_file *kpatch);
int kpatch_close_file(struct kp_file *kpatch);

#ifndef R_X86_64_REX_GOTPCRELX
/*
 * Ubuntu 1604 specific relocation that is GOTPCREL with code rewrite, more
 * info here https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI
 */
#	define R_X86_64_REX_GOTPCRELX	0x2A
#endif

#ifndef R_X86_64_GOTPCRELX
#	define R_X86_64_GOTPCRELX	0x29
#endif

#endif
