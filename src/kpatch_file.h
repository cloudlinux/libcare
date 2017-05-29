#ifndef __KPATCH_FILE_H__
#define __KPATCH_FILE_H__

#ifndef __ASSEMBLY__

#ifndef __KERNEL__
#include <stdint.h>
#else
#include <linux/types.h>
#include <linux/init.h>
#endif
#ifndef __MACH__
#include <linux/ioctl.h>
#endif

#ifdef __KERNEL__

#include <linux/list.h> /* for hlist_head */
#include <linux/rcupdate.h> /* for rcu_head */

struct kpatch_binding_type {
	void (*dtor)(void *);
	unsigned int size;
	unsigned int offset;
	const char *name;
	unsigned long objsize;
};

struct kpatch_binding {
	struct kpatch_binding_type *type;
	struct kmem_cache *cache;
	struct hlist_head hash[0];
};

struct kpatch_binding_node {
	struct kpatch_binding *binding;
	void *ptr;
	struct hlist_node hlist;
	struct rcu_head rcu;
};

/* functions to be used by init/exit calls */
struct kpatch_binding * kpatch_binding_create( struct kpatch_binding_type *);
void kpatch_binding_destroy(struct kpatch_binding *);
/* kpatch_binding API */
void * kpatch_binding_node_alloc(struct kpatch_binding *, gfp_t);
void kpatch_binding_node_free(struct kpatch_binding_node *);
void kpatch_binding_node_bind(struct kpatch_binding_node *, void *);
void kpatch_binding_node_unbind(struct kpatch_binding_node *);
void * kpatch_binding_lookup_entry(struct kpatch_binding *, void *);
struct kpatch_binding_node * kpatch_binding_lookup_node(struct kpatch_binding *, void *);

#ifndef __used
#define __used                  __attribute__((__used__))
#endif

#define kpatch_init_pre(fn) static initcall_t __kpatch_init_pre_##fn __used \
		__attribute__((__section__(".kpatch.init.pre"))) = fn
#define kpatch_init(fn) static initcall_t __kpatch_init_##fn __used \
		__attribute__((__section__(".kpatch.init"))) = fn
#define kpatch_init_post(fn) static initcall_t __kpatch_init_post_##fn __used \
		__attribute__((__section__(".kpatch.init.post"))) = fn

#define kpatch_exit_pre(fn) static exitcall_t __kpatch_exit_pre_##fn __used \
		__attribute__((__section__(".kpatch.exit.pre"))) = fn
#define kpatch_exit(fn) static exitcall_t __kpatch_exit_##fn __used \
		__attribute__((__section__(".kpatch.exit"))) = fn
#define kpatch_exit_post(fn) static exitcall_t __kpatch_exit_post_##fn __used \
		__attribute__((__section__(".kpatch.exit.post"))) = fn
#endif

typedef uint32_t kpatch_offset_t;
typedef uint32_t kpatch_reloc_t;

/* Load patch into memory, verifies it (checksum, etc...) and applies it */
#define KPATCH_APPLY      _IOW('k', 0, struct kpatch_payload *)
/* Undo the patch */
#define KPATCH_UNDO      _IO('k', 1)
/* Query info about patches */
#define KPATCH_INFO      _IOR('k', 2, struct kpatch_query *)

struct kpatch_file;
struct kpatch_data;

typedef int (*kpatch_entry)(struct kpatch_file *, unsigned long size, void **);
typedef void *(*kpatch_alloc)(unsigned long);
typedef int (*kpatch_undo_patch)(struct kpatch_data *);

#define SET_BIT(r,b) ((r) |= (1 << (b)))
#define CLR_BIT(r,b) ((r) &= ~((1) << (b)))
#define TEST_BIT(r,b) ((r) & (1<<(b)))

#define KPATCH_FILE_MAGIC1	"KPATCH1"
#define KPATCH_MAX_NR_ENTRIES	16
#define KPATCH_UNAME_LEN	256

#define KPATCH_DEBUG_FLAG    0
#define KPATCH_NOFREEZE_FLAG 1 /* this flag is ignored, use safety method insted */

enum {
	KPATCH_SAFETY_METHOD_DEFAULT = 0,
	KPATCH_SAFETY_METHOD_FREEZE_ALL,
	KPATCH_SAFETY_METHOD_FREEZE_NONE,
	KPATCH_SAFETY_METHOD_FREEZE_CONFLICT,
	KPATCH_SAFETY_METHOD_MAX,
};

struct kpatch_payload {
	size_t size;
	char *patch;
	char *description; // could be NULL
};

struct kpatch_file {
	char magic[8];			/* magic string */
	unsigned char flags;
	unsigned char safety_method;
	char pad[6];
	char modulename[64];		/* "vmlinux" or module name */
	char uname[KPATCH_UNAME_LEN];	/* /proc/version of the kernel */

	uint64_t build_time;		/* build time */
	uint32_t csum;			/* checksum of the whole kpatch */
	uint32_t nr_reloc;		/* number of relocations */

	kpatch_offset_t kpatch_offset;	/* content offset */
	kpatch_offset_t rel_offset;	/* relocations offset (vmlinux) */
	kpatch_offset_t total_size;	/* total size = header + relocations + content */
	kpatch_offset_t jmp_offset;	/* jump table offset for user-space patches */

	/* array of entry offsets in the patch content */
	union {
		kpatch_offset_t entries[KPATCH_MAX_NR_ENTRIES];
		struct {
			kpatch_offset_t kpatch_entry;
			kpatch_offset_t kpatch_module_alloc;
			kpatch_offset_t kpatch_unpatch;
			kpatch_offset_t kpatch_delta;
		};
		struct {
			kpatch_offset_t elf_hdr;	/* saved offset to ELF hdr */
			kpatch_offset_t extbl_start;	/* exception table start for modules */
			kpatch_offset_t extbl_end;	/* exception table end for modules */
			kpatch_offset_t bugtbl_start;	/* bug table start for modules */
			kpatch_offset_t bugtbl_end;	/* bug table end for modules */
		};
		struct {
			kpatch_offset_t user_undo;	/* undo information for userspace */
			kpatch_offset_t user_info;	/* patch information */
			kpatch_offset_t user_level;	/* FIXME(pboldin) */
		};
	};

	char srcversion[25]; /* srcversion of module or zeros */
	char pad2[231];

	/* relocations */
	/* content */
};

struct kpatch_reloc {
	kpatch_reloc_t offset;	/* offset in file */
	char type;		/* relocation type */
/* possible pcrel values according to area offset points to:
 * ==  0 - offset points to kpatch area,
 * ==  1 - offset points to vmlinux area,
 * == -1 - offset points to per_cpu variable */
#define KPATCH_PCREL_EXT_KPATCH (0)
#define KPATCH_PCREL_EXT_VMLINUX (1)
#define KPATCH_PCREL_EXT_PER_CPU (-1)
	char pcrel;		/* pcrel = 0 => code reloation +x bytes should adjust relocation value by +x, otherwise -x */
	char pad[2];
	char pad2[4];
	kpatch_reloc_t delta;	/* not used for patching, only during make stage */
};

#define KPATCH_INFO_PTR64(name) union { unsigned long name; uint64_t name ## 64; }
struct kpatch_info {
	KPATCH_INFO_PTR64(daddr);
	KPATCH_INFO_PTR64(saddr);
	uint32_t dlen;
	uint32_t slen;
	KPATCH_INFO_PTR64(symstr);
	KPATCH_INFO_PTR64(vaddr);
	uint32_t flags;
	char     pad[4];
};

struct kpatch_undo_entry {
	#define UNDO_ENTRY_ALLOCATED	(1 << 0)
	#define UNDO_ENTRY_PATCHED	(1 << 1)
	#define UNDO_ENTRY_EXITED	(1 << 2)
	long flags;
	/* module name or vmlinux */
	char modulename[64];
	/* pointer original code (all hunks stored sequentially) */
	void *orig_code;
	/* pointer to original patch (for exitcalls) */
	struct kpatch_file *kpatch;
};

/* data stored by kpatch-loader to support unpatching */
struct kpatch_undo {
	/* number of entries */
	uint32_t nr_entries;
	/* size of the area */
	size_t size;
	/* entries */
	struct kpatch_undo_entry entries[];
};

struct kpatch_query_info {
	/* Patch state */
#define KPATCH_STATE_NONE	0	/* No patch applied */
#define KPATCH_STATE_APPLIED	1	/* Patch is applied */
	uint32_t state;

	char uname[KPATCH_UNAME_LEN];
	char description[512];

	uint64_t build_time;
	/* Add info about patch (name?/modules?, etc.) */
	char pad[1024];
};

#ifndef __kpatch_text
# define __kpatch_text
#endif /* ifndef __kpatch_text */

static inline int
__kpatch_text
is_end_info(struct kpatch_info *info)
{
	return (info->daddr == 0) && (info->dlen == 0) &&
		(info->saddr == 0) && (info->slen == 0);
}

static inline int
__kpatch_text
is_new_func(struct kpatch_info *info)
{
	return (info->daddr == 0) && (info->dlen == 0);
}

#endif /* __ASSEMBLY__ */

#ifdef __KPATCH_ASSEMBLY__

#define KPATCH_INFO_DEFINE(fname, flags) KPATCH_INFO_DEFINE fname, flags
/* we use can CPP to define macro, but if we do it macro
 * will expand in one line, which is nearly impossible to
 * read in preprocessed file
 */
.macro KPATCH_INFO_DEFINE fname, flags
.pushsection .kpatch.strtab,"a",@progbits
\fname\().kpatch_strtab:
	.string "\fname\().kpatch"
.popsection
.pushsection .kpatch.info,"a",@progbits
\fname\().Lpi:
	.ifdef \fname
		.quad \fname
	.else
		.quad 0
	.endif
	.quad \fname\().kpatch
	.ifdef \fname
		.long \fname\().Lfe - \fname
	.else
		.long 0
	.endif
	.long \fname\().kpatch_end - \fname\().kpatch
	.quad \fname\().kpatch_strtab
	.quad 0
	.long \flags
	.byte 0, 0, 0, 0
.popsection
.endm

#endif /* __KPATCH_ASSEMBLY__ */
#endif
