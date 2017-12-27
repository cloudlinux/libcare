#ifndef __KPATCH_PROCESS__
#define __KPATCH_PROCESS__

#include <libunwind.h>

#include <elf.h>
#include "kpatch_common.h"
#include "kpatch_coro.h"
#include "kpatch_file.h"
#include "list.h"

struct kpatch_process;
typedef struct kpatch_process kpatch_process_t;

struct vm_area {
	unsigned long start;
	unsigned long end;
	unsigned long offset;
	unsigned int prot;
};

struct vm_hole {
	unsigned long start;
	unsigned long end;
	struct list_head list;
};

struct obj_vm_area {
	struct vm_area inmem;
	struct vm_area inelf;
	struct vm_area ondisk;
	struct list_head list;
};

struct object_file {
	struct list_head list;
	kpatch_process_t *proc;

	/**
	 * This is a pointer to storage's kpfile, readonly.
	 */
	const struct kp_file *skpfile;

	/**
	 * This is filled with kpatch information if is_patch = 1
	 * and used as a storage for copy of a patch from storage.
	 */
	struct kp_file kpfile;

	/* Pointer to jump table for DSO relocations */
	struct kpatch_jmp_table *jmp_table;

	/* Address of the patch in target's process address space */
	unsigned long kpta;

	/* Device the object resides on */
	dev_t dev;
	ino_t inode;

	/* Object name (as seen in /proc/<pid>/maps) */
	char *name;

	/* List of object's VM areas */
	struct list_head vma;

	/* Object's Build-ID */
	char buildid[41];

	/* Patch information */
	struct kpatch_info *info;
	size_t ninfo;

	/* Address of the first allocated virtual memory area */
	unsigned long vma_start;

	/*
	 * Load offset. Add this values to symbol addresses to get
	 * correct addresses in the loaded binary. Zero for EXEC,
	 * equals to `vma_start` for DYN (libs and PIEs)
	 */
	unsigned long load_offset;

	/* ELF header for the object file */
	Elf64_Ehdr ehdr;

	/* Program header */
	Elf64_Phdr *phdr;

	/* Dynamic symbols exported by the object if it is a library */
	Elf64_Sym *dynsyms;
	size_t ndynsyms;

	char **dynsymnames;

	/* Pointer to the previous hole in the patient's mapping */
	struct vm_hole *previous_hole;

	/* Pointer to the applied patch, if any */
	struct object_file *applied_patch;

	/* Do we have patch for the object? */
	unsigned int has_patch:1;

	/* Is that a patch for some object? */
	unsigned int is_patch:1;

	/* Is it a shared library? */
	unsigned int is_shared_lib:1;

	/* Is it an ELF or a mmap'ed regular file? */
	unsigned int is_elf:1;
};

struct kpatch_process {
	/* Pid of target process */
	int pid;

	/* memory fd of /proc/<pid>/mem */
	int memfd;

	/* /proc/<pid>/maps FD, also works as lock */
	int fdmaps;

	/* Process name */
	char comm[16];

	/* List of process objects */
	struct list_head objs;
	int num_objs;

	/* List ptrace contexts (one per each thread) */
	struct {
		struct list_head pctxs;
		unw_addr_space_t unwd;
	} ptrace;

	/* List of coroutines + ops to manipulate */
	struct {
		struct list_head coros;
		unw_addr_space_t unwd;
	} coro;

	/* List of free VMA areas */
	struct list_head vmaholes;

	/* libc's base address to use as a worksheet */
	unsigned long libc_base;

	/*
	 * Is client have been stopped right before the `execve`
	 * and awaiting our response via this fd?
	 */
	int send_fd;

	/* Just started process? */
	unsigned int is_just_started:1;

	/* Is it an ld-linux trampoline? */
	unsigned int is_ld_linux:1;
};

void
kpatch_object_dump(struct object_file *o);

int
kpatch_object_allocate_patch(struct object_file *obj,
			     size_t sz);

int
kpatch_process_associate_patches(kpatch_process_t *proc);
int
kpatch_process_parse_proc_maps(kpatch_process_t *proc);
int
kpatch_process_map_object_files(kpatch_process_t *proc);
int
kpatch_process_attach(kpatch_process_t *proc);

enum {
	MEM_READ,
	MEM_WRITE,
};
int
kpatch_process_mem_open(kpatch_process_t *proc, int mode);
int
kpatch_process_load_libraries(kpatch_process_t *proc);
int
kpatch_process_kick_send_fd(kpatch_process_t *proc);

void
kpatch_process_print_short(kpatch_process_t *proc);

int
kpatch_process_init(kpatch_process_t *proc,
		    int pid,
		    int is_just_started,
		    int send_fd);
void
kpatch_process_free(kpatch_process_t *proc);


struct object_file *
kpatch_process_get_obj_by_regex(kpatch_process_t *proc, const char *regex);

static inline int
is_kernel_object_name(char *name)
{
       if ((name[0] == '[') && (name[strlen(name) - 1] == ']'))
               return 1;
       if (strncmp(name, "anon_inode", 10) == 0)
               return 1;
       return 0;
}

#endif /* ifndef __KPATCH_PROCESS__ */
