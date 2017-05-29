#ifndef __KPATCH_ELF__
#define __KPATCH_ELF__

#include "kpatch_process.h"

const char *kpatch_get_buildid(struct object_file *o);

/*
 * Set ELF header (and program headers if they fit)
 * from the already read `buf` of size `bufsize`.
 */
int
kpatch_elf_object_set_ehdr(struct object_file *o,
			   const unsigned char *buf,
			   size_t bufsize);

int kpatch_elf_object_is_shared_lib(struct object_file *o);
int kpatch_elf_parse_program_header(struct object_file *o);
int kpatch_elf_load_kpatch_info(struct object_file *o);

int kpatch_resolve(struct object_file *o);
int kpatch_relocate(struct object_file *o);

struct kpatch_jmp_table *kpatch_new_jmp_table(int entries);
int kpatch_count_undefined(struct object_file *o);

int kpatch_resolve_undefined_single_dynamic(struct object_file *o,
					    const char *sname,
					    unsigned long *addr);

unsigned long vaddr2addr(struct object_file *o, unsigned long vaddr);

struct kpatch_jmp_table_entry {
	unsigned long jmp;
	unsigned long addr;
};

struct kpatch_jmp_table {
	unsigned int size;
	unsigned int cur_entry;
	unsigned int max_entry;

	struct kpatch_jmp_table_entry entries[0];
};

#endif
