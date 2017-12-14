#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>

#include <gelf.h>

#include "kpatch_common.h"
#include "kpatch_user.h"
#include "kpatch_process.h"
#include "kpatch_elf.h"
#include "kpatch_file.h"
#include "kpatch_ptrace.h"
#include "kpatch_log.h"

static int
elf_object_peek_phdr(struct object_file *o)
{
	int rv = 0;

	if (o->vma_start != ~(unsigned long)0)
		return 0;

	o->vma_start = list_first_entry(&o->vma, struct obj_vm_area,
					list)->inmem.start;

	if (o->ehdr.e_ident[0] != '\177') {
		rv = kpatch_process_mem_read(o->proc,
					     o->vma_start,
					     &o->ehdr,
					     sizeof(o->ehdr));
		if (rv < 0)
			return rv;
	}

	if (o->phdr == NULL) {
		unsigned long phaddr = o->vma_start + o->ehdr.e_phoff;

		o->phdr = malloc(o->ehdr.e_phnum * sizeof(*o->phdr));
		if (o->phdr == NULL)
			return -1;

		rv = kpatch_process_mem_read(o->proc,
					     phaddr,
					     o->phdr,
					     sizeof(*o->phdr) * o->ehdr.e_phnum);
	}

	return rv;
}

int
kpatch_elf_object_set_ehdr(struct object_file *o,
			   const unsigned char *buf,
			   size_t bufsize)
{
	if (bufsize < sizeof(o->ehdr))
		return 0;


	if (memcmp(buf, ELFMAG, SELFMAG)) {
		kpdebug("magic(%s) = %x%x%x%x\n", o->name, buf[0], buf[1], buf[2], buf[3]);
		return -1;
	}

	memcpy(&o->ehdr, buf, sizeof(o->ehdr));

	if (bufsize < o->ehdr.e_phoff + o->ehdr.e_phentsize * o->ehdr.e_phnum)
		return 0;

	o->phdr = malloc(o->ehdr.e_phnum * sizeof(*o->phdr));
	if (o->phdr == NULL)
		return -1;

	memcpy(o->phdr, buf + o->ehdr.e_phoff,
	       o->ehdr.e_phentsize * o->ehdr.e_phnum);

	return 0;
}

static int
elf_object_look_for_buildid(struct object_file *o)
{
	int rv = -1;
	size_t i;
	char buf[128];

	rv = elf_object_peek_phdr(o);
	if (rv < 0)
		return rv;

	for (i = 0; i < o->ehdr.e_phnum; i++) {
		Elf64_Nhdr *nhdr = (void *)buf;
		char *data = buf + sizeof(*nhdr);
		size_t offset = o->phdr[i].p_offset;
		size_t lastoffset = offset + o->phdr[i].p_memsz;

		if (o->phdr[i].p_type != PT_NOTE)
			continue;
		if (o->phdr[i].p_memsz > sizeof(buf))
			continue;

		while (offset < lastoffset) {
			rv = kpatch_process_mem_read(o->proc,
						     o->vma_start + offset,
						     buf,
						     sizeof(buf));
			if (rv < 0)
				return rv;

			if (nhdr->n_namesz == 4 && !strcmp(data, "GNU") &&
			    nhdr->n_type == NT_GNU_BUILD_ID)
				break;

			offset += nhdr->n_namesz + nhdr->n_descsz + sizeof(*nhdr);
		}

		if (offset >= lastoffset)
			continue;

		data += nhdr->n_namesz;
		for (i = 0; i < 40; i+=2, data++)
			sprintf(o->buildid + i, "%02hhx", *data);

		kpdebug("read '%s'\n", o->buildid);

		return 0;
	}

	return -1;
}


const char *
kpatch_get_buildid(struct object_file *o)
{
	if (!o->is_elf)
		return NULL;

	if (o->buildid[0] == '\0') {
		int rv;

		kpdebug("Getting BuildID for '%s'...", o->name);
		rv = elf_object_look_for_buildid(o);

		if (rv < 0)
			return NULL;
	}

	return o->buildid;
}

static int
elf_object_is_interp_exception(struct object_file *o)
{
	/* libc */
	if (!strncmp(o->name, "libc", 4) &&
	    !strncmp(o->name + strlen(o->name) - 3, ".so", 3))
		return 1;
	/* libpthread */
	if (!strncmp(o->name, "libpthread", 10) &&
	    !strncmp(o->name + strlen(o->name) - 3, ".so", 3))
		return 1;
	/* libdl */
	if (!strncmp(o->name, "libdl", 5) &&
	    !strncmp(o->name + strlen(o->name) - 3, ".so", 3))
		return 1;
	return 0;
}

int kpatch_elf_object_is_shared_lib(struct object_file *o)
{
	size_t i;
	int rv;

	rv = elf_object_peek_phdr(o);
	if (rv < 0)
		return rv;

	/*
	 * If type of the ELF is not ET_DYN, this is definitely
	 * not a shared library
	 */
	if (o->ehdr.e_type != ET_DYN) {
		return 0;
	}

	/*
	 * Now there are possibilities:
	 *   - either this is really a shared library
	 *   - or this is a position-independent executable
	 * To distinguish between them look for INTERP
	 * program header that mush be present in any valid
	 * executable or usually don't in shared libraries
	 * (notable exception - libc)
	 */
	for (i = 0; i < o->ehdr.e_phnum; i++) {
		/* Ok, looks like this is an executable */
		if (o->phdr[i].p_type == PT_INTERP &&
		    !elf_object_is_interp_exception(o))
			return 0;
	}

	/* Ok, looks like this is a shared library */
	return 1;
}

static int prot2flags(unsigned int prot)
{
	unsigned int flags = 0;

	if (prot & PROT_READ)
		flags |= PF_R;
	if (prot & PROT_WRITE)
		flags |= PF_W;
	if (prot & PROT_EXEC)
		flags |= PF_X;
	return flags;
}

/* Sort by inclusion, so the previous PT_LOAD contains current PT_GNU_RELRO */
static int phdr_compare(const void *a, const void *b)
{
	const GElf_Phdr *pa = a, *pb = b;

	if (pa->p_vaddr < pb->p_vaddr)
		return -1;

	if (pa->p_vaddr > pb->p_vaddr)
		return 1;

	if (pa->p_memsz < pb->p_memsz)
		return 1;

	if (pa->p_memsz > pb->p_memsz)
		return -1;

	return 0;
}

#define PAGE_DOWN(x)	ROUND_DOWN(x, getpagesize())
#define PAGE_UP(x)	ROUND_UP(x, getpagesize())

static int match_program_header_vm_area(Elf64_Phdr *pphdr,
					struct obj_vm_area *ovma,
					unsigned long load_offset)
{
	unsigned long start = pphdr->p_vaddr + load_offset;
	unsigned long end = start + pphdr->p_filesz;

	/* Whenever segment size in memory p_memsz > segment size in file
	 * (p_memsz > p_filesz) the rest of the segemnt memory is mapped by
	 * the glibc from the anonymous fd = -1, so we only match inmem.end
	 * against start + pphdr->p_filesz
	 */
	return (PAGE_DOWN(start) == ovma->inmem.start) &&
	       (PAGE_UP(end) == ovma->inmem.end) &&
	       ((pphdr->p_flags & (PF_R|PF_W|PF_X))
		== prot2flags(ovma->inmem.prot));
}

int kpatch_elf_parse_program_header(struct object_file *o)
{
	Elf64_Phdr *maphdrs = NULL;

	unsigned long load_offset;
	unsigned long lowest_vaddr = ULONG_MAX;

	struct obj_vm_area *ovma;
	int rv = -1, errno_save;
	size_t i, j, nmaps;
	Elf64_Phdr *pphdr;

	kpdebug("Parsing program headers for '%s'...\n", o->name);

	rv = elf_object_peek_phdr(o);
	if (rv < 0)
		return rv;

	/* First, find the load_offset that is the difference between lowest
	 * vma.inmem.start and lowest phdr.v_addr
	 */

	/* Look for the lowest LOAD */
	for (i = 0, nmaps = 0; i < o->ehdr.e_phnum; i++) {
		pphdr = &o->phdr[i];
		switch (pphdr->p_type) {
		case PT_LOAD:
			lowest_vaddr = lowest_vaddr > pphdr->p_vaddr
				       ? pphdr->p_vaddr : lowest_vaddr;
			/* FALLTHROUGH */
		case PT_GNU_RELRO:
			nmaps++;
			break;
		}
	}
	if (lowest_vaddr == ULONG_MAX) {
		kperr("%s: unable to find lowest load address\n",
		      o->name);
		goto out;
	}

	lowest_vaddr = PAGE_DOWN(lowest_vaddr);

	load_offset = o->vma_start - lowest_vaddr;
	o->load_offset = load_offset;

	kpinfo("%s: load offset: %lx = %lx - %lx\n",
	       o->name, load_offset, o->vma_start, lowest_vaddr);

	maphdrs = malloc(sizeof(*maphdrs) * nmaps);
	if (!maphdrs)
		goto out;

	for (i = 0, j = 0; i < o->ehdr.e_phnum; i++) {
		pphdr = &o->phdr[i];
		switch (pphdr->p_type) {
		case PT_LOAD:
		case PT_GNU_RELRO:
			maphdrs[j++] = *pphdr;
			break;
		}
	}

	qsort(maphdrs, nmaps, sizeof(*maphdrs), phdr_compare);

	/* Account for GNU_RELRO */
	for (i = 0; i < nmaps; i++) {

		if (maphdrs[i].p_type != PT_GNU_RELRO)
			continue;

		if (i == 0) {
			kperr("%s: wrong ELF: PT_GNU_RELRO is first phdr\n",
			      o->name);
			goto out;
		}

		maphdrs[i].p_flags &= ~PF_W;

		if (maphdrs[i - 1].p_vaddr == maphdrs[i].p_vaddr) {
			maphdrs[i - 1].p_vaddr = maphdrs[i].p_vaddr +
				maphdrs[i].p_memsz;
			maphdrs[i - 1].p_memsz -= maphdrs[i].p_memsz;

			maphdrs[i - 1].p_offset += maphdrs[i].p_filesz;
			maphdrs[i - 1].p_filesz -= maphdrs[i].p_filesz;
		} else {
			kperr("TODO: splitting VM by GNU_RELRO\n");
			goto out;
		}
	}

	for (i = 0; i < nmaps; i++) {
		kpdebug("maphdrs[%ld] = { .p_vaddr = %lx, .p_memsz = %lx, .p_offset = %lx, .p_filesz = %lx }\n",
			i,
			maphdrs[i].p_vaddr, maphdrs[i].p_memsz,
			maphdrs[i].p_offset, maphdrs[i].p_filesz);
	}

	list_for_each_entry(ovma, &o->vma, list) {
		if (ovma->inmem.prot == PROT_NONE) {
			/* Ignore holes */
			continue;
		}

		for (i = 0; i < nmaps; i++) {
			pphdr = &maphdrs[i];
			if (match_program_header_vm_area(pphdr,
							 ovma, load_offset))
				break;
		}

		if (i == nmaps) {
			kperr("cant match ovma->inmem = { .start = %lx, .end = %lx, .prot = %x }\n",
			      ovma->inmem.start, ovma->inmem.end, ovma->inmem.prot);
			rv = -1;
			goto out;
		}

		ovma->ondisk.start = pphdr->p_offset;
		ovma->ondisk.end = pphdr->p_offset + pphdr->p_filesz;
		ovma->ondisk.prot = ovma->inmem.prot;

		ovma->inelf.start = pphdr->p_vaddr;
		ovma->inelf.end = pphdr->p_vaddr + pphdr->p_memsz;
		ovma->inelf.prot = 0;

		ovma->inmem.start = load_offset + ovma->inelf.start;
		ovma->inmem.end = load_offset + ovma->inelf.end;

		kpdebug(" phdr[%ld]{ .start = %lx, .end = %lx, prot = %x }",
			i,
			ovma->ondisk.start, ovma->ondisk.end,
			ovma->ondisk.prot);
		kpdebug(" <-> ");
		kpdebug("{ .start = %lx, .end = %lx, prot = %x }\n",
			ovma->inmem.start, ovma->inmem.end, ovma->inmem.prot);
	}

	rv = 0;
out:
	errno_save = errno;

	free(maphdrs);

	errno = errno_save;
	return rv;
}

static char *secname(GElf_Ehdr *ehdr, GElf_Shdr *s)
{
	GElf_Shdr *shdr = (void *)ehdr + ehdr->e_shoff;
	char *str = (void *)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

	return str + s->sh_name;
}

static int kpatch_is_our_section(GElf_Shdr *s)
{
	// FIXME: is this enough???
	return s->sh_type != SHT_NOBITS;
}

unsigned long vaddr2addr(struct object_file *o, unsigned long vaddr)
{
	struct obj_vm_area *ovma;

	if (vaddr == 0)
		return 0;
	list_for_each_entry(ovma, &o->vma, list) {
		if (vaddr >= ovma->inelf.start && vaddr < ovma->inelf.end)
			return vaddr - ovma->inelf.start + ovma->inmem.start;
	}

	return 0;
}

struct kpatch_jmp_table *kpatch_new_jmp_table(int entries)
{
	struct kpatch_jmp_table *jtbl;
	size_t sz = sizeof(*jtbl) + entries * sizeof(struct kpatch_jmp_table_entry);

	jtbl = malloc(sz);
	memset(jtbl, 0, sz);
	jtbl->size = sz;
	jtbl->max_entry = entries;
	return jtbl;
}

static inline int
is_undef_symbol(const Elf64_Sym *sym)
{
	return sym->st_shndx == SHN_UNDEF || sym->st_shndx >= SHN_LORESERVE;
}

int kpatch_count_undefined(struct object_file *o)
{
	GElf_Ehdr *ehdr;
	GElf_Shdr *shdr;
	GElf_Sym *sym;
	int i, symidx = 0, count = 0;
	char *strsym;

	ehdr = (void *)o->kpfile.patch + o->kpfile.patch->kpatch_offset;
	shdr = (void *)ehdr + ehdr->e_shoff;

	for (i = 1; i < ehdr->e_shnum; i++) {
		GElf_Shdr *s = shdr + i;
		if (s->sh_type == SHT_SYMTAB) {
			symidx = i;
			break;
		}
	}

	kpdebug("Counting undefined symbols:\n");
	sym = (void *)ehdr + shdr[symidx].sh_offset;
	strsym = (void *)ehdr + shdr[shdr[symidx].sh_link].sh_offset;
	for (i = 1; i < shdr[symidx].sh_size / sizeof(GElf_Sym); i++) {
		GElf_Sym *s = sym + i;

		if (s->st_shndx == SHN_UNDEF &&
		    GELF_ST_BIND(s->st_info) == STB_GLOBAL) {
			count++;
			kpdebug("Undefined symbol '%s'\n",
				strsym + s->st_name);
		}
	}

	return count;
}

static int
sym_name_cmp(const void *a_, const void *b_, void *s_)
{
	const Elf64_Sym *a = (const Elf64_Sym *)a_;
	const Elf64_Sym *b = (const Elf64_Sym *)b_;
	const char *s = (char *)s_;
	int rv, t;

	/*
	 * Sort references to undefined symbols to be at the end
	 * so we can later cut them off.
	 */
	t = is_undef_symbol(a);

	rv = t - is_undef_symbol(b);
	if (rv)
		return rv;

	/* Make sure we are correctly sortable if both are undefined */
	if (!rv && t)
		return a->st_name - b->st_name;

	return strcmp(s + a->st_name, s + b->st_name);
}

static int
elf_object_load_dynsym(struct object_file *o)
{
	int rv;
	size_t i;
	Elf64_Dyn *dynamics = NULL;
	char *buffer = NULL;
	Elf64_Phdr *phdr;
	unsigned long symtab_addr, strtab_addr;
	unsigned long symtab_sz, strtab_sz;

	if (o->dynsyms != NULL)
		return 0;

	rv = elf_object_peek_phdr(o);
	if (rv < 0)
		return rv;

	for (i = 0; i < o->ehdr.e_phnum; i++) {
		if (o->phdr[i].p_type == PT_DYNAMIC)
			break;
	}

	if (i == o->ehdr.e_phnum)
		return -1;

	phdr = &o->phdr[i];

	dynamics = malloc(phdr->p_memsz);
	if (dynamics == NULL)
		return -1;

	rv = kpatch_process_mem_read(o->proc,
				     o->load_offset + phdr->p_vaddr,
				     dynamics,
				     phdr->p_memsz);
	if (rv < 0)
		goto out_free;

	for (i = 0; i < phdr->p_memsz / sizeof(Elf64_Dyn); i++) {
		Elf64_Dyn *curdyn = dynamics + i;
		switch (curdyn->d_tag) {
		case DT_SYMTAB:
			symtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRTAB:
			strtab_addr = curdyn->d_un.d_ptr;
			break;
		case DT_STRSZ:
			strtab_sz = curdyn->d_un.d_val;
			break;
		case DT_SYMENT:
			if (sizeof(Elf64_Sym) != curdyn->d_un.d_val) {
				kperr("Dynsym entry size is %ld expected %ld\n",
				      curdyn->d_un.d_val, sizeof(Elf64_Sym));
				goto out_free;
			}
			break;
		}
	}

	symtab_sz = (strtab_addr - symtab_addr);

	buffer = malloc(strtab_sz + symtab_sz);
	if (buffer == NULL)
		goto out_free;

	rv = kpatch_process_mem_read(o->proc,
				     symtab_addr,
				     buffer,
				     strtab_sz + symtab_sz);
	if (rv < 0)
		goto out_free;

	o->dynsyms = (Elf64_Sym*) buffer;
	o->ndynsyms = symtab_sz / sizeof(Elf64_Sym);
	o->dynsymnames = malloc(sizeof(char *) * o->ndynsyms);

	qsort_r((void *)o->dynsyms, o->ndynsyms, sizeof(Elf64_Sym),
		sym_name_cmp, buffer + symtab_sz);

	for (i = 0; i < o->ndynsyms; i++) {
		if (is_undef_symbol(&o->dynsyms[i]))
			break;
		o->dynsymnames[i] = buffer + symtab_sz + o->dynsyms[i].st_name;
	}
	o->ndynsyms = i;


out_free:
	if (rv < 0)
		free(buffer);
	free(dynamics);

	return rv;
}

/* TODO reuse kpatch_cc */
static int
bsearch_strcmp(const void *a_, const void *b_)
{
	const char *a = (const char *)a_;
	const char *b = *(const char **)b_;

	return strcmp(a, b);
}

int kpatch_resolve_undefined_single_dynamic(struct object_file *o,
					    const char *sname,
					    unsigned long *addr)
{
	int rv;
	void *found;
	size_t n;

	rv = elf_object_load_dynsym(o);
	if (rv < 0)
		return rv;

	found = bsearch(sname, o->dynsymnames,
			o->ndynsyms, sizeof(char *),
			bsearch_strcmp);
	if (found == NULL)
		return -1;

	n = (unsigned long)(found - (void *)o->dynsymnames) / sizeof(char *);

	*addr = o->dynsyms[n].st_value;
	return GELF_ST_TYPE(o->dynsyms[n].st_info);
}

static unsigned long
kpatch_resolve_undefined(struct object_file *obj,
			 char *sname)
{
	struct object_file *o;
	unsigned long addr = 0;
	int type;
	char *p;

	/* TODO: versioned symbols which are ignored by now */
	p = strchr(sname, '@');
	if (p)
		*p = 0;

	/*
	 * TODO: we should do this in the same order as linker does.
	 * Otherwise we might end up picking up the wrong symbol!!!
	 */
	list_for_each_entry(o, &obj->proc->objs, list) {
		if (!o->is_shared_lib)
			continue;

		type = kpatch_resolve_undefined_single_dynamic(o, sname, &addr);
		if (type == -1)
			continue;

		addr = vaddr2addr(o, addr);

		if (type == STT_GNU_IFUNC)
			if (kpatch_ptrace_resolve_ifunc(proc2pctx(obj->proc), &addr) < 0)
				kpfatalerror("kpatch_ptrace_resolve_ifunc failed\n");

		break;
	}

	return addr;
}

#define JMP_TABLE_JUMP  0x90900000000225ff /* jmp [rip+2]; nop; nop */
static unsigned long kpatch_add_jmp_entry(struct object_file *o, unsigned long addr)
{
	struct kpatch_jmp_table_entry entry = {JMP_TABLE_JUMP, addr};
	int e;

	if (o->jmp_table == NULL) {
		kpfatalerror("JMP TABLE not found\n");
		return 0;
	}

	if (o->jmp_table->cur_entry >= o->jmp_table->max_entry)
		return 0;
	e = o->jmp_table->cur_entry++;
	o->jmp_table->entries[e] = entry;
	return (unsigned long)(o->kpta + o->kpfile.patch->jmp_offset + \
			((void *)&o->jmp_table->entries[e] - (void *)o->jmp_table));
}

static inline int
symbol_resolve(struct object_file *o,
	       GElf_Shdr *shdr,
	       GElf_Sym *s,
	       char *symname)
{
	unsigned long uaddr;

	switch(GELF_ST_TYPE(s->st_info)) {
	case STT_SECTION:
		s->st_value = shdr[s->st_shndx].sh_addr;
		break;

	case STT_FUNC:
	case STT_OBJECT:

		/* TODO(pboldin) this breaks rule for overriding
		 * symbols via dynamic libraries. Fix it. */
		if (s->st_shndx == SHN_UNDEF &&
		    GELF_ST_BIND(s->st_info) == STB_GLOBAL) {
			/* This is a reference to a symbol from
			 * the dynamic library. Resolve it. */

			uaddr = kpatch_resolve_undefined(o, symname);

			if (!uaddr) {
				kperr("Failed to resolve undefined symbol '%s'\n",
				      symname);
				return -1;
			}
			/* OK, we overuse st_size to store original offset */
			s->st_size = uaddr;
			s->st_value = kpatch_add_jmp_entry(o, uaddr);

			kpdebug("symbol '%s' = 0x%lx\n",
				symname, uaddr);
			kpdebug("jmptable '%s' = 0x%lx\n",
				symname, s->st_value);
		} else {
			/*
			 * We retain all non-local (except for .LC*)
			 * symbols to help us debugging.
			 */
			if (GELF_ST_BIND(s->st_info) == STB_GLOBAL)
				kpwarn("symbol '%s' is defined and global, we don't check for overrition\n",
				       symname);

			s->st_value += shdr[s->st_shndx].sh_addr;
			kpdebug("symbol '%s' = 0x%lx\n",
				symname, s->st_value);
		}

		break;

	case STT_TLS:
		break;

	case STT_NOTYPE:			// for Systemtap symbol _.stapsdt.base.kpatch
		break;

	default:
		kperr("Unsupported symbol type: %d\n", GELF_ST_TYPE(s->st_info));
		return -1;
	}

	return 0;
}

int kpatch_resolve(struct object_file *o)
{
	GElf_Ehdr *ehdr;
	GElf_Shdr *shdr;
	GElf_Sym *sym;
	int i, symidx, rv;
	char *strsym;

	ehdr = (void *)o->kpfile.patch + o->kpfile.patch->kpatch_offset;
	shdr = (void *)ehdr + ehdr->e_shoff;

	kpdebug("Resolving sections' addresses for '%s'\n", o->name);
	for (i = 1; i < ehdr->e_shnum; i++) {
		GElf_Shdr *s = shdr + i;
		if (s->sh_type == SHT_SYMTAB)
			symidx = i;

		if (kpatch_is_our_section(s)) {
			/*
			 * For our own sections, we just point sh_addr to
			 * proper offet in *target process* region of memory
			 */
			s->sh_addr = (unsigned long)o->kpta +
				o->kpfile.patch->kpatch_offset + s->sh_offset;
		} else {
			/*
			 * We copy the `sh_addr`esses from the original binary
			 * into the patch during the preparation. Just use
			 * this.
			 */
			if (s->sh_addr)
				s->sh_addr += (unsigned long)o->load_offset;
		}
		kpdebug("section '%s' = 0x%lx\n", secname(ehdr, s), s->sh_addr);
	}

	kpdebug("Resolving symbols for '%s'\n", o->name);
	sym = (void *)ehdr + shdr[symidx].sh_offset;
	strsym = (void *)ehdr + shdr[shdr[symidx].sh_link].sh_offset;
	for (i = 1; i < shdr[symidx].sh_size / sizeof(GElf_Sym); i++) {
		GElf_Sym *s = sym + i;
		char *symname = strsym + s->st_name;

		rv = symbol_resolve(o, shdr, s, symname);
		if (rv < 0)
			return rv;
	}

	return 0;
}

static int kpatch_apply_relocate_add(struct object_file *o, GElf_Shdr *relsec)
{
	struct kpatch_file *kp = o->kpfile.patch;
	GElf_Ehdr *ehdr = (void *)kp + kp->kpatch_offset;
	GElf_Shdr *shdr = (void *)ehdr + ehdr->e_shoff, *symhdr;
	GElf_Rela *relocs = (void *)ehdr + relsec->sh_offset;
	GElf_Shdr *tshdr = shdr + relsec->sh_info;
	void *t = (void *)ehdr + shdr[relsec->sh_info].sh_offset;
	void *tshdr2 = (void *)shdr[relsec->sh_info].sh_addr;
	int i, is_kpatch_info;
	const char *scnname;

	for (i = 1; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB)
			symhdr = &shdr[i];
	}

	scnname = secname(ehdr, shdr + relsec->sh_info);
	kpdebug("applying relocations to '%s'\n", scnname);
	is_kpatch_info = strcmp(scnname, ".kpatch.info") == 0;

	for (i = 0; i < relsec->sh_size / sizeof(*relocs); i++) {
		GElf_Rela *r = relocs + i;
		GElf_Sym *s;
		unsigned long val;
		void *loc, *loc2;

		if (r->r_offset < 0 || r->r_offset >= tshdr->sh_size)
			kpfatalerror("Relocation offset for section '%s'"
				     " is at 0x%lx beyond the section size 0x%lx\n",
				     scnname, r->r_offset, tshdr->sh_size);

		/* Location in our address space */
		loc = t + r->r_offset;
		/* Location in target process address space (for relative addressing) */
		loc2 = tshdr2 + r->r_offset;
		s = (GElf_Sym *)((void *)ehdr + symhdr->sh_offset) + GELF_R_SYM(r->r_info);
		val = s->st_value + r->r_addend;

		if (is_kpatch_info && is_undef_symbol(s)) {
			val = s->st_size;
		}

		switch (GELF_R_TYPE(r->r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			*(unsigned long *)loc = val;
			break;
		case R_X86_64_32:
			*(unsigned int *)loc = val;
			break;
		case R_X86_64_32S:
			*(signed int *)loc = val;
			break;
		case R_X86_64_GOTTPOFF:
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
			if (is_undef_symbol(s)) {
				/* This is an undefined symbol,
				 * use jmp table as the GOT */
				val += sizeof(unsigned long);
			} else if (GELF_ST_TYPE(s->st_info) == STT_TLS) {
				/* This is GOTTPOFF that already points
				 * to an appropriate GOT entry in the
				 * patient's memory.
				 */
				val = r->r_addend + o->load_offset - 4;
			}
			/* FALLTHROUGH */
		case R_X86_64_PC32:
			val -= (unsigned long)loc2;
			*(unsigned int *)loc = val;
			break;
		case R_X86_64_TPOFF64:
		case R_X86_64_TPOFF32:
			kperr("TPOFF32/TPOFF64 should not be present\n");
			break;
		default:
			kperr("unknown relocation type: %lx\n", r->r_info);
			return -1;
		}
	}

	return 0;
}

int kpatch_relocate(struct object_file *o)
{
	GElf_Ehdr *ehdr;
	GElf_Shdr *shdr;
	int i, ret = 0;

	ehdr = (void *)o->kpfile.patch + o->kpfile.patch->kpatch_offset;
	shdr = (void *)ehdr + ehdr->e_shoff;

	kpdebug("Applying relocations for '%s'...\n", o->name);
	for (i = 1; i < ehdr->e_shnum; i++) {
		GElf_Shdr *s = shdr + i;

		if (s->sh_type == SHT_RELA)
			ret = kpatch_apply_relocate_add(o, s);
		else if (shdr->sh_type == SHT_REL) {
			kperr("TODO: handle SHT_REL\n");
			return -1;
		}
		if (ret)
			return -1;
	}

	return 0;
}

int kpatch_elf_load_kpatch_info(struct object_file *o)
{
	GElf_Ehdr *ehdr;
	GElf_Shdr *shdr;
	int i;

	if (o->info != NULL)
		return 0;

	ehdr = (void *)o->kpfile.patch + o->kpfile.patch->kpatch_offset;
	shdr = (void *)ehdr + ehdr->e_shoff;

	kpdebug("Loading patch info '%s'...", o->name);
	for (i = 1; i < ehdr->e_shnum; i++) {
		GElf_Shdr *s = shdr + i;

		if (!strcmp(secname(ehdr, s), ".kpatch.info")) {
			o->info = (struct kpatch_info *)((void *)ehdr +
							 s->sh_offset);
			o->ninfo = s->sh_size / sizeof(struct kpatch_info);
			kpdebug("successfully, %ld entries\n", o->ninfo);
			return 0;
		}
	}

	kpdebug("failed\n");
	return -1;
}
