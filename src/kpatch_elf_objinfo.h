
#ifndef __KPATCH_ELF_OBJINFO_INCLUDED__
#define __KPATCH_ELF_OBJINFO_INCLUDED__

typedef struct {
	Elf *elf;

	GElf_Ehdr ehdr;

	Elf_Data *symtab;
	size_t nsym;
	size_t symidx;


	Elf_Data *dynsymtab;
	size_t ndynsym;
	size_t dynsymidx;
	size_t dynsymstridx;

	size_t shdrstridx;
	size_t symstridx;

	size_t shnum;

	unsigned short _kpatch_sections[16];

	int loaded;

	Elf64_Rela *tlsreladyn;
	size_t ntlsreladyn;

} kpatch_objinfo;

static inline
void init_kpatch_object_info(kpatch_objinfo *oi, Elf *elf)
{
	oi->elf = elf;
	oi->symtab = NULL;
	oi->dynsymtab = NULL;
	oi->loaded = 0;
	oi->tlsreladyn = NULL;
	oi->ntlsreladyn = 0;
}

#define OBJINFO_INIT(elf_) { .elf = elf_, .symtab = NULL, .loaded = 0 }

int kpatch_objinfo_load(kpatch_objinfo *oi);

Elf_Scn *kpatch_objinfo_getshdr(kpatch_objinfo *oi, int secnum, GElf_Shdr *shdr);

int kpatch_objinfo_is_our_section(kpatch_objinfo *oi, int secnum);

/* TODO(pboldin): SYMBOL_NAME -> SYMBOL_NAMEIDX and make SYMBOL_NAME resolve
 * name from the symbol number, not the .strtab offset */
#define SECTION_NAME	0x0
#define SYMBOL_NAME	0x1
#define DYNAMIC_NAME	0x2
const char *kpatch_objinfo_strptr(kpatch_objinfo *oi, int type,
				  size_t nameidx);

int _elf_getshdrstrndx(Elf  *elf, size_t *ndx);

Elf_Scn *kpatch_objinfo_find_scn_by_name(kpatch_objinfo *oi,
					 const char *name, GElf_Shdr *shdr);

static inline int
kpatch_is_tls_rela(Elf64_Rela *rela)
{
	return (ELF64_R_TYPE(rela->r_info) == R_X86_64_TPOFF64 ||
		ELF64_R_TYPE(rela->r_info) == R_X86_64_DTPOFF64 ||
		ELF64_R_TYPE(rela->r_info) == R_X86_64_DTPMOD64);
}

int
kpatch_objinfo_load_tls_reladyn(kpatch_objinfo *oi);

#endif /* __KPATCH_ELF_OBJINFO_INCLUDED__ */
