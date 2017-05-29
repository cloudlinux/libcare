
#include <stdlib.h>
#include <string.h>

#include <gelf.h>

#include "kpatch_common.h"
#include "kpatch_elf_objinfo.h"
#include "kpatch_log.h"

const char *kpatch_objinfo_strptr(kpatch_objinfo *oi, int type, size_t nameidx)
{
	size_t strsecidx;

	switch (type) {
	case SECTION_NAME:
		strsecidx = oi->shdrstridx;
		break;
	case SYMBOL_NAME:
		strsecidx = oi->symstridx;
		break;
	case DYNAMIC_NAME:
		strsecidx = oi->dynsymstridx;
		break;
	default:
		return NULL;
	}

	return elf_strptr(oi->elf, strsecidx, nameidx);
}

int kpatch_objinfo_load(kpatch_objinfo *oi)
{
	size_t i, n;

	if (oi->loaded)
		return 0;

	if (_elf_getshdrstrndx(oi->elf, &oi->shdrstridx))
		return -1;
	if (!gelf_getehdr(oi->elf, &oi->ehdr))
		return -1;
	if (elf_getshnum(oi->elf, &oi->shnum) < 0)
		return -1;

	/* symtab is usually placed at the end */
	for (n = 0, i = 1; i < oi->shnum; i++) {
		const char *secname;
		GElf_Shdr shdr;
		Elf_Scn *scn = NULL;

		scn = kpatch_objinfo_getshdr(oi, i, &shdr);
		if (scn == NULL)
			return -1;

		secname = kpatch_objinfo_strptr(oi, SECTION_NAME,
						shdr.sh_name);
		if (!strncmp(secname, ".kpatch", 7)) {
			if (n == ARRAY_SIZE(oi->_kpatch_sections))
				return -1;
			oi->_kpatch_sections[n++] = i;
		}

		switch (shdr.sh_type) {
		case SHT_SYMTAB:
			oi->symtab = elf_getdata(scn, NULL);
			oi->nsym = shdr.sh_size / shdr.sh_entsize;
			oi->symstridx = shdr.sh_link;
			oi->symidx = i;
			break;
		case SHT_DYNSYM:
			oi->dynsymtab = elf_getdata(scn, NULL);
			oi->ndynsym = shdr.sh_size / shdr.sh_entsize;
			oi->dynsymstridx = shdr.sh_link;
			oi->dynsymidx = i;
			break;
		}
	}
	oi->loaded = 1;

	return 0;
}

extern int elf_getshdrstrndx(Elf *elf, size_t *ndx) __attribute__ ((weak));

int _elf_getshdrstrndx(Elf  *elf, size_t *ndx)
{
	if (elf_getshdrstrndx)
		return elf_getshdrstrndx(elf, ndx);
	else
		return elf_getshstrndx(elf, ndx);
}

Elf_Scn *kpatch_objinfo_getshdr(kpatch_objinfo *oi, int secnum, GElf_Shdr *shdr)
{
	Elf_Scn *scn;

	scn = elf_getscn(oi->elf, secnum);
	if (scn == NULL) {
		kplogerror("elf_getscn(%d)", secnum);
		return NULL;
	}

	if (shdr != NULL && !gelf_getshdr(scn, shdr)) {
		kplogerror("gelf_getshdr");
		return NULL;
	}

	return scn;
}

Elf_Scn *
kpatch_objinfo_find_scn_by_name(kpatch_objinfo *oi,
				const char *name,
				GElf_Shdr *pshdr)
{
	size_t i;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	const char *tmp;

	for (i = 1; i < oi->shnum; i++) {
		scn = kpatch_objinfo_getshdr(oi, i, &shdr);
		if (scn == NULL)
			return NULL;

		tmp = kpatch_objinfo_strptr(oi, SECTION_NAME, shdr.sh_name);
		if (tmp != NULL && !strcmp(name, tmp)) {
			if (pshdr)
				*pshdr = shdr;
			return scn;
		}
	}

	return NULL;
}

int kpatch_objinfo_is_our_section(kpatch_objinfo *oi, int secnum)
{
	int i = 0, n = ARRAY_SIZE(oi->_kpatch_sections);
	unsigned short *s  = oi->_kpatch_sections;

	for (; s[i] && i < n; i++) {
		if (s[i] == secnum)
			return 1;
	}
	return 0;
}

int
kpatch_objinfo_load_tls_reladyn(kpatch_objinfo *oi)
{
	Elf64_Rela *rela;
	Elf_Scn *scn_rela_dyn;
	Elf_Data *data_rela_dyn;
	size_t nrela, i, nlast;

	if (oi->tlsreladyn != NULL)
		return 0;

	scn_rela_dyn = kpatch_objinfo_find_scn_by_name(oi, ".rela.dyn", NULL);
	if (scn_rela_dyn == NULL) {
		kpfatalerror("unable to find .rela.dyn");
		return -1;
	}

	data_rela_dyn = elf_getdata(scn_rela_dyn, NULL);
	if (data_rela_dyn == NULL || data_rela_dyn->d_buf == NULL) {
		kpfatalerror("no data for .rela.dyn");
		return -1;
	}

	rela = data_rela_dyn->d_buf;
	nrela = data_rela_dyn->d_size / sizeof(*rela);

	/* Skip RELATIVE and others at the start */
	for (; nrela != 0; rela++, nrela--) {
		if (kpatch_is_tls_rela(rela))
			break;
	}

	oi->tlsreladyn = rela;

	/* Chop at last TLS reloc */
	for (i = 0; i < nrela; rela++, i++) {
		if (kpatch_is_tls_rela(rela))
			nlast = i;
	}

	oi->ntlsreladyn = nlast + 1;

	return 0;
}
