#include <stdlib.h>

#include "kpatch_log.h"
#include "kpatch_parse.h"
#include "kpatch_flags.h"

char *cline(struct kp_file *f, int l)
{
	if (l < 0 || l >= f->nr_lines)
		return NULL;

	return f->lines[l];
}

int clinenum(struct kp_file *f, int l)
{
	if (l < 0 || l >= f->nr_lines)
		return 0;

	return f->lines_num[l];
}

void __get_token(char **str, kpstr_t *x, const char *delim)
{
	char *s = *str, *e;

	kpstrset(x, "", 0);
	if (!s)
		return;

	s = skip_blanks(s);
	if (!*s || *s == '\n') {
		*str = NULL;
		return;
	}

	if (*s == '"') {
		for (e = s + 1; *e && *e != '"'; e++)
			if (e[0] == '\\' && e[1]) e++;	/* skip all escaping sequences, including \" */
		if (*e == '"') e++;
	} else
		for (e = s; *e && !strchr(delim, *e); e++) ;

	if (e == s)
		e++;

	kpstrset(x, s, e - s);

	e = skip_blanks(e);
	if (!*e || *e == '\n')
		e = NULL;
	*str = e;
}

void get_token(char **str, kpstr_t *x)
{
	const char *delim = " \t,;:-+*()[]$\n";
	__get_token(str, x, delim);
}

/* ------------------------------  as directives parsing ---------------------------------- */

static struct {
	int type;
	char *s;
} asm_directives[] = {
	{ DIRECTIVE_ALIGN, ".align"},
	{ DIRECTIVE_ALIGN, ".p2align"},

	{ DIRECTIVE_TYPE, ".type"},
	{ DIRECTIVE_COMM, ".comm"},
	{ DIRECTIVE_SIZE, ".size"},
	{ DIRECTIVE_WEAK, ".weak"},

	{ DIRECTIVE_TEXT, ".text"},
	{ DIRECTIVE_DATA, ".data"},
	{ DIRECTIVE_BSS, ".bss"},
	{ DIRECTIVE_SECTION, ".section"},
	{ DIRECTIVE_PUSHSECTION, ".pushsection"},
	{ DIRECTIVE_POPSECTION, ".popsection"},
	{ DIRECTIVE_PREVIOUS, ".previous"},
	{ DIRECTIVE_SUBSECTION, ".subsection"},

	{ DIRECTIVE_GLOBL, ".globl"},
	{ DIRECTIVE_LOCAL, ".local"},
	{ DIRECTIVE_HIDDEN, ".hidden"},
	{ DIRECTIVE_PROTECTED, ".protected"},
	{ DIRECTIVE_INTERNAL, ".internal"},
	{ DIRECTIVE_SET, ".set"},
	{ DIRECTIVE_KPFLAGS, ".kpgensrc_flags" },
};

/* parse arguments of .type command */
static void get_type_args(char *s, kpstr_t *nm, kpstr_t *attr)
{
	kpstr_t t, t2;

	get_token(&s, &t);	/* skip command */
	if (kpstrcmpz(&t, ".type"))
		return;

	get_token(&s, nm);	/* get name */
	get_token(&s, &t2);	/* skip ',' */
	get_token(&s, attr);	/* get attr */

	if (kpstrcmpz(&t2, ","))
		kpfatal("can't parse .type command");
}

static int find_ctype(kpstr_t *t)
{
	int i;
	for (i = 0; i < (int)(sizeof(asm_directives)/sizeof(asm_directives[0])); i++) {
		if (!kpstrcmpz(t, asm_directives[i].s))
			return asm_directives[i].type;
	}
	return -1;
}

int parse_ctype(char *origs, bool with_checks)
{
	char *s = origs;
	int type;
	kpstr_t t;

	s = skip_blanks(s);
	if (s[0] == '#')
		return DIRECTIVE_COMMENT;		/* Single-line comment */

	get_token(&s, &t);
	type = find_ctype(&t);

	if (type >= 0)
		return type;

	/*
	 * Asm labels starting from digits are local labels, they can be even created multiple times in the same function.
	 * So there is no reason to handle them and bother with renaming at all. It would create conflicts at our brains
	 * and require special tracking and matching... Brrrr.... */
	if (s && *s == ':')
		return !isdigit(t.s[0]) ? DIRECTIVE_LABEL : DIRECTIVE_LOCAL_LABEL;

	return DIRECTIVE_OTHER;
}

int ctype(struct kp_file *f, int l)
{
	if (l >= f->nr_lines)
		kpfatal("ctype access beyond EOF");

	return f->ctype[l];
}

int is_sect_cmd(struct kp_file *f, int l)
{
	int t = ctype(f, l);

	return t == DIRECTIVE_TEXT || t == DIRECTIVE_DATA || t == DIRECTIVE_BSS || t == DIRECTIVE_SECTION ||
		t == DIRECTIVE_PUSHSECTION || t == DIRECTIVE_POPSECTION ||
		t == DIRECTIVE_PREVIOUS || t == DIRECTIVE_SUBSECTION;
}

/* break manually crafted multiple statements separated by ; to separate lines */
void init_multilines(struct kp_file *f)
{
	int i, nr, sz = 64, slen, first_token;
	char **lines = NULL, *s, *se;
	int *lines_num = NULL;
	kpstr_t t;

	nr = 0;
	for (i = 0; i < f->nr_lines; i++) {
		if (nr + 1000 >= sz || !lines) {
			sz *= 2;
			lines = kp_realloc(lines, (sz/2) * sizeof(char *), sz * sizeof(char *));
			lines_num = kp_realloc(lines_num, (sz/2) * sizeof(int), sz * sizeof(int));
		}

		s = f->lines[i];
		if (strpbrk(s, ";:") != NULL) {
			while (s && *s) {
				se = s;
				slen = strlen(s);
				first_token = 1;
				while (se) {
					get_token(&se, &t);
					if (t.l == 1 && t.s[0] == '#')
						goto done;
					if (t.l == 1 && t.s[0] == ';') {
						slen = t.s - s;
						break;
					}
					/* first token with ':' after is
					 * the label, separate it unless
					 * it is done already (next non-blank
					 * is '\0')
					 */
					if (first_token && se &&
					    se[0] == ':' &&
					    se[1] != '\0') {
						slen = se - s + 1;
						se++;
						break;
					}
					first_token = 0;
				}
				lines[nr] = strndup(s, slen);
				s = se;
				lines_num[nr] = i;
				nr++;
				if (nr >= sz)
					kpfatal("oops, not prepared to handle >1000 asm statements in single line");
			}
			free(f->lines[i]);
		} else {
done:
			lines[nr] = s;
			lines_num[nr] = i;
			nr++;
		}
	}
	free(f->lines);
	f->lines = lines;
	f->lines_num = lines_num;
	f->nr_lines = nr;
}

void init_ctypes(struct kp_file *f)
{
	int i;

	f->ctype = malloc(f->nr_lines * sizeof(f->ctype[0]));
	for (i = 0; i < f->nr_lines; i++) {
		f->ctype[i] = parse_ctype(cline(f, i), true);
	}
}

/* ------------------------------------------- code blocks parsing --------------------------------------------- */

static inline int cblock_name_cmp(struct rb_node *node, unsigned long key)
{
	struct cblock *blk = rb_entry(node, struct cblock, rbnm);
	kpstr_t *nm = (kpstr_t *)key;
	int res;

	res = kpstrcmp(&blk->name, nm);
	return res;
}

static inline int cblock_human_name_cmp(struct rb_node *node, unsigned long key)
{
	struct cblock *blk = rb_entry(node, struct cblock, rb_hnm);
	kpstr_t *nm = (kpstr_t *)key;
	int res;

	res = kpstrcmp(&blk->human_name, nm);
	return res;
}

static inline int cblock_start_cmp(struct rb_node *node, unsigned long key)
{
	struct cblock *blk = rb_entry(node, struct cblock, rbs);

	return blk->start == key ? 0 : (blk->start > key ? -1 : 1);
}

static void cblock_make_human_name(kpstr_t *hnm, kpstr_t *nm)
{
	kpstr_t subnm;
	char *s = nm->s;

	*hnm = *nm;

	/*
	 * Latests gcc versions (RHEL7) generate lots of function clones optimized for some specific cases (e.g. for constanct propogation).
	 * These functions are typically called as func.part.NUM or func.isra.NUM.constprop.NUM, so we cut all the gcc specific suffixes
	 * to get real human name of the function. This is used later for matching functions by name.
	 *
	 * Same applies to static variables. They have a suffix like "var.NUM", so we need to make sure we compare same kind of variables later.
	 */
	__get_token(&s, &subnm, "\t\n.,");
	if (s && isdigit(nm->s[nm->l - 1])) {
		*hnm = subnm;	/* return whatever is before "." */
		return;
	}

	/* __mod_XXX variables are nasty as Linux kernel adds __LINE__ suffix to it in __MODULE_INFO() macro. For proper matching need to handle this as well. */
	if (!kpstrncmpz(nm, "__mod_") && isdigit(nm->s[nm->l - 1]))
		while (isdigit(hnm->s[hnm->l - 1]))
			hnm->l--;
}

struct cblock * cblock_add(struct kp_file *f, int s, int e, kpstr_t *nm, int type, int globl)
{
	struct cblock *blk = malloc(sizeof(*blk));

	if (nm->l && cblock_find_by_name(f, nm))
		kpfatal("duplicate cblock name '%.*s'", nm->l, nm->s);

	blk->start = s;
	blk->end = e;
	blk->f = f;
	blk->name = *nm;
	cblock_make_human_name(&blk->human_name, &blk->name);
	blk->auto_name = !!kpstrcmp(&blk->human_name, &blk->name);
	blk->type = type;
	blk->globl = globl;
	blk->handled = blk->ignore = blk->unlink = 0;
	blk->pair = NULL;
	rb_insert_node(&f->cblocks_by_name, &blk->rbnm, cblock_name_cmp, (unsigned long)&blk->name);
	rb_insert_node(&f->cblocks_by_human_name, &blk->rb_hnm, cblock_human_name_cmp, (unsigned long)&blk->human_name);
	rb_insert_node(&f->cblocks_by_start, &blk->rbs, cblock_start_cmp, s);
	kplog(LOG_DEBUG, "Add cblock %.*s (%d: %d-%d)\n", nm->l, nm->s, f->id, s, e - 1);

	return blk;
}

struct cblock *cblock_find_by_name(struct kp_file *f, kpstr_t *nm)
{
	struct rb_node *rb;
	struct cblock *blk;

	rb = rb_search_node(&f->cblocks_by_name, cblock_name_cmp, (unsigned long)nm);
	if (rb == NULL)
		return NULL;

	blk = rb_entry(rb, struct cblock, rbnm);
	return blk;
}

struct cblock *cblock_find_by_human_name(struct kp_file *f, kpstr_t *nm)
{
	struct rb_node *n, *n2;
	struct cblock *blk;

	n = rb_search_node(&f->cblocks_by_human_name, cblock_human_name_cmp, (unsigned long)nm);
	if (!n)
		return NULL;

	/* find the most-left tree node - we may have collisions, i.e. entries with same name and lookup returns arbitrary one */
	for (n2 = rb_prev(n); n2; n2 = rb_prev(n)) {
		blk = rb_entry(n2, struct cblock, rb_hnm);
		if (kpstrcmp(&blk->human_name, nm))
			break;
		n = n2;
	}

	blk = rb_entry(n, struct cblock, rb_hnm);
	return blk;
}

static int get_kpatch_flags(char *s)
{
	kpstr_t t;
	int flags = 0;

	get_token(&s, &t);

	while(s) {
		get_token(&s, &t);
		if (!kpstrcmpz(&t, "KPGENSRC_ADAPTED"))
			flags |= KPGENSRC_ADAPTED;
	}

	return flags;
}

static void init_func_block(struct kp_file *f, int *i, kpstr_t *nm)
{
	int s = *i, e = *i, globl = 0;
	int flags = 0;
	struct cblock *blk;

	while (e < f->nr_lines - 1 && !is_function_end(f, e, nm)) {
		if (ctype(f, e) == DIRECTIVE_GLOBL)
			globl = 1;
		if (ctype(f, e) == DIRECTIVE_KPFLAGS) {
			flags |= get_kpatch_flags(cline(f, e));
			cline(f, e)[0] = 0;
		}
		e++;
	}

	e++;

	blk = cblock_add(f, s, e, nm, CBLOCK_FUNC, globl);
	if (flags & KPGENSRC_ADAPTED)
		blk->adapted = 1;
	*i = e;
}

static void init_var_block(struct kp_file *f, int *i, kpstr_t *nm)
{
	int s = *i, e = *i, e2, globl = 0;
	kpstr_t nm2;

	while (e < f->nr_lines) {
		if (is_variable_start(f, e, &e2, &globl, &nm2)) {
			if (kpstrcmp(nm, &nm2))
				break;
			e = e2;
			continue;
		}
		if (is_data_def(cline(f, e), ctype(f, e))) {
			e++;
			continue;
		}
		break;
	}
#if 0
	/* unfortunately, variables can be constructed manually in a single line, so w/o 2nd line with "body" */
	if (!has_body)
		kpfatal("Failed to find variable '%.*s' body", nm->l, nm->s);
#endif
	cblock_add(f, s, e, nm, CBLOCK_VAR, globl);
	*i = e;
}

static void init_set_block(struct kp_file *f, int *i, kpstr_t *nm)
{
	char *s = cline(f, *i);
	get_token(&s, nm);
	get_token(&s, nm);
	cblock_add(f, *i, *i + 1, nm, CBLOCK_VAR, 0);
	(*i)++;
}

static void init_other_block(struct kp_file *f, int *i)
{
	int s = *i, e = *i;
	kpstr_t nm;

	while (e < f->nr_lines && !(is_function_start(f, e, &nm) || is_variable_start(f, e, NULL, NULL, &nm)))
		e++;

	kpstrset(&nm, "", 0);
	cblock_add(f, s, e, &nm, CBLOCK_OTHER, 0);
	*i = e;
}

static void init_attr_block(struct kp_file *f, int *i)
{
	kpstr_t nm;
	char *s = cline(f, *i);

	/* use the whole ".weak symbol" or ".globl symbol" as a block name to avoid intersection with real blocks */
	get_token(&s, &nm);
	kpstrset(&nm, nm.s, strlen(nm.s));
	if (!cblock_find_by_name(f, &nm))
		cblock_add(f, *i, *i + 1, &nm, CBLOCK_ATTR, 0);
	(*i)++;
}

void cblock_split(struct cblock *b, int len)
{
	struct cblock *blk = malloc(sizeof(*blk));

	memset(blk, 0, sizeof(*blk));
	blk->start = b->start + len;
	blk->end = b->end;
	blk->f = b->f;
	blk->name = b->name;
	blk->type = b->type;
	b->end = b->start + len;
	rb_insert_node(&blk->f->cblocks_by_name, &blk->rbnm, cblock_name_cmp, (unsigned long)&blk->name);
	rb_insert_node(&blk->f->cblocks_by_human_name, &blk->rb_hnm, cblock_human_name_cmp, (unsigned long)&blk->human_name);
	rb_insert_node(&blk->f->cblocks_by_start, &blk->rbs, cblock_start_cmp, blk->start);
	kplog(LOG_DEBUG, "Add split cblock %.*s (%d: %d-%d)\n", blk->name.l, blk->name.s, blk->f->id, blk->start, blk->end - 1);
}

void cblocks_init(struct kp_file *f)
{
	int i;
	kpstr_t nm;

	rb_init(&f->cblocks_by_name);
	rb_init(&f->cblocks_by_human_name);
	rb_init(&f->cblocks_by_start);
	kpstrset(&nm, "", 0);
	for (i = 1; i < f->nr_lines; ) {
		if (cline(f, i)[0] == 0) {
			i++;	/* skip empty lines */
			continue;
		}
		if (is_function_start(f, i, &nm))
			init_func_block(f, &i, &nm);
		else if (is_variable_start(f, i, NULL, NULL, &nm))
			init_var_block(f, &i, &nm);
		else if (ctype(f, i) == DIRECTIVE_SET)
			init_set_block(f, &i, &nm);
		else if (ctype(f, i) == DIRECTIVE_WEAK || ctype(f, i) == DIRECTIVE_GLOBL)
			/* sometimes .globl memcmp can be found in the middle of asm file... */
			init_attr_block(f, &i);
		else
			init_other_block(f, &i);
	}
}

void cblock_print2(struct cblock *b0, struct cblock *b1)
{
	int i0, i1;

	for (i0 = b0->start, i1 = b1->start; i0 < b0->end || i1 < b1->end; i0++, i1++)
		kplog(LOG_DEBUG, "%-64s            %s\n",
				i0 < b0->end ? cline(b0->f, i0) : "",
				i1 < b1->end ? cline(b1->f, i1) : "");
}

struct cblock *cblock_first(struct kp_file *f)
{
	struct rb_node *n = rb_first(&f->cblocks_by_start);
	if (!n)
		return NULL;
	return rb_entry(n, struct cblock, rbs);
}

struct cblock *cblock_next(struct cblock *blk)
{
	struct rb_node *n = rb_next(&blk->rbs);
	if (!n)
		return NULL;
	return rb_entry(n, struct cblock, rbs);
}

struct cblock *cblock_skip(struct cblock *blk, int type)
{
	while (blk && blk->type != type)
		blk = cblock_next(blk);
	return blk;
}

/* --------------------------------------------- sections handling ----------------------------------------------- */

/* by default outname for all executable sections is .kpatch.text and .kpatch.data otherwise */
static struct section_desc predefined_sections[] = {
	{.name = ".bss"},
	{.name = ".data"},
	{.name = ".init.data"},

	{.name = ".text",		.type = SECTION_EXECUTABLE},
	{.name = ".init.text",		.type = SECTION_EXECUTABLE},
	{.name = ".exit.text",		.type = SECTION_EXECUTABLE},
	{.name = ".text.unlikely",	.type = SECTION_EXECUTABLE},
	{.name = ".text.hot",		.type = SECTION_EXECUTABLE},
	{.name = ".fixup",		.outname = ".kpatch.fixup,\"ax\",@progbits",	.type = SECTION_EXECUTABLE},

	{.name = ".modinfo"},
	{.name = "__ex_table",		.outname = ".kpatch.__ex_table,\"a\",@progbits"},
	{.name = "__bug_table",		.outname = ".kpatch.__bug_table,\"a\""},

	{.name = ".altinstructions",	.outname = ".kpatch.altinstructions,\"a\""},
	{.name = ".altinstr_replacement",.outname = ".kpatch.altinstr_replacement, \"ax\"",	.type = SECTION_EXECUTABLE},
	{.name = ".smp_locks",		.outname = ".kpatch.smp_locks,\"a\""},
	{.name = ".parainstructions",	.outname = ".kpatch.parainstructions,\"a\""},
	{.name = "__jump_table",	.outname = ".kpatch.__jump_table,\"a\""},

	{.name = ".kpatch.text",	.type = SECTION_EXECUTABLE},
	{.name = ".kpatch.init.pre",	.outname = ".kpatch.init.pre,\"aw\",@progbits"},
	{.name = ".kpatch.init",	.outname = ".kpatch.init,\"aw\",@progbits"},
	{.name = ".kpatch.init.post",	.outname = ".kpatch.init.post,\"aw\",@progbits"},
	{.name = ".kpatch.exit.pre",	.outname = ".kpatch.exit.pre,\"aw\",@progbits"},
	{.name = ".kpatch.exit",	.outname = ".kpatch.exit,\"aw\",@progbits"},
	{.name = ".kpatch.exit.post",	.outname = ".kpatch.exit.post,\"aw\",@progbits"},

	{.name = ".discard",		.outname = ".discard,\"awx\",@progbits",	.type = SECTION_EXECUTABLE},

	{.name = "__ksymtab",		.outname = ".kpatch.__ksymtab,\"a\""},
	{.name = "__ksymtab_gpl",	.outname = ".kpatch.__ksymtab,\"a\""},
	{.name = "__kcrctab",		.outname = ".kpatch.__kcrctab,\"a\""},
	{.name = "__kcrctab_gpl",	.outname = ".kpatch.__kcrctab,\"a\""},
	{.name = "__kstrtab",		.outname = ".kpatch.__kstrtab,\"a\""},

	{.name = NULL}
};
static struct rb_root sections_rbroot_byname;

static inline int section_name_cmp(struct rb_node *node, unsigned long key)
{
	struct section_desc *sect = rb_entry(node, struct section_desc, rbnm);
	char *name = (char *)key;

	return strcmp(sect->name, name);
}

struct section_desc *find_section(char *name)
{
	struct rb_node *rb;
	struct section_desc *sect;

	rb = rb_search_node(&sections_rbroot_byname, section_name_cmp, (unsigned long)name);
	if (rb == NULL)
		return NULL;

	sect = rb_entry(rb, struct section_desc, rbnm);
	return sect;
}

static struct section_desc *dup_section(struct section_desc *sect)
{
	struct section_desc *s = malloc(sizeof(*s));
	*s = *sect;
	s->prev = NULL;
	memset(&s->rbnm, 0, sizeof(s->rbnm));
	return s;
}

struct section_desc *csect(struct kp_file *f, int l)
{
	struct section_desc *sect;

	if (l < 0 || l >= f->nr_lines)
		return NULL;

	sect = f->section[l];
	return sect;
}

int is_data_sect(struct section_desc *sect)
{
	return !(sect->type & SECTION_EXECUTABLE);
}

int is_code_sect(struct section_desc *sect)
{
	return (sect->type & SECTION_EXECUTABLE);
}

static struct section_desc *__parse_section(char *s)
{
	struct section_desc *sect;
	char *sname;
	kpstr_t nm;
	const char *delim = " \t,\n;";	/* section names like .note.GNU-stack can have '-' in names, which is not appropriate in normal tokens */

	get_token(&s, &nm);		/* skip section directive */
	__get_token(&s, &nm, delim);	/* section name */

	/* skip quotes around name */
	if (nm.s[0] == '"' && nm.s[nm.l - 1] == '"') {
		nm.s++;
		nm.l -= 2;
	}
	sname = strndup(nm.s, nm.l);
	sect = find_section(sname);
	if (sect) {
		free(sname);
		return dup_section(sect);
	}

	sect = malloc(sizeof(*sect));
	memset(sect, 0, sizeof(*sect));
	sect->name = sname;

	if (s) {
		get_token(&s, &nm);	/* skip ',' */
		if (kpstrcmpz(&nm, ","))
			goto done;
		get_token(&s, &nm);	/* attr */
		if (nm.s[0] == '"') {
			char *cp = strpbrk(&nm.s[1], "x\"");
			if (cp != NULL && *cp == 'x')
				sect->type |= SECTION_EXECUTABLE;
		}
	}
done:
	rb_insert_node(&sections_rbroot_byname, &sect->rbnm, section_name_cmp, (unsigned long)sname);
	return sect;
}

static struct section_desc *parse_section(struct kp_file *f, int l)
{
	int t;
	struct section_desc *cur = f->section[l - 1], *new;

	t = ctype(f, l);
	switch (t) {
		case DIRECTIVE_TEXT: return dup_section(find_section(".text"));
		case DIRECTIVE_DATA: return dup_section(find_section(".data"));
		case DIRECTIVE_BSS: return dup_section(find_section(".bss"));
		case DIRECTIVE_PUSHSECTION:
		case DIRECTIVE_SECTION:
			return __parse_section(cline(f, l));
		case DIRECTIVE_POPSECTION:
		case DIRECTIVE_PREVIOUS:
			return dup_section(cur->prev);
		case DIRECTIVE_SUBSECTION:
			new = dup_section(cur);
			new->prev = cur;
			return new;
	}
	return NULL;
}

void init_sections(struct kp_file *f)
{
	struct section_desc *sect;
	int i;

	if (rb_empty(&sections_rbroot_byname))
		for (i = 0; predefined_sections[i].name; i++)
			rb_insert_node(&sections_rbroot_byname, &predefined_sections[i].rbnm, section_name_cmp, (unsigned long)predefined_sections[i].name);

	f->section = malloc(f->nr_lines * sizeof(void *));
	f->section[0] = find_section(".text");		/* code can start w/o sectiong directive */
	for (i = 1; i < f->nr_lines; i++) {
		sect = parse_section(f, i);
		if (sect) {
			sect->prev = f->section[i - 1];
			f->section[i] = sect;
		} else {
			f->section[i] = f->section[i - 1];
		}
	}
}

/* ----------------------------------------- code block boundaries detection ---------------------------------------- */

int is_function_start(struct kp_file *f, int l, kpstr_t *nm)
{
	char *s;
	kpstr_t nm2, attr;
	int l0 = l, func = 0;

	kpstrset(nm, "", 0);
	for (; l < f->nr_lines; l++) {
		if (l != l0 && cline(f, l)[0] == '\0')
			continue;
		if ((is_sect_cmd(f, l) && is_code_sect(csect(f, l))) ||
		    ctype(f, l) == DIRECTIVE_ALIGN)
		       continue;
		get_type_args(cline(f, l), &nm2, &attr);
		if ((ctype(f, l) == DIRECTIVE_WEAK && l0 != l) ||
		     ctype(f, l) == DIRECTIVE_GLOBL || ctype(f, l) == DIRECTIVE_HIDDEN ||
		     ctype(f, l) == DIRECTIVE_PROTECTED || ctype(f, l) == DIRECTIVE_INTERNAL ||
		    (ctype(f, l) == DIRECTIVE_TYPE && !kpstrcmpz(&attr, "@function"))) {
			s = cline(f, l);
			get_token(&s, &nm2);	/* skip command */
			get_token(&s, &nm2);
			if (nm->l && kpstrcmp(nm, &nm2))	/* verify name matches in all .weak/.globl/.type commands */
				return 0;
			*nm = nm2;
			func = func ? 1 : ctype(f, l) == DIRECTIVE_TYPE;
			continue;
		}
		break;
	}
	return func;
}

int is_function_end(struct kp_file *f, int l, kpstr_t *nm)
{
	/* Functions should always end by .size directive. Previously used to detect .LFe labels, but they are not generated w/o frame pointers */
	if (ctype(f, l) != DIRECTIVE_SIZE)
		return 0;

	kpstr_t nm2;
	char *s = cline(f, l);
	get_token(&s, &nm2);	/* skip command */
	get_token(&s, &nm2);
	if (kpstrcmp(nm, &nm2)) /* verify name matches */
		return 0;

	return 1;
}

int is_variable_start(struct kp_file *f, int l, int *e, int *pglobl, kpstr_t *nm)
{
	char *s;
	int l0 = l, globl = 0;
	kpstr_t nm2, attr;

	kpstrset(nm, "", 0);
	for ( ; cline(f, l); l++) {

		/* first verify that all the commands we met has the same symbol name... just to be safe! */
		s = cline(f, l);
		if (*s == '\0' && l != l0)
			continue;
		switch (ctype(f, l)) {
			case DIRECTIVE_TYPE:
			case DIRECTIVE_GLOBL:
			case DIRECTIVE_LOCAL:
				get_token(&s, &nm2);
			case DIRECTIVE_LABEL:
				get_token(&s, &nm2);
				if (nm->l && kpstrcmp(nm, &nm2))		/* some other symbol met... stop */
					return 0;
				*nm = nm2;
				break;
		}

		switch (ctype(f, l)) {
			case DIRECTIVE_TEXT:
			case DIRECTIVE_DATA:
			case DIRECTIVE_BSS:
			case DIRECTIVE_SECTION:
			case DIRECTIVE_PUSHSECTION:
			case DIRECTIVE_POPSECTION:
			case DIRECTIVE_PREVIOUS:
			case DIRECTIVE_SUBSECTION:
				break;
			case DIRECTIVE_TYPE:
				get_type_args(cline(f, l), &nm2, &attr);
				if (kpstrcmpz(&attr, "@object"))
					return 0;
				break;
			case DIRECTIVE_GLOBL:
				globl = 1;
				break;
			case DIRECTIVE_ALIGN:
				break;
			case DIRECTIVE_COMMENT:
			case DIRECTIVE_SIZE:
				/* can't start with .size */
				if (l0 == l)
					return 0;
				break;
			case DIRECTIVE_LABEL:
				if (!is_data_sect(csect(f, l)))
					return 0;
				/* fall throught */
			case DIRECTIVE_LOCAL:
				if (e)
					*e = l + 1;
				if (pglobl)
					*pglobl = globl;
				return 1;
			default:
				return 0;
		}
	}
	return 0;
}

int is_data_def(char *s, int type)
{
	kpstr_t t;

	get_token(&s, &t);
	if (
	    /* strings */
	    !kpstrcmpz(&t, ".ascii") ||
	    !kpstrcmpz(&t, ".asciz") ||
	    !kpstrcmpz(&t, ".string") ||
	    /* numeric */
	    !kpstrcmpz(&t, ".byte") ||
	    !kpstrcmpz(&t, ".word") ||
	    !kpstrcmpz(&t, ".short") ||
	    !kpstrcmpz(&t, ".int") ||
	    !kpstrcmpz(&t, ".long") ||
	    !kpstrcmpz(&t, ".quad") ||
	    /* float */
	    !kpstrcmpz(&t, ".double") ||
	    !kpstrcmpz(&t, ".float") ||
	    !kpstrcmpz(&t, ".single") ||
	    /* other */
	    !kpstrcmpz(&t, ".value") ||
	    !kpstrcmpz(&t, ".comm") ||
	    !kpstrcmpz(&t, ".zero") ||
	    /* dwarf types */
	    !kpstrcmpz(&t, ".uleb128") ||
	    !kpstrcmpz(&t, ".sleb128") ||
	    !kpstrcmpz(&t, ".4byte")
	)
		return 1;
	return 0;
}

