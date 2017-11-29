#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <getopt.h>

#include "kpatch_log.h"
#include "kpatch_parse.h"
#include "kpatch_dbgfilter.h"
#include "kpatch_flags.h"

#define OS_RHEL5 1
#define OS_RHEL6 2
static int os = OS_RHEL6;

#define ARCH_X86_32 1
#define ARCH_X86_64 2
static int arch = ARCH_X86_64, arch_bits = 64;

#define FLAG_PUSH_SECTION	0x01
#define FLAG_RENAME		0x10
#define FLAG_GOTPCREL		0x20

#define MAX_SYM_LIST		32
struct sym_desc {
	char *filename;
	char *sym;
};
static struct sym_desc ignore_syms[MAX_SYM_LIST];
static int nr_ignore_syms;

static struct sym_desc unlink_syms[MAX_SYM_LIST];
static int nr_unlink_syms;

static struct sym_desc must_adapt_syms[MAX_SYM_LIST];
static int nr_must_adapt_syms;

static int force_gotpcrel;
static int force_global;

static inline int in_syms_list(char *filename, kpstr_t *sym, const struct sym_desc *sym_arr, int nr_syms)
{
	int i, len;
	for (i = 0; i < nr_syms; i++) {
		if (sym_arr[i].filename) {
			len = strlen(sym_arr[i].filename);
			if (strncmp(filename, sym_arr[i].filename, len))
				continue;
		}
		if (!kpstrcmpz(sym, sym_arr[i].sym))
			return 1;
	}
	return 0;
}

/* ---------------------------------------- renames ------------------------------------------ */

struct rename {
	kpstr_t src, dst;
	struct rb_node rb;
};

static inline int rename_cmp(struct rb_node *node, unsigned long key)
{
	struct rename *r = rb_entry(node, struct rename, rb);
	kpstr_t *nm = (kpstr_t *)key;
	int res;

	res = kpstrcmp(&r->src, nm);
	return res;
}

struct rename * rename_find(struct kp_file *f, kpstr_t *nm)
{
	struct rb_node *rb;
	struct rename *r;

	rb = rb_search_node(&f->renames, rename_cmp, (unsigned long)nm);
	if (rb == NULL)
		return NULL;

	r = rb_entry(rb, struct rename, rb);
	return r;
}

void rename_add(struct kp_file *f, kpstr_t *src, kpstr_t *dst)
{
	struct rename *r, *r2;

	if (!kpstrcmp(src, dst))
		return;

	if ((r2 = rename_find(f, src))) {
		if (kpstrcmp(&r2->dst, dst))
			kpfatal("Rename conflict %.*s -> %.*s and -> %.*s\n", src->l, src->s, r2->dst.l, r2->dst.s, dst->l, dst->s);
		return;
	}

	r = malloc(sizeof(*r));
	r->src = *src;
	r->dst = *dst;
	rb_insert_node(&f->renames, &r->rb, rename_cmp, (unsigned long)src);
}

void rename_del(struct kp_file *f, kpstr_t *src)
{
	struct rename *r;
	r = rename_find(f, src);
	if (r) {
		rb_erase(&r->rb, &f->renames);
		free(r);
	}
}

int strcmp_after_rename(struct kp_file *f0, struct kp_file *f1, char *s0, char *s1)
{
	kpstr_t t0, t1;
	struct rename *r0, *r1;

	while (s0 && s1) {
		get_token(&s0, &t0);
		get_token(&s1, &t1);

		r0 = rename_find(f0, &t0);
		r1 = rename_find(f1, &t1);

		if (r0 && r1 && !kpstrcmp(&r0->dst, &r1->dst))				/* t0 -> x && t1 -> x case */
			continue;
		if (r0 && r1 && !kpstrcmp(&r0->dst, &t1) && !kpstrcmp(&r1->dst, &t0))	/* t0 <-> t1 case */
			continue;
		if (r0 && !r1 && !kpstrcmp(&r0->dst, &t1))				/* t0 -> t1 */
			continue;
		if (!r0 && r1 && !kpstrcmp(&t0, &r1->dst))				/* t0 <- t1 */
			return 1;
		if (!r0 && !r1 && !kpstrcmp(&t0, &t1))
			continue;
		return 1;
	}
	return !(s0 == NULL && s1 == NULL);
}

void str_do_rename(struct kp_file *f, char *dst, char *src)
{
	kpstr_t t0, *t;
	struct rename *r;
	char *s;

	*dst = 0;
	while (src) {
		for (s=src; isblank(*s); s++)
			strncat(dst, s, 1);
		get_token(&src, &t0);

		r = rename_find(f, &t0);
		t = r ? &r->dst : &t0;
		strncat(dst, t->s, t->l);
		for (s=t0.s + t0.l; isblank(*s); s++)
			strncat(dst, s, 1);
	}
}

#define	GOTPCREL_SUFFIX	"@GOTPCREL(%rip)"
#define	GOTPCREL_LENGTH	(sizeof(GOTPCREL_SUFFIX) - 1)

#define GOTTPOFF_SUFFIX "@GOTTPOFF(%rip)"
#define GOTTPOFF_LENGTH (sizeof(GOTTPOFF_SUFFIX) - 1)

static int is_gotpcrel(kpstr_t *t)
{
	if (t->l <= GOTPCREL_LENGTH + 1)
		return 0;
	return !strncasecmp(t->s + t->l - GOTPCREL_LENGTH, GOTPCREL_SUFFIX,
			    GOTPCREL_LENGTH);
}

static int is_gottpoff(kpstr_t *t)
{
	if (t->l <= GOTTPOFF_LENGTH + 1)
		return 0;
	return !strncasecmp(t->s + t->l - GOTTPOFF_LENGTH, GOTTPOFF_SUFFIX,
			    GOTTPOFF_LENGTH);
}

static int is_gotpcrel_or_gottpoff(kpstr_t *t)
{
	return is_gotpcrel(t) || is_gottpoff(t);
}

static void get_full_reg(kpstr_t *t, char *dstreg)
{
	dstreg[0] = '%';
	dstreg[1] = 'r';
	if (t->l > 2 && t->s[0] == '%') {
		char prev = t->s[t->l - 2];
		char last = t->s[t->l - 1];
		switch (last) {
		case 'h':
		case 'l':
		case 'x':
			dstreg[2] = prev;
			dstreg[3] = 'x';
			break;
		case 'd':
			/* Is %rNNd */
			if (t->l == 5) {
				prev = t->s[2];
				last = t->s[3];
			} else
			/* Is %rNd */
				last = '\0';
			/* FALLTHROUGH */
		default:
                        if (t->l == 3) {  // Is %rN
                                dstreg[2] = t->s[2];
                                dstreg[3] = 0;
                                return;
                        }
			dstreg[2] = prev;
			dstreg[3] = last;
			break;
		}
	} else {
		kpfatal("unable to get_auxreg for '%.*s'\n", t->l, t->s);
	}
	dstreg[4] = '\0';
}

/* Return true if token references rax or its part. */
static int is_rax_reference(kpstr_t *t)
{
	return (t->l > 2 && t->s[0] == '%' && t->s[t->l - 2] == 'a');
}

#define	RIP_SUFFIX	"(%rip)"
#define	RIP_LENGTH	(sizeof(RIP_SUFFIX) - 1)

static int is_global_rip_reference(kpstr_t *t)
{
	return t->l > RIP_LENGTH &&
	       !strncasecmp(t->s + t->l - RIP_LENGTH, RIP_SUFFIX, RIP_LENGTH) &&
	       (t->s[0] != '.' || t->s[1] != 'L');
}

#define	MOV_PREFIX	"mov"
#define	MOV_LENGTH	(sizeof(MOV_PREFIX) - 1)

void str_do_gotpcrel(struct kp_file *f, char *dst, char *src)
{
	kpstr_t mov, movsrc, movdst, tmptok;
	char flavor[16], *s = src, *d = dst;

	*d = 0;

	get_token(&s, &mov);

	/* Command is not a mov */
	if (kpstrncmpz(&mov, "mov"))
		goto out;

	/* Command has no %rip reference */
	if (strstr(s, "%rip") == NULL)
		goto out;

	strncpy(flavor, mov.s + MOV_LENGTH, mov.l - MOV_LENGTH);
	flavor[mov.l - MOV_LENGTH] = '\0';

	get_token(&s, &movsrc);
	do {
		get_token(&s, &tmptok);
		if (!kpstrcmpz(&tmptok, ","))
			break;
		movsrc.l += tmptok.l;
	} while (s);

	if (!s)
		kpfatal("can't parse src/dst from '%s'\n", src);

	get_token(&s, &movdst);
	do {
		get_token(&s, &tmptok);
		if (!kpstrcmpz(&tmptok, "\n"))
			break;
		movdst.l += tmptok.l;
	} while (s);

	if (is_global_rip_reference(&movsrc)) {
		char auxreg[8];

		if (is_gotpcrel_or_gottpoff(&movsrc)) {
			/* Is GOTPCREL (-fPIC) already, bail out */
			goto out;
		}

		/* Use full 64-bit counterpart of the destination register
		 * as the auxiliary register */
		get_full_reg(&movdst, auxreg);

		d += sprintf(d, "\tmovq\t%.*s%s, %s\n",
			movsrc.l - (int)RIP_LENGTH, movsrc.s, GOTPCREL_SUFFIX,
			auxreg);
		d += sprintf(d, "\tmov%s\t(%s), %.*s\n", flavor,
			auxreg, movdst.l, movdst.s);

		*(d - 1) = '\0';

		return;
	}

	if (is_global_rip_reference(&movdst)) {
		char *auxreg;

		if (is_gotpcrel_or_gottpoff(&movdst)) {
			/* Is GOTPCREL (-fPIC) already, bail out */
			goto out;
		}

		auxreg = is_rax_reference(&movsrc) ? "%rbx" : "%rax";

		d += sprintf(d, "\tpushq\t%s\n", auxreg);
		d += sprintf(d, "\tmovq\t%.*s%s, %s\n",
			movdst.l - (int)RIP_LENGTH, movdst.s, GOTPCREL_SUFFIX, auxreg);
		d += sprintf(d, "\tmov%s\t%.*s, (%s)\n",
			flavor, movsrc.l, movsrc.s, auxreg);
		d += sprintf(d, "\tpopq\t%s", auxreg);

		return;
	}

out:
	strcpy(dst, src);
	return;
}

/* ------------------------------------------ helpers -------------------------------------------- */

static void change_section(struct kp_file *fout, struct section_desc *sect, int flags)
{
	char *s;

	if (sect->outname)
		s = sect->outname;
	else if (sect->type & SECTION_EXECUTABLE)
		s = ".kpatch.text,\"ax\",@progbits";
	else
		s = ".kpatch.data,\"aw\",@progbits";

	fprintf(fout->f, "\t.%ssection %s\n", (flags & FLAG_PUSH_SECTION) ? "push" : "", s);
}

void get_comm_args(struct kp_file *f, int l, kpstr_t *xname, int *sz, int *align)
{
	char *s, *p;
	kpstr_t t;

	s = cline(f, l);
	get_token(&s, &t);
	if (kpstrcmpz(&t, ".comm")) kpfatal("get_comm_args() on non .comm cmd\n");

	get_token(&s, xname);
	get_token(&s, &t);
	if (kpstrcmpz(&t, ",")) kpfatal("can't parse .comm token #3\n");

	get_token(&s, &t);
	*sz = strtoul(t.s, &p, 10);
	if (p == t.s) kpfatal("can't parse .comm size\n");

	*align = 0;
	if (s == NULL)
		return;

	get_token(&s, &t);
	if (kpstrcmpz(&t, ",")) kpfatal("can't parse .comm token #5\n");
	get_token(&s, &t);
	*align = strtoul(t.s, &p, 10);
	if (p == t.s) kpfatal("can't parse .comm align\n");
}

/* .comm implies .bss section, while we need to put all new data to .kpatch.data, so parse and replace with other commands  */
/* Surprise!!! sometimes .comm can be of a zero size for an empty struct definition :) */
void add_comm_cmd(struct kp_file *fout, struct kp_file *f, int l, int flags)
{
	kpstr_t commname, *nm = &commname;
	struct rename *r;
	int sz, align;

	get_comm_args(f, l, &commname, &sz, &align);
	if (flags & FLAG_RENAME) {
		r = rename_find(f, nm);
		nm = r ? &r->dst : &commname;
	}

	change_section(fout, find_section(".data"), FLAG_PUSH_SECTION);
	if (align)
		fprintf(fout->f, "\t.align\t%d\n", align);
	fprintf(fout->f, "%.*s:\n", nm->l, nm->s);
	if (sz)
		fprintf(fout->f, "\t.zero\t%d\n", sz);
	fputs("\t.popsection\n", fout->f);
}


/* -------------------------------------- code blocks matching ----------------------------------------- */

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

static struct {
	char *funcname;
	char *regname;
} lineno_functions[] = {
	/* A list of pairs { "functioname", "expected register" } */
	{ "warn_slowpath_null", "esi" },
	{ "warn_slowpath_fmt", "esi" },
	{ "warn_slowpath_fmt_taint", "esi" },

	{ "object_dynamic_cast_assert@PLT", "ecx" },
	{ "object_class_dynamic_cast_assert@PLT", "ecx" },
	{ "error_setg_internal@PLT", "edx" },
	{ "error_setg_errno_internal@PLT", "edx" },
	{ "g_assertion_message_expr@PLT", "edx" },
	{ "__assert_fail@PLT", "edx" },
	{ "__assert_fail@PLT", "dx" },
};

static inline int get_mov_const_reg(const char *s, char *regname)
{
	/* Extract register name ignoring the line number. */
	return sscanf(s, " mov%*c $%*i, %%%31[a-zA-Z0-9]", regname);
}

/*
 * Extracts register names from `movl $const, %reg` operations of both lines
 * and returns bit mask with possible function names to match.
 */
static int get_possible_lineno_funcs(const char *s0, const char *s1)
{
	int i, try = 0;
	char regname0[32], regname1[32];

	if (ARRAY_SIZE(lineno_functions) > sizeof(try) * 8)
		kpfatal("get_possible_lineno_funcs return value overflow");

	if (!get_mov_const_reg(s0, regname0) ||
	    !get_mov_const_reg(s1, regname1))
		return 0;

	if (strcmp(regname0, regname1))
		return 0;

	for (i = 0; i < ARRAY_SIZE(lineno_functions); i++) {
		if (!strcmp(regname0, lineno_functions[i].regname))
			try |= (1 << i);
	}

	return try;
}

/* this is a minor improvement to avoid function patching just because of code line numbers are screwed, but real function hasn't changed */
static int match_lineno_func(struct cblock *b0, int *p0, struct cblock *b1, int *p1)
{
	char *s0, *s1;
	int i0 = *p0, i1 = *p1, i, possible_funcs;
	kpstr_t xs0, xs1;

	/* WARN_ONCE() generates a code with __LINE__ inside, so it easily leads to difference even in functions not really changed */
	/* so we try to find a sequence like:
	 *
	 * movl $const, %esi
	 * ...
	 * call warn_slowpath_XXX
	 */

	/* the lines that differ are guaranteed to be present in files */
	s0 = cline(b0->f, i0++); s1 = cline(b1->f, i1++);

	/* what functions should we expect called for these registers, if any? */
	possible_funcs = get_possible_lineno_funcs(s0, s1);
	if (!possible_funcs)
		return 0;

	/*
	 * Just in case, it's better to keep the search distance as small as
	 * possible.  Usually, call to warn_slowpath* is within 6 next lines
	 * (~99% of warnings in vmlinux), but in some functions that are better
	 * left unpatched there are warnings with quite a large number of
	 * arguments (e.g. tcp_recvmsg on 2.6.32 kernels has 15 lines between
	 * saving line-number and calling warn_slowpath_fmt).
	 */
	for (i = 0; i < 15; i++, i0++, i1++) {
		if (i0 >= b0->end || i1 >= b1->end)
			return 0;
		s0 = cline(b0->f, i0); s1 = cline(b1->f, i1);

		/*
		 * There are cases of several instructions saving constant value
		 * to %reg in 5-6 lines before the call to the appropriate
		 * function.  Which means that the one saving warning's line
		 * number is probably the last one, and not the one passed to
		 * match_lineno_func(). Clear the matching functions from the
		 * list of our variants.
		 */
		possible_funcs &= ~get_possible_lineno_funcs(s0, s1);
		if (!possible_funcs)
			return 0;

		/* no diffs allowed between line number saving and the call */
		if (strcmp_after_rename(b0->f, b1->f, s0, s1))
			return 0;

		get_token(&s0, &xs0); get_token(&s1, &xs1);
		if (!kpstrcmpz(&xs0, "call"))
			goto call;
	}

	return 0;

call:
	get_token(&s0, &xs0); get_token(&s1, &xs1);
	for (i = 0; i < ARRAY_SIZE(lineno_functions); i++) {
		if (!(possible_funcs & (1 << i)))
			continue;

		if (kpstrcmpz(&xs0, lineno_functions[i].funcname))
			continue;

		/*
		 * Consider all the checked lines "identical" and skip them by
		 * setting iterators to the number of "call warn_slowpath_*"
		 * line, they will later get incremented before next
		 * for-iteration in cblock_cmp().
		 */
		*p0 = i0; *p1 = i1;
		return 1;
	}

	return 0;
}

static int match_build_path(struct cblock *b0, int *p0, struct cblock *b1, int *p1)
{
	char *s0 = cline(b0->f, *p0), *s1 = cline(b1->f, *p1);
	kpstr_t t0, t1;

	get_token(&s0, &t0); get_token(&s1, &t1);
	if (kpstrcmpz(&t0, ".string") || kpstrcmpz(&t0, ".string"))
		return 0;

	/* skip quotes around */
	get_token(&s0, &t0); get_token(&s1, &t1);
	if (kpstrncmpz(&t0, "\"") || kpstrncmpz(&t1, "\""))
		return 0;
	kpstrskip(&t0, 1); kpstrskip(&t1, 1);

	/* match dirnames */
	if (kpstrncmpz(&t0, b0->f->dirname) || kpstrncmpz(&t1, b1->f->dirname))
		return 0;

	/* skip matched dirname, the rest string should be the same */
	kpstrskip(&t0, strlen(b0->f->dirname)); kpstrskip(&t1, strlen(b1->f->dirname));
	if (!kpstrcmp(&t0, &t1)) {
		kplog(LOG_DEBUG, "Matched build path at %d, %d\n", *p0, *p1);
		return 1;
	}
	return 0;
}

/* this is a minor improvement to avoid function patching just because of code line numbers are screwed, but real function hasn't changed */
static int match_var_descriptor(struct cblock *b0, int *p0, struct cblock *b1, int *p1)
{
	char *s0, *s1;
	kpstr_t t0, t1;

	/* static variable descriptor from pr_debug() may easily results in code mismatches due to use of __LINE__ macro inside, try to match */
#define DESC_STR "descriptor."
	if (kpstrncmpz(&b0->name, DESC_STR) || kpstrncmpz(&b1->name, DESC_STR))
		return 0;

	s0 = cline(b0->f, *p0); s1 = cline(b1->f, *p1);
	get_token(&s0, &t0); get_token(&s1, &t1);
	if (kpstrcmpz(&t0, ".byte") || kpstrcmpz(&t1, ".byte"))
		return 0;

	return 1;
}

static int match_var_datetime(struct cblock *b0, int *p0, struct cblock *b1, int *p1)
{
#if 0
	char *s0, *s1, *s;
	kpstr_t t0, t1;

	s0 = cline(b0->f, *p0); s1 = cline(b1->f, *p1);
	get_token(&s0, &t0); get_token(&s1, &t1);
	if (kpstrcmpz(&t0, ".string") || kpstrcmpz(&t1, ".string") || strlen(s0) != strlen(s1))
		return 0;

	while (*s0 && *s1) {
		if (!strncmp(s1, __DATE__, strlen(__DATE__))) {
			s0 += strlen(__DATE__);
			s1 += strlen(__DATE__);
			continue;
		}
		if (!strncmp(s1, __TIME__, strlen(__TIME__))) {
			s0 += strlen(__TIME__);
			s1 += strlen(__TIME__);
			continue;
		}
		if (*s0 == *s1) {
			s0++; s1++;
			continue;
		}

		return 0;
	}
	return (*s0 == *s1) ? 1 : 0;
#else
	/* if both kernels are compiled with fake __DATE__ and __TIME__ then no need to match it. */
	return 0;
#endif
}

/* this is a minor improvement to avoid function patching just because of code line numbers are screwed, but real function hasn't changed */
static int match_bug_on(struct cblock *b0, int *p0, struct cblock *b1, int *p1)
{
	char *s0, *s1;
	kpstr_t t00, t01, t10, t11, t20, t21, t30, t31, t40, t41, t50, t51, t60, t61;

	if (os == OS_RHEL5) {
		/* RHEL5 BUG() refers to __LINE__ right in the code like this:
		 *      ud2 ; pushq $.LC0 ; ret $1704
		 * so if everything but line numbers match - function hasn't really changed and can be left in original version
		 */
		s0 = cline(b0->f, *p0); s1 = cline(b1->f, *p1);
		get_token(&s0, &t00); get_token(&s1, &t01);
		get_token(&s0, &t10); get_token(&s1, &t11);
		get_token(&s0, &t20); get_token(&s1, &t21);
		__get_token(&s0, &t30, " \t,;"); __get_token(&s1, &t31, " \t,;");
		get_token(&s0, &t40); get_token(&s1, &t41);
		get_token(&s0, &t50); get_token(&s1, &t51);
		__get_token(&s0, &t60, " \t,;"); __get_token(&s1, &t61, " \t,;");
		if (kpstrcmpz(&t00, "ud2") || kpstrcmpz(&t01, "ud2") ||
		    kpstrcmpz(&t10, ";") || kpstrcmpz(&t11, ";") ||
		    kpstrcmpz(&t20, "pushq") || kpstrcmpz(&t21, "pushq") ||
		    kpstrcmpz(&t40, ";") || kpstrcmpz(&t41, ";") ||
		    kpstrcmpz(&t50, "ret") || kpstrcmpz(&t51, "ret") ||
		    s0 != NULL || s1 != NULL
		   )
			return 0;
		goto match;
	}
	if (os == OS_RHEL6) {
		/* RHEL6 BUG() refers to __LINE__ from special section with bug description like this:
		 *        1:      ud2
		 *        .pushsection __bug_table,"a"
		 *        2:      .long 1b - 2b, .LC0 - 2b
		 *                .word 48, 0
		 *                .org 2b+12
		 *        .popsection
		 */
		s0 = cline(b0->f, *p0); s1 = cline(b1->f, *p1);
		if (strcmp(csect(b0->f, *p0)->name, "__bug_table") || strcmp(csect(b1->f, *p1)->name, "__bug_table"))
		       return 0;
		if (!strncmp(s0, "2:\t.long 1b - 2b, ", 18) && !strncmp(s1, "2:\t.long 1b - 2b, ", 18))
			goto match;
		get_token(&s0, &t00); get_token(&s1, &t01);
		if (!kpstrcmpz(&t00, ".word") && !kpstrcmpz(&t01, ".word"))
			goto match;
	}
	return 0;
match:
	kplog(LOG_DEBUG, "Matched BUG() at %d, %d\n", clinenum(b0->f, *p0), clinenum(b1->f, *p1));
	return 1;
}

static void cblock_cmp_skip(struct cblock *b, int *i)
{
	while (*i < b->end) {
		/* Skip section commands - they may differ (gcc issues them only when really need to change and
		 * freshly inserted variable may have changed section already above.
		 * !!! But we check that blocks go to the same sections. */
		if (is_sect_cmd(b->f, *i))
			{(*i)++; continue;}

		/* skip .globl commands - they may differ as well. e.g. in old code function was static, while in new one - global.
		 * later during code output we find this difference and make the old code global as well (for symbol resolving) */
		if (ctype(b->f, *i) == DIRECTIVE_GLOBL)
			{(*i)++; continue;}

		if (cline(b->f, *i)[0] == '\0')
			{(*i)++; continue;}
		break;
	}
}

#define CBLOCK_CMP_SECT		1
#define CBLOCK_CMP_RENAME	2

static int cblock_cmp(struct cblock *b0, struct cblock *b1, int flags)
{
	int i0, i1, t0, t1;
	char *s0, *s1;

	for (i0 = b0->start, i1 = b1->start; ; i0++, i1++) {
		cblock_cmp_skip(b0, &i0);
		cblock_cmp_skip(b1, &i1);
		if (i0 >= b0->end || i1 >= b1->end)
			break;

		s0 = cline(b0->f, i0); t0 = ctype(b0->f, i0);
		s1 = cline(b1->f, i1); t1 = ctype(b1->f, i1);

		/* .comm directive implies .bss section (?). saw such a symbol put to .rodata by gcc! */
		if ((flags & CBLOCK_CMP_SECT) && strcmp(csect(b0->f, i0)->name, csect(b1->f, i1)->name) &&
				t0 != DIRECTIVE_LOCAL && t0 != DIRECTIVE_COMM && t1 != DIRECTIVE_LOCAL && t1 != DIRECTIVE_COMM)
			goto diff;

		if (t0 == DIRECTIVE_COMMENT && t1 == DIRECTIVE_COMMENT)
			continue;

		if (flags & CBLOCK_CMP_RENAME) {
			if (!strcmp_after_rename(b0->f, b1->f, s0, s1))
				continue;
		} else {
			if (!strcmp(s0, s1))
				continue;
		}

		if (b0->type == CBLOCK_FUNC && match_lineno_func(b0, &i0, b1, &i1))
			continue;
		if (b0->type == CBLOCK_FUNC && match_bug_on(b0, &i0, b1, &i1))
			continue;
		if (b0->type == CBLOCK_VAR && match_build_path(b0, &i0, b1, &i1))
			continue;
		if (b0->type == CBLOCK_VAR && match_var_descriptor(b0, &i0, b1, &i1))
			continue;
		if (b0->type == CBLOCK_VAR && match_var_datetime(b0, &i0, b1, &i1))
			continue;
		goto diff;
	}
	if (i0 != b0->end || i1 != b1->end)
		goto diff;
	return 0;

diff:
	kplog(LOG_DEBUG, "cblock_cmp: difference at %d vs. %d\n", clinenum(b0->f, i0), clinenum(b1->f, i1));
	return 1;
}

static int __cblock_var_cmp(struct cblock *b0, struct cblock *b1)
{
	int res;
	struct rename *r;

	if (!b1)
		return 1;

	/* skip already matched blocks - actually 1st check below is wider then 2nd */
	if (b1->pair && b1->pair != b0)
		return 1;
	if ((r = rename_find(b1->f, &b1->name)) && kpstrcmp(&b0->name, &r->dst))
		return 1;

	/* base name (human given) of variable should be the same, e.g. we should try to match desc.XXX to desc.XXX and to nothing else */
	if (kpstrcmp(&b0->human_name, &b1->human_name))
		return 1;

	rename_add(b0->f, &b0->name, &b1->name);
	rename_add(b1->f, &b1->name, &b0->name);
	res = cblock_cmp(b0, b1, CBLOCK_CMP_SECT|CBLOCK_CMP_RENAME);
	rename_del(b0->f, &b0->name);
	rename_del(b1->f, &b1->name);
	return res;
}

static struct cblock * cblock_var_try_to_match(struct kp_file *f0, struct kp_file *f1, struct cblock *b0, struct cblock *b1)
{
	/* case #1: for normal variables just do a strict matching by name */
	if (!b0->auto_name)
		return cblock_find_by_name(f1, &b0->name);

	/* case #2: auto-generated variables with numbers at the end (e.g. .LC2 or __warn.23666 or __mod_XXX#__LINE__ should be tried to match with other vars */

	/* check that content matches, try the current b1 variable at hands to save time on the loop below */
	if (b1 && !__cblock_var_cmp(b0, b1))
		return b1;

	/* when new variables are inserted, old ones obviously don't match 1:1 and we need to skip some in new file to find the match */
	for (b1 = cblock_skip(cblock_first(f1), CBLOCK_VAR); b1; b1 = cblock_skip(cblock_next(b1), CBLOCK_VAR)) {
		if (!__cblock_var_cmp(b0, b1))
			return b1;
	}
	return NULL;
}

static void cblock_var_check_content(struct cblock *b0)
{
	struct cblock *b1 = b0->pair;

	/* not matched variables are handled later separately */
	if (!b1)
		return;

	/* compare blocks */
	kplog(LOG_DEBUG, "Comparing variables %.*s and %.*s at %d-%d and %d-%d\n", b0->name.l, b0->name.s, b1->name.l, b1->name.s,
			clinenum(b0->f, b0->start), clinenum(b0->f, b0->end-1), clinenum(b1->f, b1->start), clinenum(b1->f, b1->end-1));
	kplog(LOG_DEBUG, "-------------------------------------------\n");
	cblock_print2(b0, b1);
	kplog(LOG_DEBUG, "-------------------------------------------\n");

	if (in_syms_list(b1->f->basename, &b0->human_name, ignore_syms, nr_ignore_syms))
		return;

	if (cblock_cmp(b0, b1, CBLOCK_CMP_SECT|CBLOCK_CMP_RENAME))
		kpfatal("Variables %.*s (line %d) and %.*s (line %d) don't match\n", b0->name.l, b0->name.s, clinenum(b0->f, b0->start),
				b1->name.l, b1->name.s, clinenum(b1->f, b1->start));
}

#define MATCH_ACTION_RENAME_ADD		1
#define MATCH_ACTION_RENAME_DEL		2
#define MATCH_ACTION_RENAME_VERBOSE	4
static void cblock_func_match_labels(struct cblock *b0, struct cblock *b1, int action)
{
	int i0, i1;
	char *s0, *s1;
	kpstr_t t0, t1;

	/* we don't try that much... just matching labels one by one... real matching would be an NP-problem (see how `diff` works) */
	for (i0 = b0->start, i1 = b1->start ; i0 < b0->end && i1 < b1->end; i0++, i1++) {
		while (i0 < b0->end && ctype(b0->f, i0) != DIRECTIVE_LABEL) i0++;
		while (i1 < b1->end && ctype(b1->f, i1) != DIRECTIVE_LABEL) i1++;

		if (i0 >= b0->end || i1 >= b1->end)
			break;

		s0 = cline(b0->f, i0);
		s1 = cline(b1->f, i1);
		if (!strcmp(s0, s1))
			continue;

		get_token(&s0, &t0);
		get_token(&s1, &t1);

		if (action & MATCH_ACTION_RENAME_ADD)
			rename_add(b0->f, &t0, &t1);
		else if (action & MATCH_ACTION_RENAME_DEL)
			rename_del(b0->f, &t0);
		if (action & MATCH_ACTION_RENAME_VERBOSE)
			kplog(LOG_DEBUG, "RENAME[0]: %.*s -> %.*s\n", t0.l, t0.s, t1.l, t1.s);

		if (!s0 || !s1 || *s0 != ':' || *s1 != ':')
			kpfatal("Label parsing error\n");
	}
}

static void __name_add_kpatch_suffix(struct kp_file *f, kpstr_t *t, kpstr_t *basename, const char *suffix)
{
	kpstr_t tnew;

	/* rename name to name.kpatch */
	tnew.l = basename->l + strlen(suffix) + 1;
	tnew.s = malloc(tnew.l);
	snprintf(tnew.s, tnew.l, "%.*s%s", basename->l, basename->s, suffix);
	rename_add(f, t, &tnew);
	kplog(LOG_DEBUG, "RENAME[%d]: %.*s -> %.*s\n", f->id, t->l, t->s, tnew.l, tnew.s);
}

static void cblock_make_new_labels(struct cblock *b)
{
	int i;
	char *s;
	kpstr_t t;

	/* just add .kpatch suffix to all label names */
	for (i = b->start ; i < b->end; i++) {
		while (i < b->end && ctype(b->f, i) != DIRECTIVE_LABEL) i++;
		if (i >= b->end)
			break;

		s = cline(b->f, i);
		get_token(&s, &t);
		if (!s || *s != ':')
			kpfatal("Label parsing error at %d\n", clinenum(b->f, i));

		/* rename all but block name itself */
		if (!kpstrcmp(&t, &b->name))
			continue;

		__name_add_kpatch_suffix(b->f, &t, &t, ".kpatch");
	}
}

static void cblock_make_new_name(struct cblock *b, kpstr_t *basename, const char * suffix)
{
	/* rename name -> basename + suffix */
	__name_add_kpatch_suffix(b->f, &b->name, basename, suffix);
}

/* -------------------------------------------- analyzer ---------------------------------------------- */

static void analyze_var_cblocks_matches(struct kp_file *f0, struct kp_file *f1)
{
	struct cblock *b0, *b1;
	int progress, pass = 0;

	do {
		progress = 0;
		b1 = cblock_skip(cblock_first(f1), CBLOCK_VAR);
		for (b0 = cblock_skip(cblock_first(f0), CBLOCK_VAR); b0; b0 = cblock_skip(cblock_next(b0), CBLOCK_VAR)) {
			if (b0->pair)
				continue;
			if (pass == 0 && !kpstrncmpz(&b0->name, DESC_STR))
				continue;
			/* sometimes name can match due to renames in asm, but content - not. So try to match with real variable content */
			b1 = cblock_var_try_to_match(f0, f1, b0, b1);
			if (!b1)		/* skip unmatched variables */
				continue;

			rename_add(f0, &b0->name, &b1->name);
			rename_add(f1, &b1->name, &b0->name);
			kplog(LOG_DEBUG, "RENAME: %.*s <-> %.*s\n", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
			b0->pair = b1; b1->pair = b0;
			progress = 1;
			b1 = cblock_skip(cblock_next(b1), CBLOCK_VAR);
		}
		if (!progress)
			pass++;
	} while (pass < 2);

	for (b0 = cblock_skip(cblock_first(f0), CBLOCK_VAR); b0; b0 = cblock_skip(cblock_next(b0), CBLOCK_VAR)) {
		if (!b0->pair) {
			/* constant strings may disappear if e.g. printk() argument was changed... let them go... */
			if (!kpstrncmpz(&b0->name, ".LC"))
				continue;
			/* warned.XXX and __func__. variables used in WARN_ONCE() may go if we remove warnings in code... */
			if (!kpstrncmpz(&b0->name, "warned.") || !kpstrncmpz(&b0->name, "__warned.") || !kpstrncmpz(&b0->name, "__func__."))
				continue;
			/* descriptor variables used in pr_debug() may go away if we remove/change warnings in code... */
			if (!kpstrncmpz(&b0->name, DESC_STR))
				continue;
			kpfatal("Variable %.*s was removed or changed? Patch requires adoptation\n", b0->name.l, b0->name.s);
		}
	}
}

static void analyze_var_cblocks(struct kp_file *f0, struct kp_file *f1)
{
	struct cblock *b0, *b1;

	/* Pass #1: add renames to all variables first assuming they should match (content comparison is done later) */
	analyze_var_cblocks_matches(f0, f1);

	/* Pass #2: compare variable content of all matched variables from the source side */
	for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
		if (b0->type != CBLOCK_VAR)
			continue;
		cblock_var_check_content(b0);
	}

	/* Pass #3: rename all new variables to avoid conflicts with old names */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type != CBLOCK_VAR || b1->pair)
			continue;
		cblock_make_new_name(b1, &b1->name, ".kpatch");
	}
}

/*
 * This functions simply skips "func" functions on boths sides and matches any "func.XXX" to another "func.YYY".
 * Not accurate, but it's not a big deal - in the worst case function will be replaced when it could be avoided...
 */
static struct cblock *func_match_by_human_name(struct cblock *b0, struct cblock *b1, int cmp)
{
	if (!b1)
		return NULL;

	while (1) {
		if (kpstrcmp(&b0->human_name, &b1->human_name))	/* iterated over all entries with same human_name */
			break;
		/* skip all entries with name == human_name, they were processed already on pass #1 */
		if (!b1->auto_name || b1->pair)
			goto next;

		kplog(LOG_DEBUG, "consider: %.*s :: %.*s\n", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
		if (cmp) {
			cblock_func_match_labels(b0, b1, MATCH_ACTION_RENAME_ADD);
			cmp = cblock_cmp(b0, b1, CBLOCK_CMP_SECT|CBLOCK_CMP_RENAME);
			cblock_func_match_labels(b0, b1, MATCH_ACTION_RENAME_DEL);
		}

		if (!cmp)
			return b1;
next: ;
		struct rb_node *n = rb_next(&b1->rb_hnm);
		if (!n)
			break;
		b1 = rb_entry(n, struct cblock, rb_hnm);
	}
	return NULL;
}

static void analyze_func_cblocks(struct kp_file *f0, struct kp_file *f1)
{
	struct cblock *b0, *b1;
	int progress, cmp, not_adapted=0;

	/* Pass #1: match functions by their EXACT names (and skip auto generated funcs) and try to match all local function labels then */
	kplog(LOG_DEBUG, "matching normal symbols\n");
	log_indent += 2;
	for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
		if (b0->type != CBLOCK_FUNC)
			continue;
		if (b0->auto_name)	/* skip all blocks with auto-generated names, i.e. name != human_name */
			continue;

		b1 = cblock_find_by_name(f1, &b0->name);

		if (b1) {
			kplog(LOG_DEBUG, "matching %.*s\n", b0->name.l, b0->name.s);
			log_indent += 2;
			b0->pair = b1; b1->pair = b0;
			cblock_func_match_labels(b0, b1, MATCH_ACTION_RENAME_ADD | MATCH_ACTION_RENAME_VERBOSE);
			rename_del(b0->f, &b0->name);
			cblock_make_new_name(b1, &b1->name, ".kpatch");
			cblock_make_new_name(b0, &b1->name, ".kpatch");
			log_indent -= 2;
		}
	}
	log_indent -= 2;

	/* --- begin of messing up with auto-generated names --- */
	/* can be safely removed - but patches will become bigger as auto-gen symbols will always be considered as new */

	/* Pass #2a: match the rest of functions with gcc-specific suffixes like func.part.NUM */
	kplog(LOG_DEBUG, "matching auto-generated symbols\n");
	log_indent += 2;
	cmp = 1;
	do {
		for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
			if (b0->type != CBLOCK_FUNC || b0->pair || !b0->auto_name)
				continue;

			b1 = cblock_find_by_human_name(f1, &b0->human_name);
			b1 = func_match_by_human_name(b0, b1, cmp);

			if (b1) {
				b0->pair = b1; b1->pair = b0;
				kplog(LOG_DEBUG, "matching %.*s <-> %.*s\n", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
				log_indent += 2;
				cblock_func_match_labels(b0, b1, MATCH_ACTION_RENAME_ADD | MATCH_ACTION_RENAME_VERBOSE);

				rename_del(b0->f, &b0->name);
				cblock_make_new_name(b1, &b1->name, ".kpatch");
				cblock_make_new_name(b0, &b1->name, ".kpatch");
//				rename_add(b1->f, &b1->name, &b0->name);
				log_indent -= 2;
			}
		}
	} while (cmp--);
	log_indent -= 2;

	/* matching can be false positive, e.g. in test.s we have fn.isra.1 -> fn.isra.0, but later it turns out that fn.isra.2 is different,
	 * so reference to it can't be the same and fn.isra.1 and .0 are not the same as a result */

	do {
		/* Pass #2b: rename all new functions to avoid conflicts with old names (needed for auto-generated names only, normal names always paired) */
		kplog(LOG_DEBUG, "renaming all new unmatched auto-generated symbols\n");
		log_indent += 2;
		for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
			if (b1->type != CBLOCK_FUNC || b1->pair)
				continue;
			if (rename_find(b1->f, &b1->name))	/* just to supress re-renames and logging due to loop below */
				continue;

			/* leave old names for normal functions. e.g. we want to reference to functions like kpatch_search_module_bugtables() by user name,
			 * but for auto-generated functions which are not global we have to rename to avoid possible conflicts */
			if (b1->auto_name)
				cblock_make_new_name(b1, &b1->name, ".kpatch");
			cblock_make_new_labels(b1);
		}
		log_indent -= 2;

		/* Pass #2c: after all renames done it can turn out that matches were false-positives, so we have to undo. this may lead to recursive unmatching */
		progress = 0;
#if 0
		for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
			if (b0->type != CBLOCK_FUNC || !b0->pair || !b0->auto_name)
				continue;

			b1 = b0->pair;
			kplog(LOG_DEBUG,"consider undo %.*s -> %.*s", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
			log_indent += 2;
			if (cblock_cmp(b0, b0->pair, CBLOCK_CMP_SECT|CBLOCK_CMP_RENAME)) {
				kplog(LOG_DEBUG, "undo matching %.*s -> %.*s", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
				cblock_func_match_labels(b0, b1, MATCH_ACTION_RENAME_DEL);
				rename_del(b1->f, &b1->name);
				b0->pair = NULL; b1->pair = NULL;
				progress = 1;
			}
			log_indent -= 2;
		}
#endif

	} while (progress);

	/* --- end of messing up with auto-generated names --- */

	/* Pass 3: unlink specific symbols as configured. this can be used e.g. if we want to change some code (e.g. freezer), but put the modified code
	 * to kpatch w/o patching real functions to modified ones. instead we want to use these changed code for our own private needs. */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type != CBLOCK_FUNC || !b1->pair)
			continue;

		if (in_syms_list(b1->f->basename, &b1->human_name, ignore_syms, nr_ignore_syms)) {
			rename_del(b1->f, &b1->name);
			rename_del(b1->pair->f, &b1->pair->name);
			b1->ignore = 1;
		}
		if (in_syms_list(b1->f->basename, &b1->human_name, unlink_syms, nr_unlink_syms)) {
			kplog(LOG_DEBUG, "unlinking %.*s\n", b1->name.l, b1->name.s);
			b1->unlink = 1;
		}
	}

	/* Pass 4: ignore all unchanged functions */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type != CBLOCK_FUNC || !b1->pair || b1->ignore)
			continue;

		b0 = b1->pair;
		kplog(LOG_DEBUG, "check content changes in symbol %.*s <-> %.*s\n", b0->name.l, b0->name.s, b1->name.l, b1->name.s);
		log_indent += 2;

		if (!cblock_cmp(b0, b1, CBLOCK_CMP_SECT|CBLOCK_CMP_RENAME)) {
			rename_del(b0->f, &b0->name);
			rename_del(b1->f, &b1->name);
			rename_add(b0->f, &b0->name, &b1->name);
			rename_add(b1->f, &b1->name, &b0->name);
			b1->ignore = 1;
		} else {
			if (!b1->adapted && in_syms_list(b1->f->basename, &b1->human_name, must_adapt_syms, nr_must_adapt_syms)) {
				not_adapted= 1;
				kplog(LOG_ERR, "FATAL! not adapted function change %.*s\n", b1->name.l, b1->name.s);
			}
			cblock_make_new_labels(b1);
		}

		log_indent -= 2;
	}
	if (not_adapted)
		kpfatal("not adapted function found\n");
}

static void analyze_other_cblocks(struct kp_file *f0, struct kp_file *f1)
{
	struct cblock *b0, *b1;

	/* Pass #1: match other blocks */
	b0 = cblock_skip(cblock_first(f0), CBLOCK_OTHER);
	b1 = cblock_skip(cblock_first(f1), CBLOCK_OTHER);
	while (b0 && b1) {
		if (!cblock_cmp(b0, b1, 0))
			goto done;

		/* split may be required e.g. when an almost empty file has a single cblock, while destination has 2 */
		if (b1->end - b1->start > b0->end - b0->start)
			cblock_split(b1, b0->end - b0->start);
		if (b0->end - b0->start > b1->end - b1->start)
			cblock_split(b0, b1->end - b1->start);

		if (cblock_cmp(b0, b1, 0))
			kpfatal("Blocks of type other mismatch %d-%d vs. %d-%d\n", clinenum(f0, b0->start), clinenum(f0, b0->end - 1),
					clinenum(f1, b1->start), clinenum(f1, b1->end - 1));
done:
		b0->pair = b1; b1->pair = b0;
		b0 = cblock_skip(cblock_next(b0), CBLOCK_OTHER);
		b1 = cblock_skip(cblock_next(b1), CBLOCK_OTHER);
	}
}

/* output of single block line with renames done if needed */
static void cblock_write_line(struct kp_file *fout, struct cblock *b, int l, int flags)
{
	char buf[2*BUFSIZE], buf2[2*BUFSIZE], *s;

	s = cline(b->f, l);
	if (flags & FLAG_RENAME) {
		str_do_rename(b->f, buf, s);
		s = buf;
	}
	if (flags & FLAG_GOTPCREL) {
		str_do_gotpcrel(b->f, buf2, s);
		s = buf2;
	}

	fprintf(fout->f, "%s", s);
	if (clinenum(b->f, l) != clinenum(b->f, l + 1))
		fprintf(fout->f, "\n");
	else if (s[strlen(s) - 1] != ':')
		fprintf(fout->f, "; ");
}

static void cblock_write(struct kp_file *fout, struct cblock *b, int flags)
{
	int i;

	for (i = b->start; i < b->end; i++)
		cblock_write_line(fout, b, i, flags);
}

static void cblock_write_other(struct kp_file *fout, struct cblock *b)
{
	cblock_write(fout, b, 0);
	b->handled = 1;
	if (b->pair)
		b->pair->handled = 1;
}

static void cblock_write_attr(struct kp_file *fout, struct cblock *b, struct cblock *bpair)
{
	cblock_write(fout, b, FLAG_RENAME);
	b->handled = 1;

	if (bpair) {
		b->pair = bpair; bpair->pair = b;
		bpair->handled = 1;
	}
}

static void cblock_write_var(struct kp_file *fout, struct cblock *b)
{
	fprintf(fout->f, "#---------- var ---------\n");
	/* if new variable became global, then mark the old one as well */
	if (b->pair && b->pair->globl && !b->globl)
		fprintf(fout->f, "\t.globl %.*s\n", b->name.l, b->name.s);
	cblock_write(fout, b, 0);
	b->handled = 1;
	if (b->pair)
		b->pair->handled = 1;
}

static void __cblock_gen(struct kp_file *fout, struct cblock *b, int flags)
{
	int i, t;

	for (i = b->start; i < b->end; i++) {
		t = ctype(b->f, i);
		switch (t) {
			case DIRECTIVE_TEXT:
			case DIRECTIVE_DATA:
			case DIRECTIVE_BSS:
			case DIRECTIVE_PUSHSECTION:
			case DIRECTIVE_SECTION:
			case DIRECTIVE_POPSECTION:
			case DIRECTIVE_PREVIOUS:
				if (i == b->start)
					break;		/* beautification: caller just pushed our section, so supress this useless section change again */
				change_section(fout, csect(b->f, i), 0);
				break;
			case DIRECTIVE_COMM:
				/* .comm implies .bss, while we need to put data to .kpatch.data, so deal with it */
				add_comm_cmd(fout, b->f, i, flags);
				break;
			default:
				cblock_write_line(fout, b, i, flags);
				break;
		}
	}
}

/* Add new code/data. Puts it into appropriate sections depending on the source section (.text/.data). */
static void cblock_gen(struct kp_file *fout, struct cblock *b, int flags)
{
	change_section(fout, csect(b->f, b->start), FLAG_PUSH_SECTION);
	if (force_global && b->type == CBLOCK_FUNC)
		fprintf(fout->f, "\t.globl\t%.*s.kpatch\n", b->name.l, b->name.s);
	__cblock_gen(fout, b, flags);
	if (b->type == CBLOCK_FUNC)
		fprintf(fout->f, "%.*s.kpatch_end:\n", b->name.l, b->name.s);
	fprintf(fout->f, "\t.popsection\n");
	b->handled = 1;
}

/* 32 bit binary can't contain 64 bit relocations.
 * thus we forced to split .quad to two .long on x86 */
static inline void pad2quad(struct kp_file *fout)
{
	if (arch_bits == 32)
		fprintf(fout->f, "\t.long 0\n");
}

static void write_new_function(struct kp_file *fout, struct cblock *b)
{
	static int nsyms = 0;
	char *s = b->name.s;
	int l = b->name.l;
	char *slong = (arch_bits == 32) ? ".long" : ".quad";
	struct rename *r = rename_find(b->f, &b->name);
	kpstr_t *bnm = r ? &r->dst : &b->name;
	int cblock_flags = FLAG_RENAME;

	if (force_gotpcrel)
		cblock_flags |= FLAG_GOTPCREL;
	cblock_gen(fout, b, cblock_flags);
	fprintf(fout->f, "\n");

	/* patch info */
	nsyms++;
	fprintf(fout->f, "\t.pushsection .kpatch.strtab,\"a\",@progbits\n");
	fprintf(fout->f, "kpatch_strtab%d:\n", nsyms);
	fprintf(fout->f, "\t.string \"%.*s\"\n", bnm->l, bnm->s);
	fprintf(fout->f, "\t.popsection\n");
	fprintf(fout->f, "\t.pushsection .kpatch.info,\"a\",@progbits\n");
	fprintf(fout->f, "%.*s.Lpi:\n", l, s);
	/* kpatch_info structure */
	/* daddr: */
	if (b->pair && !b->unlink) {
		fprintf(fout->f, "\t%s %.*s\n", slong,  b->pair->name.l, b->pair->name.s);
		pad2quad(fout);
	} else
		fprintf(fout->f, "\t.quad 0\n");
	/* saddr: */
	fprintf(fout->f, "\t%s %.*s\n", slong, bnm->l, bnm->s);
	pad2quad(fout);
	/* dlen: */
	if (b->pair && !b->unlink) {
		fprintf(fout->f, "\t.long %.*s.Lfe - %.*s\n",
		        b->pair->name.l, b->pair->name.s,
		        b->pair->name.l, b->pair->name.s);
	} else
		fprintf(fout->f, "\t.long 0\n");
	/* slen: */
	fprintf(fout->f, "\t.long %.*s.kpatch_end - %.*s\n", l, s, bnm->l, bnm->s);
	/* symstr: */
	fprintf(fout->f, "\t%s kpatch_strtab%d\n", slong, nsyms);
	pad2quad(fout);
	/* vaddr: */
	fprintf(fout->f, "\t.quad 0\n");
	/* flags: */
	fprintf(fout->f, "\t.long 0\n");
	/* pad[4]: */
	fprintf(fout->f, "\t.byte 0, 0, 0, 0\n");
	fprintf(fout->f, "\t.popsection\n");
	fprintf(fout->f, "\n");
}

static void cblock_write_func(struct kp_file *f0, struct kp_file *fout, struct cblock *b)
{
	/* write original function */
	kplog(LOG_TRACE, "cblock_write_func %.*s\n", b->name.l, b->name.s);
	log_indent += 2;

	fprintf(fout->f, "#---------- func ---------\n");
	/* if new function became global, then mark the old one as well */
	if (force_global || (b->pair && b->pair->globl && !b->globl))
		fprintf(fout->f, "\t.globl\t%.*s\n", b->name.l, b->name.s);
	cblock_write(fout, b, 0);
	b->handled = 1;

	/* write function patch if needed */
	if (b->pair) {
		b->pair->handled = 1;

		if (b->pair->ignore || b->pair->unlink)
			goto done;

		kplog(LOG_TRACE, "cblock_write_func pair %.*s\n", b->pair->name.l, b->pair->name.s);
		/* first put the end label, so we could refer to original function end */
		fprintf(fout->f, "%.*s.Lfe:\n", b->name.l, b->name.s);
		fprintf(fout->f, "#---------- kpatch begin ---------\n");
		write_new_function(fout, b->pair);
		fprintf(fout->f, "#---------- kpatch end -----------\n");
	}
done:
	log_indent -= 2;
}


static void write_cblocks(struct kp_file *f0, struct kp_file *f1, struct kp_file *fout)
{
	struct cblock *b0, *b1;

	/* Pass #0: write down file header (first other block) */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {	/* iterate over b1 since src#1 can be totally empty and have no header/footer */
		if (b1->type == CBLOCK_OTHER) {
			cblock_write_other(fout, b1);
			break;
		}
	}

	/* Pass #1: write down original code and variables */
	for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
		if (b0->type == CBLOCK_FUNC)
			cblock_write_func(f0, fout, b0);
		if (b0->type == CBLOCK_VAR)
			cblock_write_var(fout, b0);
	}

	/* Pass #2: write all new code/variables */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->pair)		/* paired blocks were already handled above */
			continue;
		if (b1->type == CBLOCK_FUNC) {
			fprintf(fout->f, "#---------- new func ---------\n");
			write_new_function(fout, b1);
		}
		if (b1->type == CBLOCK_VAR)
			cblock_gen(fout, b1, FLAG_RENAME);
	}

	/* Pass #2b: write down all unlinked blocks */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		/* rename all to make chained calls correct */
		if (b1->type == CBLOCK_FUNC && b1->unlink) {
			cblock_make_new_labels(b1);
			cblock_make_new_name(b1, &b1->name, ".kpatch");
		}
	}
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type == CBLOCK_FUNC && b1->unlink) {
			fprintf(fout->f, "#---------- unlinked func ---------\n");
			write_new_function(fout, b1);
		}
	}

	/* footnotes... */

	/* Pass #3: write down all weak definitions blocks */
	for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
		if (b0->type == CBLOCK_ATTR)
			cblock_write_attr(fout, b0, cblock_find_by_name(f1, &b0->name));
	}
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type == CBLOCK_ATTR && !b1->handled)
			cblock_write_attr(fout, b1, cblock_find_by_name(f0, &b1->name));
	}

	/* Pass #4: write down all other blocks (footnote) */
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (b1->type == CBLOCK_OTHER && !b1->handled)
			cblock_write_other(fout, b1);
	}

	/* Pass #5: verify that no blocks were left unnoticed */
	for (b0 = cblock_first(f0); b0; b0 = cblock_next(b0)) {
		if (!b0->handled)
			kpfatal("Unhandled block left %d:%d-%d\n", b0->f->id, clinenum(b0->f, b0->start), clinenum(b0->f, b0->end));
	}
	for (b1 = cblock_first(f1); b1; b1 = cblock_next(b1)) {
		if (!b1->handled)
			kpfatal("Unhandled block left %d:%d-%d\n", b1->f->id, clinenum(b1->f, b1->start), clinenum(b1->f, b1->end));
	}
}

static void parse_sym_list(struct sym_desc *syms, int *nr_syms)
{
	char *tok;
	int sym_idx;

	tok = strtok(optarg, ",");
	while (tok) {
		sym_idx = *nr_syms;
		syms[sym_idx].sym = strchr(tok, ':');

		if (syms[sym_idx].sym) {
			*syms[sym_idx].sym = 0;
			syms[sym_idx].sym++;
			syms[sym_idx].filename = tok;
		} else {
			syms[sym_idx].sym = tok;
			syms[sym_idx].filename = NULL;
		}
		(*nr_syms)++;
		tok = strtok(NULL, ",");
	}
}

static void usage(void)
{
	kplog(LOG_ERR, "Usage:");
	kplog(LOG_ERR, "kpatch_gensrc [-d loglevel] [--os=rhel5|rhel6] --dbg-filter [--dbg-filter-eh-frame] -i <input1> -o <output-asm>");
	kplog(LOG_ERR, "    to filter out debug information and commands from asm file");
	kplog(LOG_ERR, "kpatch_gensrc [-d loglevel] [--arch=i686|x86_64] [--os=rhel5|rhel6] [--ignore-changes=FLIST] [--unlink-symbols=FLIST]");
	kplog(LOG_ERR, "              [--must-adapt=FLIST] -i <input1> -i <input2> -o <output-asm>");
	kplog(LOG_ERR, "    to compare 2 asm files and generate a kpatch'ed resuling asm");
	kplog(LOG_ERR, "Options:");
	kplog(LOG_ERR, " --dbg-filter-eh-frame - on RHEL 5 GCC can place references to CFI data in .eh_frame section, which lead to");
	kplog(LOG_ERR, "    reference to undefined synbols, since we filter out CFI data in dbgfilter. With this option .eh_frame");
	kplog(LOG_ERR, "    sections also filtered.");
	kplog(LOG_ERR, " --ignore-changes=FLIST - ignore ANY change happened in functions listed in FLIST. This is needed due to lack of");
	kplog(LOG_ERR, "    https://gcc.gnu.org/ml/gcc-patches/2013-10/msg02082.html in some supported compilers.");
	kplog(LOG_ERR, " --unlink-symbols=FLIST - this feature allow some functions to be unlinked from it destination, this allow us to");
	kplog(LOG_ERR, "    create modified copies of this functions which can be used in patch without interference to system. Primary");
	kplog(LOG_ERR, "    usecase was to modify system freezer and use it copy in kpatch. Not used in this way because smart freezer");
	kplog(LOG_ERR, "    doesn't need freezer modifications.");
	kplog(LOG_ERR, " --must-adapt=FLIST - list of functions which should be marked with KPGENSRC_ADAPTED flag at source code level.");
	kplog(LOG_ERR, "    If 'not adapted' function found, error occur. This option is helpful in cases when function can be patched");
	kplog(LOG_ERR, "    but it always require adoptation, for example vmx_vcpu_run().");
	kplog(LOG_ERR, " --force-gotpcrel - rewrites patch code to force use of the @GOTPCREL relocations so the patch can be loaded");
	kplog(LOG_ERR, "    at a random 32-bit offset. Used in user-space patching.");
	kplog(LOG_ERR, " --force-global - marks all function used in patch as global so the compiler will generate correct relocation");
	kplog(LOG_ERR, "    for .kpatch.info section. Used in user-space patching.");
	kplog(LOG_ERR, "FLIST format:");
	kplog(LOG_ERR, " FLIST is comma separated list of function names which can be prepanded with filename where this function defined.");
	exit(1);
}

enum {
	DBG_FILTER_EH_FRAME = 130,
	DBG_FILTER_GCC_EXCEPTION_TABLE,
	DBG_FILTER_CFI,
	DBG_FILTER_EMIT_NEWLINES,
	IGNORE_CHANGES,
	UNLINK_SYMBOLS,
	MUST_ADAPT,
	FORCE_GOTPCREL,
	FORCE_GLOBAL,
};

struct option long_opts[] = {
	{"debug", 1, 0, 'd'},
	{"os", 1, 0, 'O'},
	{"arch", 1, 0, 'a'},
	{"input", 1, 0, 'i'},
	{"ouput", 1, 0, 'o'},
	{"dbg-filter", 0, 0, 'f'},
	{"dbg-filter-eh-frame", 0, 0, DBG_FILTER_EH_FRAME},
	{"dbg-filter-gcc-except-table", 0, 0, DBG_FILTER_GCC_EXCEPTION_TABLE},
	{"dbg-filter-cfi", 0, 0, DBG_FILTER_CFI},
	{"dbg-filter-emit-newlines", 0, 0, DBG_FILTER_EMIT_NEWLINES},
	{"ignore-changes", 1, 0, IGNORE_CHANGES},
	{"unlink-symbols", 1, 0, UNLINK_SYMBOLS},
	{"must-adapt",  1, 0, MUST_ADAPT},
	{"force-gotpcrel", 0, 0, FORCE_GOTPCREL},
	{"force-global", 0, 0, FORCE_GLOBAL},
	{}
};

int main(int argc, char **argv)
{
	int err, ch, k = 0, dbgfilter = 0, dbgfilter_options = 0;
	struct kp_file infile[2], outfile;

	while ((ch = getopt_long(argc, argv, "d:O:i:o:a:f", long_opts, 0)) != -1) {
		switch (ch) {
		case 'd':
			sscanf(optarg, "%x", &log_level);
			break;
		case 'i':
			if (k >= 2)
				kpfatal("only 2 input files must be specified\n");
			if ((err = read_file(&infile[k], optarg)))
				kpfatal("Can't read input file '%s': %s\n", optarg, strerror(err));
			infile[k].id = k;
			k++;
			break;
		case 'o':
			if ((err = create_file(&outfile, optarg)))
				kpfatal("Can't open output file '%s': %s\n", optarg, strerror(err));
			break;
		case 'O':
			if (!strcmp(optarg, "rhel5")) os = OS_RHEL5;
			if (!strcmp(optarg, "rhel6")) os = OS_RHEL6;
			break;
		case 'a':
			if (!strcmp(optarg, "i686")) {arch = ARCH_X86_32; arch_bits = 32;}
			if (!strcmp(optarg, "x86_64")) {arch = ARCH_X86_64; arch_bits = 64;}
			break;
		case 'f':
			dbgfilter = 1;
			break;
		case DBG_FILTER_EH_FRAME:
			dbgfilter_options |= DFO_SKIP_EH_FRAME;
			break;
		case DBG_FILTER_GCC_EXCEPTION_TABLE:
			dbgfilter_options |= DFO_SKIP_GCC_EXCEPT_TABLE;
			break;
		case DBG_FILTER_CFI:
			dbgfilter_options |= DFO_SKIP_CFI;
			break;
		case DBG_FILTER_EMIT_NEWLINES:
			dbgfilter_options |= DFO_EMIT_NEWLINES;
			break;
		case IGNORE_CHANGES:
			parse_sym_list(ignore_syms, &nr_ignore_syms);
			break;
		case UNLINK_SYMBOLS:
			parse_sym_list(unlink_syms, &nr_unlink_syms);
			break;
		case MUST_ADAPT:
			parse_sym_list(must_adapt_syms, &nr_must_adapt_syms);
			break;
		case FORCE_GOTPCREL:
			force_gotpcrel = 1;
			break;
		case FORCE_GLOBAL:
			force_global = 1;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	if (dbgfilter) {
		if (k < 1)
			kpfatal("input file must be specified\n");

		init_multilines(&infile[0]);
		debug_filter(&infile[0], &outfile, dbgfilter_options);
		close_file(&outfile);
		return 0;
	}

	if (k < 2)
		kpfatal("2 input files must be specified\n");

	init_multilines(&infile[0]);	init_multilines(&infile[1]);
	init_ctypes(&infile[0]);	init_ctypes(&infile[1]);
	init_sections(&infile[0]);	init_sections(&infile[1]);
	cblocks_init(&infile[0]);	cblocks_init(&infile[1]);

	analyze_var_cblocks(&infile[0], &infile[1]);
	analyze_func_cblocks(&infile[0], &infile[1]);
	analyze_other_cblocks(&infile[0], &infile[1]);
	write_cblocks(&infile[0], &infile[1], &outfile);
	close_file(&outfile);

	return 0;
}
