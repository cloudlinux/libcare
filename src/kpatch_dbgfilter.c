#include <stdio.h>
#include <stdlib.h>

#include "kpatch_parse.h"
#include "kpatch_str.h"
#include "kpatch_dbgfilter.h"

static int is_cold_hot(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	return !kpstrncmpz(&t, ".LCOLD") || !kpstrncmpz(&t, ".LHOT");
}

/* matches comments starting from '#' */
static int is_comment(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	return !kpstrncmpz(&t, "#");
}

/* matches '.loc' */
static int is_loc_cmd(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	return !kpstrcmpz(&t, ".loc");
}

/* matches '.file n' */
static int is_file_cmd(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	if (kpstrcmpz(&t, ".file"))
		return 0;

	if (!s || !isdigit(*s))
		return 0;

	return 1;
}

/* matches '.cfi*' */
static int is_cfi_cmd(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	if (kpstrncmpz(&t, ".cfi"))
		return 0;

	return 1;
}

/* matches some gcc specific debug labels */
static int is_debug_lbl(char *s)
{
	kpstr_t t;
	get_token(&s, &t);
	return !kpstrncmpz(&t, ".LBB") || !kpstrncmpz(&t, ".LBE") || !kpstrncmpz(&t, ".LFB") ||
		!kpstrncmpz(&t, ".LCFI") || !kpstrncmpz(&t, ".LFE") || !kpstrncmpz(&t, ".LVL");
}

/* gcc generates the following sequence with debug info:
 *	.text (optional)
 *	.Ltext0:
 * and the same with .Letext0 label. Match it.
 */
static int skip_ltext_lbl(struct kp_file *f, int l, char *s)
{
	kpstr_t t;
	int n = 0;

	get_token(&s, &t);
	if (!kpstrcmpz(&t, ".text"))
		{l++; n++;}

	s = cline(f, l + n);
	get_token(&s, &t);
	if (kpstrncmpz(&t, ".Ltext") && kpstrncmpz(&t, ".Letext"))
		return 0;

	return n + 1;
}

static int is_section_start(char *s, char *prefix)
{
	kpstr_t t;
	int type;

	if (!s)
		return 0;

	type = parse_ctype(s, false);
	if (type == DIRECTIVE_SECTION) {
		get_token(&s, &t);
		get_token(&s, &t);
		if (!kpstrncmpz(&t, prefix))
			return 1;
	}
	return 0;
}

static int is_section_end(char *s, int *pl)
{
	int type;

	if (!s)
		return 1;

	/* skip all aligns, labels and data defs in section - we will filter it out */
	type = parse_ctype(s, false);
	if (type == DIRECTIVE_PREVIOUS) {
		(*pl)++;
		return 1;
	}

	if (type != DIRECTIVE_ALIGN &&
	    type != DIRECTIVE_LABEL &&
	    type != DIRECTIVE_LOCAL_LABEL &&
	    !is_data_def(s, type))
		return 1;
	return 0;
}

static int skip_section(struct kp_file *f, int l0, char *prefix)
{
	int l = l0;
	while (is_section_start(cline(f, l), prefix)) {
		l++;
		while (!is_section_end(cline(f, l), &l))
			l++;
	}
	return l - l0;
}

static inline int skip_debug_section(struct kp_file *f, int l0)
{
	return skip_section(f, l0, ".debug_");
}

static inline int skip_eh_frame_section(struct kp_file *f, int l0)
{
	return skip_section(f, l0, ".eh_frame");
}

static inline int skip_gcc_except_table(struct kp_file *f, int l0)
{
	return skip_section(f, l0, ".gcc_except_table");
}

/* function returns a number of lines to be removed from the tail of the file */
static int debug_filter_skip(struct kp_file *f, int l, int options)
{
	char *s = cline(f, l);
	int n;

	if (is_cold_hot(s))
		return 1;
	if (is_comment(s))
		return 1;
	if (is_loc_cmd(s))
		return 1;
	if (is_file_cmd(s))
		return 1;
	if (is_debug_lbl(s))
		return 1;
	if ((options & DFO_SKIP_CFI) && is_cfi_cmd(s))
		return 1;
	if ((n = skip_ltext_lbl(f, l, s)))
		return n;
	if ((n = skip_debug_section(f, l)))
		return n;
	if (options & DFO_SKIP_EH_FRAME)
		if ((n = skip_eh_frame_section(f, l)))
			return n;
	if (options & DFO_SKIP_GCC_EXCEPT_TABLE)
		if ((n = skip_gcc_except_table(f, l)))
			return n;
	return 0;
}

void debug_filter(struct kp_file *fin, struct kp_file *fout, int options)
{
	int i, n;

	for (i = 1; i < fin->nr_lines;) {
		n = debug_filter_skip(fin, i, options);
		if (n == 0) {
			const char *s = cline(fin, i);
			fprintf(fout->f, "%s", s);

			if (clinenum(fin, i) != clinenum(fin, i + 1))
				fprintf(fout->f, "\n");
			else if (s[strlen(s) - 1] != ':')
				fprintf(fout->f, "; ");
		}
		i += n ?: 1;

		if (options & DFO_EMIT_NEWLINES) {
			if (n > 16)
				n = 1;
			while (n-- > 0)
				fprintf(fout->f, "\n");
		}
	}
}
