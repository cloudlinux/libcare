#ifndef __PARSE_H__
#define __PARSE_H__

#include <stdbool.h>

#include "kpatch_log.h"
#include "kpatch_io.h"
#include "kpatch_str.h"
#include "rbtree.h"

/* fetch code line */
char *cline(struct kp_file *f, int l);
int clinenum(struct kp_file *f, int l);

/* ------------------------------------------- as directives ---------------------------------------- */

#define DIRECTIVE_ALIGN		1
#define DIRECTIVE_TYPE		2
#define DIRECTIVE_COMM		3
#define DIRECTIVE_WEAK		4
#define DIRECTIVE_SIZE		5
#define DIRECTIVE_LABEL		6
#define DIRECTIVE_LOCAL_LABEL	7

#define DIRECTIVE_GLOBL		10
#define DIRECTIVE_LOCAL		11
#define DIRECTIVE_HIDDEN	12
#define DIRECTIVE_PROTECTED	13
#define DIRECTIVE_INTERNAL	14

#define DIRECTIVE_TEXT		20
#define DIRECTIVE_DATA		21
#define DIRECTIVE_BSS		22

#define DIRECTIVE_SECTION	30
#define DIRECTIVE_PUSHSECTION	31
#define DIRECTIVE_POPSECTION	32
#define DIRECTIVE_SUBSECTION	33
#define DIRECTIVE_PREVIOUS	34

#define DIRECTIVE_COMMENT	40
#define DIRECTIVE_SET		41

#define DIRECTIVE_OTHER		100

#define DIRECTIVE_KPFLAGS	500

void init_multilines(struct kp_file *f);

void init_ctypes(struct kp_file *f);
int ctype(struct kp_file *f, int l);
int is_sect_cmd(struct kp_file *f, int l);

int parse_ctype(char *s, bool with_checks);

/* ----------------------------------------- sections ----------------------------------------- */

/* we keep a separate structure for each code block whichs allows to track previous section easily.
 * yet we have to track all possible sections ever indexed by name for correct attributes / type handling */
struct section_desc {
	char *name;
	char *outname;				/* name how to put this in result output */
#define SECTION_EXECUTABLE		0x10000000
	int type;				/* SECTION_XXX */
	struct rb_node rbnm;			/* sorted by name list */
	struct section_desc *prev;		/* previous section for .popsection / .previous */
};

struct section_desc *find_section(char *name);
struct section_desc *csect(struct kp_file *f, int l);
void init_sections(struct kp_file *f);

int is_data_sect(struct section_desc *sect);
int is_code_sect(struct section_desc *sect);

/* --------------------------------------- code blocks ----------------------------------------- */
/*
 * echo code block describes some object in asm file: function or data variable.
 * it has a name, line range [start; end) and a link to matched cblock in another file (if any).
 */
struct cblock {
	struct kp_file *f;	/* file */
	int start, end;		/* line numbers [start;end) */

	kpstr_t name;
	kpstr_t human_name;
	char auto_name;		/* auto names = (name != human_name), e.g. fn.isra.2 */

#define CBLOCK_FUNC	1
#define CBLOCK_VAR	2
#define CBLOCK_ATTR	3
#define CBLOCK_OTHER	4
	char type;		/* function, variable or smth else */
	char globl;		/* whether symbol is global */
	char handled;		/* whether this block was handled and output already */
	char ignore;		/* ignore changes in this symbol */
	char unlink;		/* unlink this symbol and do not patch */
	char adapted;		/* this block marked with KPATCH_ADAPTED at source code level */

	struct cblock *pair;	/* matched cblock in another file */
	struct rb_node rbnm, rb_hnm, rbs;
};

void get_token(char **str, kpstr_t *x);
void __get_token(char **str, kpstr_t *x, const char *delim);

int is_function_start(struct kp_file *f, int l, kpstr_t *nm);
int is_function_end(struct kp_file *f, int l, kpstr_t *nm);

int is_variable_start(struct kp_file *f, int l, int *e, int *globl, kpstr_t *nm);
int is_data_def(char *s, int type);

struct cblock *cblock_find_by_name(struct kp_file *f, kpstr_t *nm);
struct cblock *cblock_find_by_human_name(struct kp_file *f, kpstr_t *nm);
void cblocks_init(struct kp_file *f);
void cblock_print2(struct cblock *b0, struct cblock *b1);
struct cblock *cblock_first(struct kp_file *f);
struct cblock *cblock_next(struct cblock *blk);
struct cblock *cblock_skip(struct cblock *blk, int type);
void cblock_split(struct cblock *b, int len);

#endif /* __PARSE_H__ */
