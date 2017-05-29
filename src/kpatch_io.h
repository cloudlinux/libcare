#ifndef __KP_IO_H__
#define __KP_IO_H__

#include "kpatch_log.h"
#include "rbtree.h"

#define BUFSIZE		65536

struct kp_file {
	int id;

	FILE *f;
	char *rpath;
	char *dirname;
	char *basename;
	int nr_lines;
	char **lines;
	int *lines_num; /* original line numbers */

	int *ctype;
	void **section;

	struct rb_root cblocks_by_name;
	struct rb_root cblocks_by_human_name;
	struct rb_root cblocks_by_start;
	struct rb_root renames;
};

int read_file(struct kp_file *f, char *fname);
int create_file(struct kp_file *f, char *fname);
void close_file(struct kp_file *f);
void *kp_realloc(void *p, int oldsz, int newsz);

#endif /* __KP_IO_H__ */
