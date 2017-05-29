#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <libgen.h>

#include "kpatch_log.h"
#include "kpatch_io.h"
#include "kpatch_str.h"

void *kp_realloc(void *p, int oldsz, int newsz)
{
	void *p2;

	p2 = malloc(newsz);
	if (p2 == NULL)
		kpfatal("failed to allocate %d bytes", newsz);

	if (p) {
		int sz = (oldsz > newsz) ? newsz : oldsz;
		memcpy(p2, p, sz);
		free(p);
	}

	return p2;
}

int read_file(struct kp_file *file, char *fname)
{
	int sz = 64;
	char buf[BUFSIZE];

	memset(file, 0, sizeof(*file));
	if (!strcmp(fname, "-"))
		file->f = stdin;
	else
		file->f = fopen(fname, "rt");

	file->rpath = realpath(fname, NULL);
	if (!file->rpath)
		file->rpath = "";
	file->dirname = strdup(file->rpath);
	file->dirname = dirname(file->dirname);
	file->basename = strdup(file->rpath);
	file->basename = basename(file->basename);

	if (!file->f)
		return errno;

	file->nr_lines = 1;
	while (1) {
		if (file->nr_lines >= sz || !file->lines) {
			sz *= 2;
			file->lines = kp_realloc(file->lines, (sz/2) * sizeof(char *), sz * sizeof(char *));
		}

		if (!fgets(buf, BUFSIZE, file->f))
			break;

		trim_crlf(buf);
		file->lines[file->nr_lines++] = strdup(buf);
	}
	file->lines[0] = "";	/* make line with index 0 to be empty, so that our line numbers would match and editor for easier debugging, i.e. we start from index=1 */
	fclose(file->f);
	return 0;
}

int create_file(struct kp_file *file, char *fname)
{
	if (!strcmp(fname, "-")) {
		file->f = stdout;
		return 0;
	}

	file->f = fopen(fname, "wt");
	if (!file->f)
		return errno;
	return 0;
}

void close_file(struct kp_file *file)
{
	fclose(file->f);
}
