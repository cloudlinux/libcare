#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_log.h"

int kpatch_openat_file(int atfd, const char *fname, struct kp_file *kpatch)
{
	int fd;

	if (!kpatch)
		return -1;

	if (atfd == AT_FDCWD)
		kpdebug("Opening patch file '%s'...", fname);
	else
		kpdebug("Opening patch file '%s' at dirfd %d...", fname, atfd);
	fd = openat(atfd, fname, O_RDONLY);
	if (fd == -1) {
		kpdebug("FAIL: %s\n", strerror(errno));
		return -1;
	}
	if (kpatch_open_fd(fd, kpatch) < 0)
		goto error;
	kpdebug("OK\n");
	close(fd);
	return 0;
error:
	close(fd);
	return -1;
}

int kpatch_open_fd(int fd, struct kp_file *kpatch)
{
	struct stat st;

	kpdebug("OK\nQuerying file size...");
	if (fstat(fd, &st) == -1) {
		kpdebug("FAIL: %s\n", strerror(errno));
		return -1;
	}
	kpdebug("OK\nMapping patch file...");
	kpatch->size = st.st_size;
	kpatch->patch = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (kpatch->patch == MAP_FAILED) {
		kpdebug("FAIL: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int kpatch_open_file(const char *fname, struct kp_file *kpatch)
{
	return kpatch_openat_file(AT_FDCWD, fname, kpatch);
}

int kpatch_close_file(struct kp_file *kpatch)
{
	return munmap(kpatch->patch, kpatch->size);
}
