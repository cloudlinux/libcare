#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <gelf.h>

#include "kpatch_storage.h"
#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "kpatch_ptrace.h"
#include "list.h"
#include "kpatch_log.h"


/*****************************************************************************
 * Patch storage subroutines.
 ****************************************************************************/

static int
patch_file_verify(struct kp_file *kpfile)
{
	GElf_Ehdr *hdr;
	struct kpatch_file *k = kpfile->patch;
	ssize_t size = kpfile->size;

	kpdebug("Verifying patch for '%s'...", k->modulename);

	if (memcmp(k->magic, KPATCH_FILE_MAGIC1, sizeof(k->magic))) {
		kperr("'%s' patch is invalid: Invalid magic.\n",
		      k->modulename);
		return -1;
	}
	if (k->total_size > size) {
		kperr("'%s' patch is invalid: Invalid size: %u/%ld.\n",
		      k->modulename, k->total_size, size);
		return -1;
	}
	hdr = (void *)k + k->kpatch_offset;
	if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) ||
			hdr->e_type != ET_REL ||
			hdr->e_shentsize != sizeof(GElf_Shdr)) {
		kperr("'%s' patch is invalid: Wrong ELF header or not ET_REL\n",
		      k->modulename);
		return -1;
	}
	kpdebug("OK\n");
	return 1;
}

int storage_init(kpatch_storage_t *storage,
	     const char *fname)
{
	int patch_fd = -1;
	struct stat stat = { .st_mode = 0 };

	if (fname != NULL) {
		patch_fd = open(fname, O_RDONLY | O_CLOEXEC);
		if (patch_fd < 0)
			goto out_err;

		if (fstat(patch_fd, &stat) < 0)
			goto out_close;
	}

	storage->patch_fd = patch_fd;
	storage->is_patch_dir = S_ISDIR(stat.st_mode);
	storage->path = NULL;

	if (storage->is_patch_dir) {
		rb_init(&storage->tree);
	} else {
		int ret;

		ret = kpatch_open_fd(storage->patch_fd, &storage->patch.kpfile);
		if (ret < 0)
			goto out_close;

		ret = patch_file_verify(&storage->patch.kpfile);
		if (ret < 0) {
			kpatch_close_file(&storage->patch.kpfile);
			goto out_close;
		}
		strcpy(storage->patch.buildid, storage->patch.kpfile.patch->uname);
	}

	storage->path = strdup(fname);

	return 0;

out_close:
	close(patch_fd);
out_err:
	kplogerror("cannot open storage '%s'\n", fname);
	return -1;
}

static void
free_storage_patch_cb(struct rb_node *node)
{
	struct kpatch_storage_patch *patch;

	patch = rb_entry(node, struct kpatch_storage_patch, node);
	kpatch_close_file(&patch->kpfile);

	free(patch->desc);
	free(patch);
}

void storage_free(kpatch_storage_t *storage)
{
	close(storage->patch_fd);
	if (storage->is_patch_dir)
		rb_destroy(&storage->tree, free_storage_patch_cb);
	free(storage->path);
}

static int
cmp_buildid(struct rb_node *node, unsigned long key)
{
	const char *bid = (const char *)key;
	struct kpatch_storage_patch *patch;

	patch = rb_entry(node, struct kpatch_storage_patch, node);

	return strcmp(patch->buildid, bid);
}

#define PATCHLEVEL_TEMPLATE_NUM	0

static char *pathtemplates[] = {
	"%s/latest/kpatch.bin",
	"%s.kpatch"
};

static int
readlink_patchlevel(int dirfd, const char *fname)
{
	ssize_t r;
	char buf[32];

	*strrchr(fname, '/') = '\0';
	r = readlinkat(dirfd, fname, buf, sizeof(buf));
	if (r > 0 && r < 32) {
		buf[r] = '\0';
		return atoi(buf);
	} else if (r >= 32) {
		r = -1;
		errno = ERANGE;
	}

	kplogerror("can't readlink '%s' to find patchlevel\n",
		   fname);
	return -1;
}

static inline int
storage_open_patch(kpatch_storage_t *storage,
		   const char *buildid,
		   struct kpatch_storage_patch* patch)
{
	char fname[96];
	int i, rv;

	for (i = 0; i < ARRAY_SIZE(pathtemplates); i++) {
		sprintf(fname, pathtemplates[i], buildid);

		rv = kpatch_openat_file(storage->patch_fd, fname, &patch->kpfile);
		if (rv == 0) {
			rv = patch_file_verify(&patch->kpfile);

			if (rv < 0)
				kpatch_close_file(&patch->kpfile);
			else
				rv = PATCH_FOUND;
			break;
		}
	}

	if (rv == PATCH_FOUND && i == PATCHLEVEL_TEMPLATE_NUM) {
		rv = readlink_patchlevel(storage->patch_fd, fname);
		if (rv < 0) {
			rv = PATCH_OPEN_ERROR;
			kpatch_close_file(&patch->kpfile);
		} else {
			patch->patchlevel = rv;
			patch->kpfile.patch->user_level = patch->patchlevel;
			rv = PATCH_FOUND;
		}

	}

	return rv;
}

static inline int
storage_stat_patch(kpatch_storage_t *storage,
		   const char *buildid,
		   struct kpatch_storage_patch* patch)
{
	char fname[96];
	struct stat buf;
	int i, rv;

	for (i = 0; i < ARRAY_SIZE(pathtemplates); i++) {
		sprintf(fname, pathtemplates[i], buildid);

		rv = fstatat(storage->patch_fd, fname, &buf, /* flags */ 0);

		if (rv == 0) {
			rv = PATCH_FOUND;
			patch->kpfile.size = buf.st_size;
			break;
		} else if (rv < 0 && errno == ENOENT) {
			rv = PATCH_NOT_FOUND;
		}
	}

	if (rv == PATCH_FOUND && i == PATCHLEVEL_TEMPLATE_NUM) {
		rv = readlink_patchlevel(storage->patch_fd, fname);
		if (rv < 0) {
			rv = PATCH_OPEN_ERROR;
		} else {
			patch->patchlevel = rv;
			rv = PATCH_FOUND;
		}
	}

	return rv;
}

/*
 * TODO(pboldin) I duplicate a lot of code kernel has for filesystems already.
 * Should we avoid this caching at all?
 */
#define ERR_PATCH ((struct kpatch_storage_patch *)1)
static struct kpatch_storage_patch *
storage_get_patch(kpatch_storage_t *storage, const char *buildid,
		  int load)
{
	struct kpatch_storage_patch *patch = NULL;
	struct rb_node *node;
	int rv;

	if (!storage->is_patch_dir) {
		if (!strcmp(storage->patch.buildid, buildid)) {
			return &storage->patch;
		}
		return NULL;
	}

	/* Look here, could be loaded already */
	node = rb_search_node(&storage->tree, cmp_buildid,
			      (unsigned long)buildid);
	if (node != NULL)
		return rb_entry(node, struct kpatch_storage_patch, node);

	/* OK, look at the filesystem */
	patch = malloc(sizeof(*patch));
	if (patch == NULL)
		return ERR_PATCH;

	memset(patch, 0, sizeof(*patch));
	patch->patchlevel = -1;
	init_kp_file(&patch->kpfile);

	if (load)
		rv = storage_open_patch(storage, buildid, patch);
	else
		rv = storage_stat_patch(storage, buildid, patch);

	if (rv == PATCH_OPEN_ERROR) {
		free(patch);
		return ERR_PATCH;
	}

	strcpy(patch->buildid, buildid);

	rb_insert_node(&storage->tree,
		       &patch->node,
		       cmp_buildid,
		       (unsigned long)patch->buildid);

	return patch;
}

int storage_patch_found(struct kpatch_storage_patch *patch)
{
	return patch && patch->kpfile.size >= 0;
}

static int
storage_load_patch(kpatch_storage_t *storage, const char *buildid,
		   struct kp_file **pkpfile)
{
	struct kpatch_storage_patch *patch = NULL;

	if (pkpfile == NULL) {
		kperr("pkpfile == NULL\n");
		return PATCH_OPEN_ERROR;
	}

	patch = storage_get_patch(storage, buildid, /* load */ 1);
	if (patch == ERR_PATCH)
		return PATCH_OPEN_ERROR;
	if (patch == NULL)
		return PATCH_NOT_FOUND;

	*pkpfile = &patch->kpfile;

	return storage_patch_found(patch) ? PATCH_FOUND : PATCH_NOT_FOUND;
}

int storage_have_patch(kpatch_storage_t *storage, const char *buildid,
		   struct kpatch_storage_patch **ppatch)
{
	struct kpatch_storage_patch *patch = NULL;

	if (ppatch)
		*ppatch = NULL;

	patch = storage_get_patch(storage, buildid, /* load */ 0);
	if (patch == ERR_PATCH)
		return PATCH_OPEN_ERROR;

	if (!storage_patch_found(patch))
		return PATCH_NOT_FOUND;

	if (ppatch)
		*ppatch = patch;
	return PATCH_FOUND;
}

char *storage_get_description(kpatch_storage_t *storage,
			struct kpatch_storage_patch *patch)
{
	char *desc = NULL;
	char path[PATH_MAX];
	int fd, rv, alloc = 0, sz = 0;

	if (!storage->is_patch_dir)
		return NULL;

	if (patch->desc)
		return patch->desc;

	sprintf(path, "%s/%d/description", patch->buildid, patch->patchlevel);
	fd = openat(storage->patch_fd, path, O_RDONLY);
	if (fd == -1)
		return NULL;

	while (1) {
		if (sz + 1024 >= alloc) {
			char *olddesc = desc;
			alloc += PAGE_SIZE;

			desc = malloc(alloc);

			if (olddesc != NULL) {
				memcpy(desc, olddesc, sz);
				free(olddesc);
			}

			olddesc = desc;
		}

		rv = read(fd, desc + sz, alloc - sz);
		if (rv == -1 && errno == EINTR)
			continue;

		if (rv == -1)
			goto err_free;

		if (rv == 0) {
			desc[sz] = '\0';
			break;
		}

		sz += rv;
	}

	patch->desc = desc;

	return desc;

err_free:
	free(desc);
	close(fd);
	return NULL;
}

int storage_lookup_patches(kpatch_storage_t *storage, kpatch_process_t *proc)
{
	struct kp_file *pkpfile;
	struct object_file *o;
	const char *bid;
	int found = 0, ret;

	list_for_each_entry(o, &proc->objs, list) {
		if (!o->is_elf || is_kernel_object_name(o->name))
			continue;

		bid = kpatch_get_buildid(o);
		if (bid == NULL) {
			kpinfo("can't get buildid for %s\n",
			       o->name);
			continue;
		}

		ret = storage_load_patch(storage, bid, &pkpfile);
		if (ret == PATCH_OPEN_ERROR) {
			if (errno != ENOENT)
				kplogerror("error finding patch for %s (%s)\n",
					   o->name, bid);
			continue;
		}

		if (ret == PATCH_FOUND) {
			o->skpfile = pkpfile;
			found++;
		}
	}

	kpinfo("%d object(s) have valid patch(es)\n", found);

	kpdebug("Object files dump:\n");
	list_for_each_entry(o, &proc->objs, list)
		kpatch_object_dump(o);

	return found;
}

static int
storage_execute_script(kpatch_storage_t *storage,
		       kpatch_process_t *proc,
		       const char *name)
{
	int childpid, rv = 0, status;
	char pidbuf[16], pathbuf[PATH_MAX];

	if (!storage->is_patch_dir)
		return 0;

	sprintf(pathbuf, "%s/%s", storage->path, name);

	rv = access(pathbuf, X_OK);
	/* No file -- no problems */
	if (rv < 0)
		return errno == ENOENT ? 0 : -1;

	sprintf(pidbuf, "%d", proc->pid);

	childpid = fork();
	if (childpid == 0) {
		rv = execl(pathbuf, name, pidbuf, NULL);
		if (rv < 0)
			kplogerror("execl failed\n");
		exit(EXIT_FAILURE);
	} else {
		rv = waitpid(childpid, &status, 0);
		if (rv < 0)
			kplogerror("waitpid failed for %d\n", childpid);

		if (WIFEXITED(status))
			rv = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			rv = WTERMSIG(status);
		if (rv)
			kperr("child script failed %d\n", rv);
	}

	return -rv;
}

int storage_execute_before_script(kpatch_storage_t *storage, kpatch_process_t *proc)
{
	return storage_execute_script(storage, proc, "before");
}

int storage_execute_after_script(kpatch_storage_t *storage, kpatch_process_t *proc)
{
	return storage_execute_script(storage, proc, "after");
}

