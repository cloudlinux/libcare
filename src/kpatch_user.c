#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "kpatch_user.h"
#include "kpatch_process.h"
#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "kpatch_ptrace.h"
#include "list.h"
#include "kpatch_log.h"

/* Global variables */
static char storage_dir[PATH_MAX] = "/var/lib/libcare";


/*****************************************************************************
 * Utilities.
 ****************************************************************************/

/* Return -1 to indicate error, -2 to stop immediately */
typedef int (callback_t)(int pid, void *data);

static int
processes_do(int pid, callback_t callback, void *data);

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

static int
storage_init(kpatch_storage_t *storage,
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

static void
storage_free(kpatch_storage_t *storage)
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

enum {
	PATCH_OPEN_ERROR = -1,
	PATCH_NOT_FOUND = 0,
	PATCH_FOUND = 1,
};

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

static int
storage_patch_found(struct kpatch_storage_patch *patch)
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

static int
storage_have_patch(kpatch_storage_t *storage, const char *buildid,
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

static char *
storage_get_description(kpatch_storage_t *storage,
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

		if (rv == 0)
			break;

		sz += rv;
	}

	patch->desc = desc;

	return desc;

err_free:
	free(desc);
	close(fd);
	return NULL;
}

static int
storage_lookup_patches(kpatch_storage_t *storage, kpatch_process_t *proc)
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

static int
storage_execute_before_script(kpatch_storage_t *storage, kpatch_process_t *proc)
{
	return storage_execute_script(storage, proc, "before");
}

static int
storage_execute_after_script(kpatch_storage_t *storage, kpatch_process_t *proc)
{
	return storage_execute_script(storage, proc, "after");
}

enum {
	ACTION_APPLY_PATCH,
	ACTION_UNAPPLY_PATCH
};

static inline int
is_addr_in_info(unsigned long addr,
		struct kpatch_info *info,
		int direction)
{
#define IS_ADDR_IN_HALF_INTERVAL(addr, start, len) ((addr >= start) && (addr < start + len))
	if (direction == ACTION_APPLY_PATCH)
		return IS_ADDR_IN_HALF_INTERVAL(addr, info->daddr, info->dlen);
	if (direction == ACTION_UNAPPLY_PATCH)
		return IS_ADDR_IN_HALF_INTERVAL(addr, info->saddr, info->slen);
	return 0;
}

static void print_address_closest_func(int log_level, struct object_file *o, unw_cursor_t *cur, int in_oldpatch)
{
	unsigned long address, offset;
	char fname[128];

	unw_get_reg(cur, UNW_REG_IP, &address);

	if (in_oldpatch)
		if (address >= o->kpta && address < o->kpta + o->kpfile.size) {
			kplog(log_level, "\t[0x%lx](patch)\n", address);
			return;
		}

	if (!unw_get_proc_name(cur, fname, 128, &offset))
		kplog(log_level, "\t[0x%lx] %s+0x%lx\n", address, fname, offset);
	else
		kplog(log_level, "\t[0x%lx]\n", address);
}

/**
 * Verify that the function from file `o' is safe to be patched.
 *
 * If retip is given then the safe address is returned in it.
 * What is considered a safe address depends on the `paranoid' value. When it
 * is true, safe address is the upper of ALL functions that do have a patch.
 * When it is false, safe address is the address of the first function
 * instruction that have no patch.
 *
 * That is, for the call chain from left to right with functions that have
 * patch marked with '+':
 *
 * foo -> bar+ -> baz -> qux+
 *
 * With `paranoid=true' this function will return address of the `bar+'
 * instruction being executed with *retip pointing to the `foo' instruction
 * that comes after the call to `bar+'. With `paranoid=false' this function
 * will return address of the `qux+' instruction being executed with *retip
 * pointing to the `baz' instruction that comes after call to `qux+'.
 */
static unsigned long
object_patch_verify_safety_single(struct object_file *o,
				  unw_cursor_t *cur,
				  unsigned long *retip,
				  int paranoid,
				  int direction)
{
	unw_word_t ip;
	struct kpatch_info *info = o->info;
	size_t i, ninfo = o->ninfo;
	int prev = 0, rv;
	unsigned long last = 0;

	if (direction != ACTION_APPLY_PATCH &&
	    direction != ACTION_UNAPPLY_PATCH)
		kpfatal("unknown direction");

	do {
		print_address_closest_func(LOG_INFO, o, cur, direction == ACTION_UNAPPLY_PATCH);

		unw_get_reg(cur, UNW_REG_IP, &ip);

		for (i = 0; i < ninfo; i++) {
			if (is_new_func(&info[i]))
				continue;

			if (is_addr_in_info((long)ip, &info[i], direction)) {
				if (direction == ACTION_APPLY_PATCH)
					last = info[i].daddr;
				else if (direction == ACTION_UNAPPLY_PATCH)
					last = info[i].saddr;
				prev = 1;
				break;
			}
		}

		if (prev && i == ninfo) {
			prev = 0;
			if (retip)
				*retip = ip;
			if (!paranoid)
				break;
		}

		rv = unw_step(cur);
	} while (rv > 0);

	if (rv < 0)
		kperr("unw_step = %d\n", rv);

	return last;
}

#define KPATCH_CORO_STACK_UNSAFE (1 << 20)

static int
patch_verify_safety(struct object_file *o,
		    unsigned long *retips,
		    int direction)
{
	size_t nr = 0, failed = 0, count = 0;
	struct kpatch_ptrace_ctx *p;
	struct kpatch_coro *c;
	unsigned long retip, ret;
	unw_cursor_t cur;

	list_for_each_entry(c, &o->proc->coro.coros, list) {
		void *ucoro;

		kpdebug("Verifying safety for coroutine %zd...\n", count);
		kpinfo("Stacktrace to verify safety for coroutine %zd:\n", count);
		ucoro = _UCORO_create(c, proc2pctx(o->proc)->pid);
		if (!ucoro) {
			kplogerror("can't create unwind coro context\n");
			return -1;
		}

		ret = unw_init_remote(&cur, o->proc->coro.unwd, ucoro);
		if (ret) {
			kplogerror("can't create unwind remote context\n");
			_UCORO_destroy(ucoro);
			return -1;
		}

		ret = object_patch_verify_safety_single(o, &cur, NULL, 0, direction);
		_UCORO_destroy(ucoro);
		if (ret) {
			kperr("safety check failed to %lx\n", ret);
			failed++;
		} else {
			kpdebug("OK\n");
		}
		count++;
	}
	if (failed)
		return failed | KPATCH_CORO_STACK_UNSAFE;

	list_for_each_entry(p, &o->proc->ptrace.pctxs, list) {
		void *upt;

		kpdebug("Verifying safety for pid %d...\n", p->pid);
		kpinfo("Stacktrace to verify safety for pid %d:\n", p->pid);
		upt = _UPT_create(p->pid);
		if (!upt) {
			kplogerror("can't create unwind ptrace context\n");
			return -1;
		}

		ret = unw_init_remote(&cur, o->proc->ptrace.unwd, upt);
		if (ret) {
			kplogerror("can't create unwind remote context\n");
			_UPT_destroy(upt);
			return -1;
		}

		ret = object_patch_verify_safety_single(o, &cur, &retip, 0, direction);
		_UPT_destroy(upt);
		if (ret) {
			/* TODO: dump full backtrace, with symbols where possible (shared libs) */
			if (retips) {
				kperr("safety check failed for %lx, will continue until %lx\n",
				      ret, retip);
				retips[nr] = retip;
			} else {
				kperr("safety check failed for %lx\n", ret);
				errno = -EBUSY;
			}
			failed++;
		}
		kpdebug("OK\n");
		nr++;
	}

	return failed;
}

/*
 * Ensure that it is safe to apply/unapply patch for the object file `o`.
 *
 * First, we verify the safety of the patch.
 *
 * It is safe to apply patch (ACTION_APPLY_PATCH) when no threads or coroutines
 * are executing the functions to be patched.
 *
 * It is safe to unapply patch (ACTION_UNAPPLY_PATCH) when no threads or
 * coroutines are executing the patched functions.
 *
 * If it is not safe to do the action we continue threads execution until they
 * are out of the functions that we want to patch/unpatch. This is done using
 * `kpatch_ptrace_execute_until` function with default timeout of 3000 seconds
 * and checking for action safety again.
 */
static int
patch_ensure_safety(struct object_file *o,
		    int action)
{
	struct kpatch_ptrace_ctx *p;
	unsigned long ret, *retips;
	size_t nr = 0, i;

	list_for_each_entry(p, &o->proc->ptrace.pctxs, list)
		nr++;
	retips = malloc(nr * sizeof(unsigned long));
	if (retips == NULL)
		return -1;

	memset(retips, 0, nr * sizeof(unsigned long));

	ret = patch_verify_safety(o, retips, action);
	/*
	 * For coroutines we can't "execute until"
	 */
	if (ret && !(ret & KPATCH_CORO_STACK_UNSAFE)) {
		i = 0;
		list_for_each_entry(p, &o->proc->ptrace.pctxs, list) {
			p->execute_until = retips[i];
			i++;
		}

		ret = kpatch_ptrace_execute_until(o->proc, 3000, 0);

		/* OK, at this point we may have new threads, discover them */
		if (ret == 0)
			ret = kpatch_process_attach(o->proc);
		if (ret == 0)
			ret = patch_verify_safety(o, NULL, action);
	}

	free(retips);

	return ret ? -1 : 0;
}

/*****************************************************************************
 * Patch application subroutines and cmd_patch_user
 ****************************************************************************/
/*
 * This flag is local, i.e. it is never stored to the
 * patch applied to patient's memory.
 */
#define PATCH_APPLIED	(1 << 31)

#define HUNK_SIZE 5

static int
patch_apply_hunk(struct object_file *o, size_t nhunk)
{
	int ret;
	char code[HUNK_SIZE] = {0xe9, 0x00, 0x00, 0x00, 0x00}; /* jmp IMM */
	struct kpatch_info *info = &o->info[nhunk];
	unsigned long pundo;

	if (is_new_func(info))
		return 0;

	pundo = o->kpta + o->kpfile.patch->user_undo + nhunk * HUNK_SIZE;
	kpinfo("%s origcode from 0x%lx+0x%x to 0x%lx\n",
	       o->name, info->daddr, HUNK_SIZE, pundo);
	ret = kpatch_process_memcpy(o->proc, pundo,
				    info->daddr, HUNK_SIZE);
	if (ret < 0)
		return ret;

	kpinfo("%s hunk 0x%lx+0x%x -> 0x%lx+0x%x\n",
	       o->name, info->daddr, info->dlen, info->saddr, info->slen);
	*(unsigned int *)(code + 1) = (unsigned int)(info->saddr - info->daddr - 5);
	ret = kpatch_process_mem_write(o->proc,
				       code,
				       info->daddr,
				       sizeof(code));
	/*
	 * NOTE(pboldin): This is only stored locally, as information have
	 * been copied to patient's memory already.
	 */
	info->flags |= PATCH_APPLIED;
	return ret ? -1 : 0;
}

static int
duplicate_kp_file(struct object_file *o)
{
	struct kpatch_file *patch;

	patch = malloc(o->skpfile->size);
	if (patch == NULL)
		return -1;

	memcpy(patch, o->skpfile->patch, o->skpfile->size);
	o->kpfile.patch = patch;
	o->kpfile.size = o->skpfile->size;

	return 0;
}

static int
object_apply_patch(struct object_file *o)
{
	struct kpatch_file *kp;
	size_t sz, i;
	int undef, ret;

	if (o->skpfile == NULL || o->is_patch)
		return 0;

	if (o->applied_patch) {
		kpinfo("Object '%s' already have a patch, not patching\n",
		       o->name);
		return 0;
	}

	ret = duplicate_kp_file(o);
	if (ret < 0) {
		kplogerror("can't duplicate kp_file\n");
		return -1;
	}

	ret = kpatch_elf_load_kpatch_info(o);
	if (ret < 0)
		return ret;

	kp = o->kpfile.patch;

	sz = ROUND_UP(kp->total_size, 8);
	undef = kpatch_count_undefined(o);
	if (undef) {
		o->jmp_table = kpatch_new_jmp_table(undef);
		kp->jmp_offset = sz;
		kpinfo("Jump table %d bytes for %d syms at offset 0x%x\n",
		       o->jmp_table->size, undef, kp->jmp_offset);
		sz = ROUND_UP(sz + o->jmp_table->size, 128);
	}

	kp->user_info = (unsigned long)o->info -
			(unsigned long)o->kpfile.patch;
	kp->user_undo = sz;
	sz = ROUND_UP(sz + HUNK_SIZE * o->ninfo, 16);

	sz = ROUND_UP(sz, 4096);

	/*
	 * Map patch as close to the original code as possible.
	 * Otherwise we can't use 32-bit jumps.
	 */
	ret = kpatch_object_allocate_patch(o, sz);
	if (ret < 0)
		return ret;
	ret = kpatch_resolve(o);
	if (ret < 0)
		return ret;
	ret = kpatch_relocate(o);
	if (ret < 0)
		return ret;
	ret = kpatch_process_mem_write(o->proc,
				       kp,
				       o->kpta,
				       kp->total_size);
	if (ret < 0)
		return -1;
	if (o->jmp_table) {
		ret = kpatch_process_mem_write(o->proc,
					       o->jmp_table,
					       o->kpta + kp->jmp_offset,
					       o->jmp_table->size);
		if (ret < 0)
			return ret;
	}

	ret = patch_ensure_safety(o, ACTION_APPLY_PATCH);
	if (ret < 0)
		return ret;

	for (i = 0; i < o->ninfo; i++) {
		ret = patch_apply_hunk(o, i);
		if (ret < 0)
			return ret;
	}

	return 1;
}

static int
object_unapply_patch(struct object_file *o, int check_flag);

static int
object_unapply_old_patch(struct object_file *o)
{
	struct kpatch_file *kpatch_applied, *kpatch_storage;
	int ret;

	if (o->skpfile == NULL || o->is_patch || o->applied_patch == NULL)
		return 0;

	kpatch_applied = o->applied_patch->kpfile.patch;
	kpatch_storage = o->skpfile->patch;

	if (kpatch_applied->user_level >= kpatch_storage->user_level) {
		kpinfo("'%s' applied patch level is %d (storage has %d\n)\n",
		       o->name,
		       kpatch_applied->user_level,
		       kpatch_storage->user_level);
		return 1;
	}

	printf("%s: replacing patch level %d with level %d\n",
	       o->name,
	       kpatch_applied->user_level,
	       kpatch_storage->user_level);
	ret = object_unapply_patch(o, /* check_flag */ 0);
	if (ret < 0)
		kperr("can't unapply patch for %s\n", o->name);
	else {
		/* TODO(pboldin): handle joining the holes here */
		o->applied_patch = NULL;
		o->info = NULL;
		o->ninfo = 0;
	}

	return ret;
}

static int
kpatch_apply_patches(kpatch_process_t *proc)
{
	struct object_file *o;
	int applied = 0, ret;

	list_for_each_entry(o, &proc->objs, list) {

		ret = object_unapply_old_patch(o);
		if (ret < 0)
			break;

		ret = object_apply_patch(o);
		if (ret < 0)
			goto unpatch;
		if (ret)
			applied++;
	}
	return applied;

unpatch:
	kperr("Patching %s failed, unapplying partially applied patch\n", o->name);
	/*
	 * TODO(pboldin): close the holes so the state is the same
	 * after unpatch
	 */
	ret = object_unapply_patch(o, /* check_flag */ 1);
	if (ret < 0) {
		kperr("Can't unapply patch for %s\n", o->name);
	}
	return -1;
}

struct patch_data {
	kpatch_storage_t *storage;
	int is_just_started;
	int send_fd;
};

static int process_patch(int pid, void *_data)
{
	int ret;
	kpatch_process_t _proc, *proc = &_proc;
	struct patch_data *data = _data;

	kpatch_storage_t *storage = data->storage;
	int is_just_started = data->is_just_started;
	int send_fd = data->send_fd;

	ret = kpatch_process_init(proc, pid, is_just_started, send_fd);
	if (ret < 0) {
		kperr("cannot init process %d\n", pid);
		goto out;
	}

	kpatch_process_print_short(proc);

	ret = kpatch_process_mem_open(proc, MEM_READ);
	if (ret < 0)
		goto out_free;

	/*
	 * In case the process was just started we continue execution up to the
	 * entry point of a program just to allow ld.so to load up libraries
	 */
	ret = kpatch_process_load_libraries(proc);
	if (ret < 0)
		goto out_free;

	/*
	 * In case we got there from startup send_fd != -1.
	 */
	ret = kpatch_process_kick_send_fd(proc);
	if (ret < 0)
		goto out_free;

	/*
	 * For each object file that we want to patch (either binary itself or
	 * shared library) we need its ELF structure to perform relocations.
	 * Because we know uniq BuildID of the object the section addresses
	 * stored in the patch are valid for the original object.
	 */
	ret = kpatch_process_map_object_files(proc);
	if (ret < 0)
		goto out_free;

	/*
	 * Lookup for patches appicable for proc in storage.
	 */
	ret = storage_lookup_patches(storage, proc);
	if (ret <= 0)
		goto out_free;

	/* Finally, attach to process */
	ret = kpatch_process_attach(proc);
	if (ret < 0)
		goto out_free;

	ret = kpatch_coroutines_find(proc);
	if (ret < 0)
		goto out_free;

	ret = storage_execute_before_script(storage, proc);
	if (ret < 0)
		goto out_free;

	ret = kpatch_apply_patches(proc);

	if (storage_execute_after_script(storage, proc) < 0)
		kperr("after script failed\n");


out_free:
	kpatch_process_free(proc);

out:
	if (ret < 0) {
		printf("Failed to apply patch '%s'\n", storage->path);
		kperr("Failed to apply patch '%s'\n", storage->path);
	} else if (ret == 0)
		printf("No patch(es) applicable to PID '%d' have been found\n", pid);
	else {
		printf("%d patch hunk(s) have been successfully applied to PID '%d'\n", ret, pid);
		ret = 0;
	}

	return ret;
}

static int
processes_patch(kpatch_storage_t *storage,
		int pid, int is_just_started, int send_fd)
{
	struct patch_data data = {
		.storage = storage,
		.is_just_started = is_just_started,
		.send_fd = send_fd,
	};

	return processes_do(pid, process_patch, &data);
}

/* Check if system is suitable */
static int kpatch_check_system(void)
{
	return 1;
}

static int usage_patch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl patch [options] <-p PID> <-r fd> <patch>\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "  -s          - process was just executed\n");
	fprintf(stderr, "  -p <PID>    - target process\n");
	fprintf(stderr, "  -r fd       - fd used with LD_PRELOAD=execve.so.\n");
	return err ? 0 : -1;
}

int cmd_patch_user(int argc, char *argv[])
{
	kpatch_storage_t storage;
	int opt, pid = -1, is_pid_set = 0, ret, start = 0, send_fd = -1;

	if (argc < 4)
		return usage_patch(NULL);

	while ((opt = getopt(argc, argv, "hsp:r:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_patch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		case 'r':
			send_fd = atoi(optarg);
			break;
		case 's':
			start = 1;
			break;
		default:
			return usage_patch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set)
		return usage_patch("PID argument is mandatory");

	if (!kpatch_check_system())
		goto out_err;

	ret = storage_init(&storage, argv[argc - 1]);
	if (ret < 0)
		goto out_err;


	ret = processes_patch(&storage, pid, start, send_fd);

	storage_free(&storage);

out_err:
	return ret;
}

/*****************************************************************************
 * Patch cancellcation subroutines and cmd_unpatch_user
 ****************************************************************************/
static int
object_find_applied_patch_info(struct object_file *o)
{
	struct kpatch_info tmpinfo;
	struct kpatch_info *remote_info;
	size_t nalloc = 0;
	struct process_mem_iter *iter;
	int ret;

	if (o->info != NULL)
		return 0;

	iter = kpatch_process_mem_iter_init(o->proc);
	if (iter == NULL)
		return -1;

	remote_info = (void *)o->kpta + o->kpfile.patch->user_info;
	do {
		ret = REMOTE_PEEK(iter, tmpinfo, remote_info);
		if (ret < 0)
			goto err;

		if (is_end_info(&tmpinfo))
		    break;

		if (o->ninfo == nalloc) {
			nalloc += 16;
			o->info = realloc(o->info, nalloc * sizeof(tmpinfo));
		}

		o->info[o->ninfo] = tmpinfo;

		remote_info++;
		o->ninfo++;
	} while (1);

	o->applied_patch->info = o->info;
	o->applied_patch->ninfo = o->ninfo;

err:
	kpatch_process_mem_iter_free(iter);

	return ret;
}

static int
object_unapply_patch(struct object_file *o, int check_flag)
{
	int ret;
	size_t i;
	unsigned long orig_code_addr;

	ret = object_find_applied_patch_info(o);
	if (ret < 0)
		return ret;

	ret = patch_ensure_safety(o, ACTION_UNAPPLY_PATCH);
	if (ret < 0)
		return ret;

	orig_code_addr = o->kpta + o->kpfile.patch->user_undo;

	for (i = 0; i < o->ninfo; i++) {
		if (is_new_func(&o->info[i]))
			continue;

		if (check_flag && !(o->info[i].flags & PATCH_APPLIED))
			continue;

		ret = kpatch_process_memcpy(o->proc,
					    o->info[i].daddr,
					    orig_code_addr + i * HUNK_SIZE,
					    HUNK_SIZE);
		/* XXX(pboldin) We are in deep trouble here, handle it
		 * by restoring the patch back */
		if (ret < 0)
			return ret;
	}

	ret = kpatch_munmap_remote(proc2pctx(o->proc),
				   o->kpta,
				   o->kpfile.size);

	return ret;
}

static int
kpatch_should_unapply_patch(struct object_file *o,
			    char *buildids[],
			    int nbuildids)
{
	int i;
	const char *bid;

	if (nbuildids == 0)
		return 1;

	bid = kpatch_get_buildid(o);

	for (i = 0; i < nbuildids; i++) {
		if (!strcmp(bid, buildids[i]) ||
		    !strcmp(o->name, buildids[i]))
			return 1;
	}

	return 0;
}

static int
kpatch_unapply_patches(kpatch_process_t *proc,
		       char *buildids[],
		       int nbuildids)
{
	struct object_file *o;
	int ret;
	size_t unapplied = 0;

	ret = kpatch_process_associate_patches(proc);
	if (ret < 0)
		return ret;

	list_for_each_entry(o, &proc->objs, list) {
		if (o->applied_patch == NULL)
			continue;

		if (!kpatch_should_unapply_patch(o, buildids, nbuildids))
			continue;

		ret = object_unapply_patch(o, /* check_flag */ 0);
		if (ret < 0)
			return ret;
		unapplied++;
	}

	return unapplied;
}

struct unpatch_data {
	char **buildids;
	int nbuildids;
};

static int
process_unpatch(int pid, void *_data)
{
	int ret;
	kpatch_process_t _proc, *proc = &_proc;
	struct unpatch_data *data = _data;
	char **buildids = data->buildids;
	int nbuildids = data->nbuildids;

	ret = kpatch_process_init(proc, pid, /* start */ 0, /* send_fd */ -1);
	if (ret < 0)
		return -1;

	kpatch_process_print_short(proc);

	ret = kpatch_process_attach(proc);
	if (ret < 0)
		goto out;

	ret = kpatch_process_map_object_files(proc);
	if (ret < 0)
		goto out;

	ret = kpatch_coroutines_find(proc);
	if (ret < 0)
		goto out;

	ret = kpatch_unapply_patches(proc, buildids, nbuildids);

out:
	kpatch_process_free(proc);

	if (ret < 0)
		printf("Failed to cancel patches for %d\n", pid);
	else if (ret == 0)
		printf("No patch(es) cancellable from PID '%d' were found\n", pid);
	else
		printf("%d patch hunk(s) were successfully cancelled from PID '%d'\n", ret, pid);

	return ret;
}

static int
processes_unpatch(int pid, char *buildids[], int nbuildids)
{
	struct unpatch_data data = {
		.buildids = buildids,
		.nbuildids = nbuildids
	};

	return processes_do(pid, process_unpatch, &data);
}

static int usage_unpatch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl unpatch [options] <-p PID> "
		"[Build-ID or name ...]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "  -p <PID>    - target process\n");
	return err ? 0 : -1;
}

int cmd_unpatch_user(int argc, char *argv[])
{
	int opt, pid = -1, is_pid_set = 0;

	if (argc < 3)
		return usage_unpatch(NULL);

	while ((opt = getopt(argc, argv, "hp:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_unpatch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		default:
			return usage_unpatch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set)
		return usage_patch("PID argument is mandatory");

	if (!kpatch_check_system())
		return -1;

	return processes_unpatch(pid, argv, argc);
}

static
int usage_info(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl info [options] [-b BUILDID] [-p PID] [-s STORAGE] [-r REGEXP]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h		- this message\n");
	fprintf(stderr, "  -n		- don't print patch descriptions\n");
	fprintf(stderr, "  -b <BUILDID>	- output all processes having object with specified BuildID loaded\n");
	fprintf(stderr, "  -p <PID>	- target process, 'all' or omitted for all the system processes\n");
	fprintf(stderr, "  -s <STORAGE>	- only show BuildIDs of object having patches in STORAGE, default %s\n",
		storage_dir);
	fprintf(stderr, "  -r <REGEXP>	- only show BuildIDs of object having name matching REGEXP\n");
	return err ? 0 : -1;
}

struct info_data {
	const char *buildid;
	kpatch_storage_t *storage;
	regex_t *name_re;
	int print_description;
	int may_update, vulnerable;
};

const char *RED   	= "\x1B[31m";
const char *GREEN	= "\x1B[32m";
const char *YELLOW	= "\x1B[33m";
const char *RESET	= "\x1B[0m";

static void
init_colors(void)
{
	if (!isatty(fileno(stdout))) {
		RED = GREEN = YELLOW = RESET = "";
	}
}

static int
object_info(struct info_data *data, struct object_file *o,
	    int *pid_printed)
{
	const char *buildid;
	kpatch_process_t *proc = o->proc;
	int pid = proc->pid;
	struct kpatch_storage_patch *patch = NULL;
	int patch_found = PATCH_NOT_FOUND;

	if (!o->is_elf || is_kernel_object_name(o->name))
		return 0;


	if (data->name_re != NULL &&
	    regexec(data->name_re, o->name,
		    0, NULL, REG_EXTENDED) == REG_NOMATCH)
		return 0;

	buildid = kpatch_get_buildid(o);
	if (buildid == NULL) {
		kpinfo("can't get buildid for %s\n", o->name);
		return 0;
	}

	if (data->buildid) {
		if (!strcmp(data->buildid, buildid)) {
			printf("pid=%d comm=%s\n", pid, proc->comm);
			printf("%s %s\n", o->name, buildid);
			return 1;
		}
		return 0;
	}

	if (data->storage)
		patch_found = storage_have_patch(data->storage,
						 buildid,
						 &patch);

	if (o->applied_patch == NULL && !patch_found)
		return 0;

	if (!*pid_printed) {
		printf("pid=%d comm=%s\n", pid, proc->comm);
		*pid_printed = 1;
	}

	printf("%s buildid=%s", o->name, buildid);
	if (o->applied_patch != NULL) {
		int patchlvl = o->kpfile.patch->user_level;
		printf(" patchlvl=%d", patchlvl);
	}
	if (storage_patch_found(patch) && patch->patchlevel) {
		printf(" latest=%d", patch->patchlevel);
	}

	/* empty patch patchlevel=0 with description of bugs in the version */
	if (patch && patch->patchlevel == 0 && o->applied_patch == NULL) {
		printf(" %sVULNERABLE%s\n", RED, RESET);

		if (data->print_description) {
			char *desc;

			desc = storage_get_description(data->storage, patch);
			printf("\n%sVULNERABLE VERSION:\n", RED);

			printf("%s%s", desc, RESET);
		}

		data->vulnerable ++;
	}

	printf("\n");

	/* Old or no patch applied but we have one in storage */
	if (patch && patch->patchlevel != 0 &&
	    (o->applied_patch == NULL || patch->patchlevel > o->kpfile.patch->user_level)) {
		if (data->print_description) {
			char *desc;

			printf("\n%snew patch description:\n", YELLOW);

			desc = storage_get_description(data->storage, patch);
			printf("%s%s", desc, RESET);
		}

		data->may_update++;
		return 0;
	}

	/* patch applied and is latest version. show descripition for it */
	if (patch && o->applied_patch != NULL && data->print_description) {
		char *desc;

		printf("\n%slatest patch applied\n", GREEN);

		desc = storage_get_description(data->storage, patch);
		printf("%s%s", desc, RESET);
		return 0;
	}

	return 0;
}

static int
process_info(int pid, void *_data)
{
	int ret, pid_printed = 0;
	kpatch_process_t _proc, *proc = &_proc;
	struct info_data *data = _data;
	struct object_file *o;

	ret = kpatch_process_init(proc, pid, /* start */ 0, /* send_fd */ -1);
	if (ret < 0)
		return -1;

	ret = kpatch_process_mem_open(proc, MEM_READ);
	if (ret < 0)
		goto out;

	ret = kpatch_process_map_object_files(proc);
	if (ret < 0)
		goto out;


	list_for_each_entry(o, &proc->objs, list)
		if (object_info(data, o, &pid_printed))
			break;

	if (pid_printed && data->print_description)
		printf("========================================\n");
out:
	kpatch_process_free(proc);

	return ret;
}

static int
processes_info(int pid,
	       const char *buildid,
	       const char *storagepath,
	       const char *regexp,
	       int print_description)
{
	int ret = -1;
	struct info_data data = { 0, };
	kpatch_storage_t storage;
	regex_t regex;

	init_colors();

	data.buildid = buildid;
	data.print_description = print_description;
	data.may_update = 0;
	data.vulnerable = 0;

	if (regexp != NULL) {
		ret = regcomp(&regex, regexp, REG_EXTENDED);
		if (ret != 0) {
			ret = -1;
			goto out_err;
		}
		data.name_re = &regex;
	}

	if (storagepath != NULL) {
		ret = storage_init(&storage, storagepath);
		if (ret < 0)
			goto out_err;
		data.storage = &storage;
	}

	ret = processes_do(pid, process_info, &data);

	if (data.vulnerable) {
		printf("%s%d object(s) are vulnerable%s\n", RED, data.vulnerable, RESET);
	}

	if (data.may_update) {
		printf("%s%d object(s) may be updated to the latest patch%s\n",
		       YELLOW, data.may_update, RESET);
		printf("\n%sRun: libcare-client update%s\n",
		       RED, RESET);
	}

out_err:
	if (data.storage != NULL) {
		storage_free(data.storage);
	}
	if (data.name_re != NULL) {
		regfree(data.name_re);
	}

	return ret;
}

int cmd_info_user(int argc, char *argv[])
{
	int opt, pid = -1, verbose = 0, print_description = 1;
	const char *buildid = NULL;
	const char *storagepath = storage_dir;
	const char *regexp = NULL;

	while ((opt = getopt(argc, argv, "hb:p:s:r:vn")) != EOF) {
		switch (opt) {
		case 'b':
			buildid = optarg;
			break;
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			break;
		case 's':
			storagepath = optarg;
			if (storagepath[0] == '\0' ||
			    !strcmp(storagepath, "/dev/null"))
				storagepath = NULL;
			break;
		case 'n':
			print_description = 0;
			break;
		case 'r':
			regexp = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			return usage_info(NULL);
		default:
			return usage_info("unknown arg");
		}
	}

	if (!verbose)
		log_level = LOG_ERR;

	if ((regexp != NULL && buildid != NULL)  ||
	    (buildid != NULL && storagepath != NULL)) {
		return usage_info("regexp & buildid | buildid & storage are mutual");
	}


	return processes_info(pid, buildid, storagepath, regexp,
			      print_description);
}


/* Server part. Used as a start-up notification listener. */
#define SERVER_STOP	(1<<30)

static int
execute_cmd(int argc, char *argv[]);

static int
cmd_execve_startup(int fd, int argc, char *argv[], int is_just_started)
{
	int rv, pid;
	char pid_str[64], send_fd_str[64];
	char *patch_pid_argv_execve[] = {
		"patch",
		"-s",
		"-p",
		pid_str,
		"-r",
		send_fd_str,
		storage_dir
	};
	char *patch_pid_argv_startup[] = {
		"patch",
		"-p",
		pid_str,
		"-r",
		send_fd_str,
		storage_dir
	};

	rv = sscanf(argv[1], "%d", &pid);
	if (rv != 1) {
		kperr("can't parse pid from %s", argv[1]);
		return -1;
	}

	sprintf(pid_str, "%d", pid);
	sprintf(send_fd_str, "%d", fd);

	optind = 1;
	if (is_just_started)
		rv = cmd_patch_user(ARRAY_SIZE(patch_pid_argv_execve),
				    patch_pid_argv_execve);
	else
		rv = cmd_patch_user(ARRAY_SIZE(patch_pid_argv_startup),
				    patch_pid_argv_startup);

	if (rv < 0)
		kperr("can't patch pid %d\n", pid);

	return 0;
}

static void
kill_and_wait(int pid)
{
	int status;

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, &status, 0);
}

static int childpid;

static int
cmd_run(int argc, char *argv[])
{
	int pid;

	if (childpid) {
		kill_and_wait(childpid);
		childpid = 0;
	}

	pid = fork();
	if (pid == -1) {
		kplogerror("can't fork()\n");
		return -1;
	}

	if (pid == 0) {
		return execl("/bin/sh", "sh", "-c", argv[1], (char *)NULL);
	}

	childpid = pid;
	printf("%d\n", pid);
	return 0;
}

static int
cmd_kill(int argc, char *argv[])
{
	int pid;

	if (sscanf(argv[1], "%d", &pid) != 1) {
		kperr("can't parse pid from %s\n", argv[1]);
		return -1;
	}

	kpdebug("killing %d\n", pid);
	kill_and_wait(pid);

	return 0;
}

static int
cmd_storage(int argc, char *argv[])
{
	strncpy(storage_dir, argv[1], PATH_MAX - 1);
	return 0;
}

static int
cmd_update(int argc, char *argv[])
{
	char *patch_all[] = {
		"patch",
		"-p",
		"all",
		storage_dir
	};

	optind = 1;
	return cmd_patch_user(ARRAY_SIZE(patch_all), patch_all);
}

static int
server_execute_cmd(int fd, int argc, char *argv[])
{
	char *cmd = argv[0];
	int old_stdout, old_stderr, rv;
	optind = 1;

	if (!strcmp(cmd, "execve"))
		return cmd_execve_startup(fd, argc, argv, 1);
	if (!strcmp(cmd, "startup"))
		return cmd_execve_startup(fd, argc, argv, 0);
	if (!strcmp(cmd, "update"))
		return cmd_update(argc, argv);
	if (!strcmp(cmd, "storage"))
		return cmd_storage(argc, argv);
	if (!strcmp(cmd, "stop"))
		return SERVER_STOP;

	old_stdout = dup3(1, 101, O_CLOEXEC);
	old_stderr = dup3(2, 102, O_CLOEXEC);

	(void) dup3(fd, 1, O_CLOEXEC);
	(void) dup3(fd, 2, O_CLOEXEC);


	if (!strcmp(cmd, "run"))
		rv = cmd_run(argc, argv);
	else if (!strcmp(cmd, "kill"))
		rv = cmd_kill(argc, argv);
	else
		rv = execute_cmd(argc, argv);

	fflush(stdout);
	fflush(stderr);

	(void) dup2(old_stdout, 1);
	(void) dup2(old_stderr, 2);

	return rv;
}

static int
handle_client(int fd)
{
	char msg[4096], *argv[32], *p;
	ssize_t off = 0, r;
	int argc;

	do {
		r = recv(fd, msg + off, sizeof(msg) - off, 0);
		if (r == -1 && errno == EINTR)
			continue;

		if (r == 0)
			goto out_close;
		off += r;
	} while (off < sizeof(msg) &&
		 (off < 2 ||
		  msg[off - 2] != '\0' ||
		  msg[off - 1] != '\0'));

	if (off == sizeof(msg)) {
		kperr("possible buffer overflow\n");
		goto out_close;
	}

	argv[0] = msg;
	for (p = msg, argc = 1;
	     p < msg + off && argc < ARRAY_SIZE(argv);
	     p++) {
		if (*p)
			continue;
		p++;

		argv[argc] = p;
		if (*p == '\0')
			break;

		argc++;
	}

	return server_execute_cmd(fd, argc, argv);

out_close:
	close(fd);
	return 0;
}


static int usage_server(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl server <UNIX socket> [STORAGE ROOT]\n");
	return -1;
}

#define LISTEN_BACKLOG 1
static int
server_bind_socket(const char *path)
{
	int sfd = -1, rv, sockaddr_len;
	struct sockaddr_un sockaddr;

	/* Handle invocation by libcare.service */
	if (path[0] == '&') {
		if (sscanf(path, "&%d", &sfd) == 0)
			return -1;
		return sfd;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = AF_UNIX;
	sockaddr_len = strlen(path) + 1;
	if (sockaddr_len >= sizeof(sockaddr.sun_path)) {
		kperr("sockaddr is too long\n");
		return -1;
	}

	strncpy(sockaddr.sun_path, path, sizeof(sockaddr.sun_path));
	if (path[0] == '@')
		sockaddr.sun_path[0] = '\0';

	sockaddr_len += sizeof(sockaddr.sun_family);

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1)
		goto err_close;

	rv = bind(sfd, (struct sockaddr *)&sockaddr,
		  sockaddr_len);
	if (rv == -1)
		goto err_close;

	rv = listen(sfd, LISTEN_BACKLOG);
	if (rv == -1)
		goto err_close;

	return sfd;

err_close:
	if (rv < 0)
		kplogerror("can't listen on unix socket %s\n", path);
	if (sfd != -1)
		close(sfd);
	return rv;
}

static void
kill_child(int signum)
{
	/* Hello Bulba my old friend... */
	(void) signum;
	if (childpid)
		kill_and_wait(childpid);
	exit(0x80 | signum);
}

static int
cmd_server(int argc, char *argv[])
{
	int sfd = -1, cfd, rv;
	struct sigaction act;

	if (argc < 2)
		return usage_server("UNIX socket argument is missing");

	memset(&act, 0, sizeof(act));
	act.sa_handler = kill_child;
	act.sa_flags = SA_RESTART;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0) {
		kplogerror("can't install signal handler\n");
		return -1;
	}

	sfd = server_bind_socket(argv[1]);
	if (sfd < 0)
		return sfd;

	if (argc >= 3)
		strcpy(storage_dir, argv[2]);

	setlinebuf(stdout);

	while ((cfd = accept4(sfd, NULL, 0, SOCK_CLOEXEC)) >= 0) {
		rv = handle_client(cfd);
		if (rv < 0)
			kplogerror("server error\n");

		(void) close(cfd);
		if (rv == SERVER_STOP)
			break;
	}

	if (childpid)
		kill_and_wait(childpid);

	close(sfd);
	return 0;
}


/*****************************************************************************
 * Utilities.
 ****************************************************************************/
static int
processes_do(int pid, callback_t callback, void *data)
{
	DIR *dir;
	struct dirent *de;
	int ret = 0, rv;
	char *tmp, buf[64];

	if (pid != -1)
		return callback(pid, data);

	dir = opendir("/proc");
	if (!dir) {
		kplogerror("can't open '/proc' directory\n");
		return -1;
	}

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;

		pid = strtoul(de->d_name, &tmp, 10);
		if (pid == 0 || *tmp != '\0')
			continue;

		if (pid == 1 || pid == getpid())
			continue;

		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		rv = readlink(buf, buf, sizeof(buf));
		if (rv == -1) {
			if (errno == ENOENT)
				kpdebug("skipping kernel thread %d\n", pid);
			else
				kpdebug("can't get exec for %d: %s\n", pid,
					strerror(errno));
			continue;
		}

		rv = callback(pid, data);
		if (rv < 0)
			ret = -1;
		if (rv == -2)
			break;
	}

	closedir(dir);

	return ret;
}

static int usage(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl [options] <cmd> [args]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -v          - verbose mode\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  patch  - apply patch to a user-space process\n");
	fprintf(stderr, "  unpatch- unapply patch from a user-space process\n");
	fprintf(stderr, "  info   - show info on applied patches\n");
	fprintf(stderr, "  server - listen on a unix socket for commands\n");
	return -1;
}

static int
execute_cmd(int argc, char *argv[])
{
	char *cmd = argv[0];
	optind = 1;

	if (!strcmp(cmd, "patch") || !strcmp(cmd, "patch-user"))
		return cmd_patch_user(argc, argv);
	else if (!strcmp(cmd, "unpatch") || !strcmp(cmd, "unpatch-user"))
		return cmd_unpatch_user(argc, argv);
	else if (!strcmp(cmd, "info") || !strcmp(cmd, "info-user"))
		return cmd_info_user(argc, argv);
	else
		return usage("unknown command");
}

/* entry point */
int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "+vh")) != EOF) {
		switch (opt) {
			case 'v':
				log_level += 1;
				break;
			case 'h':
				return usage(NULL);
			default:
				return usage("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		return usage("not enough arguments.");

	if (!strcmp(argv[0], "server"))
		return cmd_server(argc, argv);
	else
		return execute_cmd(argc, argv);
}
