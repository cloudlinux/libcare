#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "kpatch_patch.h"
#include "kpatch_user.h"
#include "kpatch_storage.h"
#include "kpatch_process.h"
#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "kpatch_ptrace.h"
#include "list.h"
#include "kpatch_log.h"


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
 * Patch application subroutines
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

int process_patch(int pid, void *_data)
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

int process_unpatch(int pid, void *_data)
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

