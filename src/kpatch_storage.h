#ifndef __KPATCH_STORAGE__
#define __KPATCH_STORAGE__

#include "kpatch_common.h"
#include "kpatch_file.h"
#include "kpatch_process.h"
#include "rbtree.h"

struct kpatch_storage_patch {
	/* Pointer to the object's patch (if any) */
	struct kp_file kpfile;

	/* Build id kept here for negative caching */
	char buildid[41];

	/* Patch level */
	int patchlevel;

	/* Description cache */
	char *desc;

	/* Node for rb_root */
	struct rb_node node;
};

struct kpatch_storage {
	/* Patch storage path */
	char *path;

	/* Patch file (or directory) descriptor */
	int patch_fd;

	/* Is patch_fd a directory or a file? */
	char is_patch_dir;

	union {
		/* Tree with BuildID keyed `kp_file's,
		 * is_patch_dir = 1 */
		struct rb_root tree;

		/* A single file, is_patch_dir = 0 */
		struct kpatch_storage_patch patch;
	};
};

typedef struct kpatch_storage kpatch_storage_t;

int storage_init(kpatch_storage_t *storage,
	     const char *fname);
void storage_free(kpatch_storage_t *storage);

enum {
	PATCH_OPEN_ERROR = -1,
	PATCH_NOT_FOUND = 0,
	PATCH_FOUND = 1,
};
int storage_lookup_patches(kpatch_storage_t *storage, kpatch_process_t *proc);
int storage_have_patch(kpatch_storage_t *storage, const char *buildid,
		   struct kpatch_storage_patch **ppatch);
int storage_patch_found(struct kpatch_storage_patch *patch);
int storage_execute_before_script(kpatch_storage_t *storage, kpatch_process_t *proc);
int storage_execute_after_script(kpatch_storage_t *storage, kpatch_process_t *proc);
char *storage_get_description(kpatch_storage_t *storage,
			struct kpatch_storage_patch *patch);

#endif
