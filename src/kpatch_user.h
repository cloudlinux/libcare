#ifndef __KPATCH_USER__
#define __KPATCH_USER__

#include "kpatch_common.h"
#include "kpatch_file.h"
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

int cmd_patch_user(int argc, char *argv[]);
int cmd_unpatch_user(int argc, char *argv[]);

#endif
