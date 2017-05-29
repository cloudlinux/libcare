/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  See Documentation/rbtree.txt for documentation and samples.
*/

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <unistd.h>

#include "util.h"

#define WRITE_ONCE(a, b) (a) = (b)

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};


#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  (READ_ONCE((root)->rb_node) == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Postorder iteration - always visit the parent after its children */
extern struct rb_node *rb_first_postorder(const struct rb_root *);
extern struct rb_node *rb_next_postorder(const struct rb_node *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
			    struct rb_root *root);
extern void rb_replace_node_rcu(struct rb_node *victim, struct rb_node *new,
				struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
				struct rb_node **rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})

/**
 * rbtree_postorder_for_each_entry_safe - iterate in post-order over rb_root of
 * given type allowing the backing memory of @pos to be invalidated
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 *
 * rbtree_postorder_for_each_entry_safe() provides a similar guarantee as
 * list_for_each_entry_safe() and allows the iteration to continue independent
 * of changes to @pos by the body of the loop.
 *
 * Note, however, that it cannot handle other modifications that re-order the
 * rbtree it is iterating over. This includes calling rb_erase() on @pos, as
 * rb_erase() may rebalance the tree, causing us to miss some nodes.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

/* include/linux/rbtree_augmented.h */

#define RB_RED          0
#define RB_BLACK        1

#define __rb_parent(pc)    ((struct rb_node *)(pc & ~3))

#define __rb_color(pc)     ((pc) & 1)
#define __rb_is_black(pc)  __rb_color(pc)
#define __rb_is_red(pc)    (!__rb_color(pc))
#define rb_color(rb)       __rb_color((rb)->__rb_parent_color)
#define rb_is_red(rb)      __rb_is_red((rb)->__rb_parent_color)
#define rb_is_black(rb)    __rb_is_black((rb)->__rb_parent_color)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
        rb->__rb_parent_color = rb_color(rb) | (unsigned long)p;
}

static inline void rb_set_parent_color(struct rb_node *rb,
                                       struct rb_node *p, int color)
{
        rb->__rb_parent_color = (unsigned long)p | color;
}

static inline void
__rb_change_child(struct rb_node *old, struct rb_node *new,
                  struct rb_node *parent, struct rb_root *root)
{
        if (parent) {
                if (parent->rb_left == old)
                        WRITE_ONCE(parent->rb_left, new);
                else
                        WRITE_ONCE(parent->rb_right, new);
        } else
                WRITE_ONCE(root->rb_node, new);
}

extern void __rb_erase_color(struct rb_node *parent, struct rb_root *root);

static __always_inline struct rb_node *
__rb_erase(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *child = node->rb_right;
	struct rb_node *tmp = node->rb_left;
	struct rb_node *parent, *rebalance;
	unsigned long pc;

	if (!tmp) {
		/*
		 * Case 1: node to erase has no more than 1 child (easy!)
		 *
		 * Note that if there is one child it must be red due to 5)
		 * and node must be black due to 4). We adjust colors locally
		 * so as to bypass __rb_erase_color() later on.
		 */
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, child, parent, root);
		if (child) {
			child->__rb_parent_color = pc;
			rebalance = NULL;
		} else
			rebalance = __rb_is_black(pc) ? parent : NULL;
		tmp = parent;
	} else if (!child) {
		/* Still case 1, but this time the child is node->rb_left */
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	} else {
		struct rb_node *successor = child, *child2;

		tmp = child->rb_left;
		if (!tmp) {
			/*
			 * Case 2: node's successor is its right child
			 *
			 *    (n)          (s)
			 *    / \          / \
			 *  (x) (s)  ->  (x) (c)
			 *        \
			 *        (c)
			 */
			parent = successor;
			child2 = successor->rb_right;
		} else {
			/*
			 * Case 3: node's successor is leftmost under
			 * node's right child subtree
			 *
			 *    (n)          (s)
			 *    / \          / \
			 *  (x) (y)  ->  (x) (y)
			 *      /            /
			 *    (p)          (p)
			 *    /            /
			 *  (s)          (c)
			 *    \
			 *    (c)
			 */
			do {
				parent = successor;
				successor = tmp;
				tmp = tmp->rb_left;
			} while (tmp);
			child2 = successor->rb_right;
			WRITE_ONCE(parent->rb_left, child2);
			WRITE_ONCE(successor->rb_right, child);
			rb_set_parent(child, successor);
		}

		tmp = node->rb_left;
		WRITE_ONCE(successor->rb_left, tmp);
		rb_set_parent(tmp, successor);

		pc = node->__rb_parent_color;
		tmp = __rb_parent(pc);
		__rb_change_child(node, successor, tmp, root);

		if (child2) {
			successor->__rb_parent_color = pc;
			rb_set_parent_color(child2, parent, RB_BLACK);
			rebalance = NULL;
		} else {
			unsigned long pc2 = successor->__rb_parent_color;
			successor->__rb_parent_color = pc;
			rebalance = __rb_is_black(pc2) ? parent : NULL;
		}
		tmp = successor;
	}

	return rebalance;
}


/* LibCare API */

/* comparator function for node element: should return {<0, 0, >0} if
 * key { <node->key, ==node->key, >node->key }
 * the tree will be ordered in increasing order
 */
typedef int (*rb_cmp_fn_t)(struct rb_node *node, unsigned long key);

static inline void rb_init(struct rb_root *root)
{
	root->rb_node = NULL;
}

#define rb_empty(root)  ((root)->rb_node == NULL)


static inline
struct rb_node *rb_search_node(struct rb_root *root,
			       rb_cmp_fn_t cmp,
			       unsigned long key)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		int result;

		result = cmp(node, key);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return node;
	}
	return NULL;
}

/* if node with given key exists, returns it. Otherwise inserts new node */
static inline
struct rb_node *rb_insert_node(struct rb_root *root,
			       struct rb_node *new_node,
			       rb_cmp_fn_t cmp_fn,
			       unsigned long key)
{
        int cmp_res;
        struct rb_node **node = &root->rb_node;
        struct rb_node *parent = NULL;

        while (*node) {
                parent = *node;
                cmp_res = cmp_fn(*node, key);
                if (cmp_res < 0)
                        node = &(*node)->rb_left;
                else if (cmp_res > 0)
                        node = &(*node)->rb_right;
		else
			return *node;
        }

        /* insert & rebalance rb-tree */
        rb_link_node(new_node, parent, node);
        rb_insert_color(new_node, root);

        return NULL;
}

static inline
void rb_destroy(struct rb_root *root, void(*free_node_cb)(struct rb_node *))
{
        struct rb_node *node = rb_first(root), *right;
        struct rb_node *parent;

        while (node) {
                right = node->rb_right;
                parent = rb_parent(node);

                free_node_cb(node);

                if (right) {
                        node = right;
                        right->__rb_parent_color = (unsigned long)parent;
                        /* go left as far as we can */
                        while (node->rb_left)
                                node = node->rb_left;
                } else {
                        while (parent && node == parent->rb_right) {
                                node = parent;
                                parent = rb_parent(node);
                        }
                        node = parent;
                }
        }
}

#endif	/* _LINUX_RBTREE_H */
