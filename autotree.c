/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <string.h>
#include <errno.h>
#include "cache.h"	/* from git core */

struct autotree;

struct autotree_list {
	struct autotree *next, *prev;	/* cirucularly linked list */
};

/*
 * We want dynamically created directories (based on git hash, usually found
 * by resolving a tag/head symlink) to appear stabily in the root directory
 * so pwd will work.  However we don't want them to linger forever creating
 * clutter time them out after awhile if they haven't been lookup'ed in ages
 */
struct autotree {
	struct rb_node rb;		/* keep first! */
	struct autotree_list l;
	time_t atime;
	char name[0];
};

/*
 * Anchor for cicularly-linked list.  The most recent touched are always put
 * at the front ot the loop (i.e. .next points to the most-recently touched
 * item and .prev the least-recently touched one)
 */
#define ANCHOR ((struct autotree *) (((char *) &autotrees_storage) -	\
			((size_t) &((struct autotree *) 0)->l)))
static struct autotree_list autotrees_storage = {
	.next = ANCHOR,
	.prev = ANCHOR,
};
#define OLDEST	(autotrees_storage.prev)
#define NEWEST	(autotrees_storage.next)

static unsigned int autotree_numdirs = 0;  /* number of directory objects */

static void autotree_expire(time_t expire_time)
{
	struct autotree *at = OLDEST;

	assert(at != ANCHOR);
	assert(at->l.next == ANCHOR);
	do {
		struct autotree *dead;
		if (at->atime > expire_time)
			break;	/* not expired yet */
		dead = at;
		at = at->l.prev;
		/*
		 * Check if a gnode with this name still exists; if so just
		 * leave it be
		 */
		if (gn_name_exists_in_root(dead->name) == 0) {
			at->l.next = dead->l.next;
			dead->l.next->l.prev = at;
			rbtree_delete(&dead->rb);
			free(dead);
			assert(autotree_numdirs > 0);
			autotree_numdirs--;
		}
	} while (at != ANCHOR);
}

static const unsigned int automount_expire = 240; /* TODO: make setable */

unsigned int autotree_count_subdirs(void)
{
	if (autotree_numdirs > 0) {
		static time_t lastrun = 0;
		time_t now = time((time_t *) 0);
		if ((lastrun < (now - 5)) ||
		    unlikely(lastrun == 0 || lastrun > now)) {
			lastrun = now;
			autotree_expire(now - automount_expire);
		}
	}
	return autotree_numdirs;
}

static struct rb_tree autotree_byname = EMPTY_RBTREE;

void autotree_readdir(struct api_readdir_state *ars)
{
	struct rb_node *rb;

	(void) autotree_count_subdirs();	/* expire any old entries */
	for (rb = rbtree_first(&autotree_byname);
	     rb != NULL;
	     rb = rbtree_next(rb))
		if (gn_add_dir_contents(&gitfs_node_root, ars,
					((struct autotree *) rb)->name,
					GFN_DIR) != 0)
			break;
}

/*
 * If we looked up a directory then we remember it a little while so it
 * shows up in readdir
 */
static int touch_or_add(const char *name)
{
	struct rb_node **rp;
	struct autotree *at;

	rbtree_walk(&autotree_byname, rp) {
		int cmp = strcmp(name, ((struct autotree *) *rp)->name);
		if (cmp == 0)
			break;
		rp = &(*rp)->child[cmp < 0];
	}
	if (RB_IS_NIL(*rp)) {
		size_t lenz = strlen(name) + 1;
		at = malloc(sizeof(*at) + lenz);
		if (at == NULL)
			return -ENOMEM;
		autotree_numdirs++;
		rbtree_insert(rp, &at->rb);
		(void) time(&at->atime);
		memcpy(&at->name, name, lenz);
	} else {
		at = (struct autotree *) *rp;
		assert(autotree_numdirs > 0);
		assert(at != ANCHOR);
		assert(NEWEST != ANCHOR);
		assert(OLDEST != ANCHOR);
		(void) time(&at->atime);
		if (at == NEWEST) {
			assert(at->l.prev == ANCHOR);
			return 0;	/* already at the front */
		}
		if (at->atime == NEWEST->atime)
			return 0;	/* no need to reorder: no time diff */
		/* pull "at" out of the loop */
		at->l.prev->l.next = at->l.next;
		at->l.next->l.prev = at->l.prev;
	}
	/* insert "at" at the beginning of the loop */
	at->l.next = NEWEST;
	at->l.prev = ANCHOR;
	NEWEST = at;
	at->l.next->l.prev = at;
	return 0;
}

static int finish_autotree_lookup(int err, struct gitfs_node *gn)
{
	assert(err <= 0);
	if (err == 0 && gn->type == GFN_DIR) {
		err = gitview_start_readonly(gn);
		if (err == 0)
			err = touch_or_add(gn->name);
		if (err != 0)
			gn_release(gn);
	}
	return err;
}

int autotree_lookup(struct gitfs_node **resultp, const char *name)
{
	struct gitobj_ptr ptr;
	size_t nameln;
	const char *hash;

	nameln = strlen(name);
	if (nameln < HEX_PTR_LEN || nameln == (HEX_PTR_LEN + 1))
		return -ENOENT;
	hash = name + (nameln - HEX_PTR_LEN);
	if (hash != name && hash[-1] != ':')
		return -ENOENT;
	if (get_sha1_hex(hash, &ptr.sha1[0]) != 0)
		return -ENOENT;
	*resultp = gn_alloc(&gitfs_node_root, name);
	if (*resultp == NULL)
		return -ENOMEM;
	return gitobj_lookup_byptr(&ptr, *resultp, GFN_INCOMPLETE,
				   (mode_t) -1, finish_autotree_lookup);
}
