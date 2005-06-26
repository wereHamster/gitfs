/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <string.h>
#include <errno.h>
#include <time.h>
#include "cache.h"	/* from git core */

// TODO -- we really need a better data structure than a linked list soon!
struct autotree {
	struct gitobj_ptr ptr;
	struct autotree *next;
	time_t atime;
};
static struct autotree *autotree_root = NULL;
static unsigned int autotree_numdirs = 0;  /* number of directory objects */

static const int automount_expire = 120; /* TODO - make settable, and longer */

unsigned int autotree_count_subdirs(void)
{
	/*
	 * TODO - when we move to a more sane datastructure for autotree,
	 *   doing expires will be almost free.  Therefore we'll do it
	 *   before this AND before readdir
	 */
	return autotree_numdirs;
}

void autotree_readdir(struct api_readdir_state *ars)
{
	static const char xd[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	struct autotree **ap = &autotree_root;
	time_t expire_time;
	const unsigned char *b;
	char name[HEX_PTR_LEN + 1];
	unsigned int i;

	expire_time = time((time_t *) 0) - automount_expire;
	while (*ap != NULL) {
		if ((*ap)->atime <= expire_time) {
			struct autotree *to_free = *ap;
			*ap = (*ap)->next;
			free(to_free);
			assert(autotree_numdirs > 0);
			autotree_numdirs--;
			continue;
		}
		b = &(*ap)->ptr.sha1[0];
		for (i = 0; i < sizeof((*ap)->ptr.sha1); i++) {
			name[(i * 2) + 0] = xd[(b[i] >> 4) & 0xF];
			name[(i * 2) + 1] = xd[(b[i] >> 0) & 0xF];
		}
		assert(i * 2 == HEX_PTR_LEN);
		name[HEX_PTR_LEN] = '\0';
		if (api_add_dir_contents(ars, name, GFN_DIR) != 0)
			break;
		ap = &(*ap)->next;
	}
}

/*
 * If we looked up a directory then we remember it a little while so it
 * shows up in readdir
 */
static int touch_or_add(const struct gitobj_ptr *ptr)
{
	struct autotree **ap;

	for (ap = &autotree_root; *ap != NULL; ap = &(*ap)->next)
		if (0 == memcmp(ptr, &(*ap)->ptr, sizeof(*ptr)))
			goto found;
	/* OK, we didn't find it, try to add a new entry */
	*ap = calloc(1, sizeof(**ap));
	if (*ap == NULL)
		return -ENOMEM;
	autotree_numdirs++;
	memcpy(&(*ap)->ptr, ptr, sizeof(*ptr));
  found:
	(void) time(&(*ap)->atime);
	return 0;
}

int autotree_lookup(struct gitfs_node **resultp, const char *name)
{
	struct gitobj_ptr ptr;
	int ret;

	if (get_sha1_hex(name, &ptr.sha1[0]) != 0 || name[HEX_PTR_LEN] != '\0')
		return -ENOENT;
	ret = gitobj_lookup_byptr(&ptr, resultp, NULL);
	if (ret == 0 && (*resultp)->type == GFN_DIR) {
		ret = touch_or_add(&ptr);
		if (ret != 0)
			gn_release(*resultp);
	}
	return ret;
}
