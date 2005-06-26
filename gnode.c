/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

struct gitfs_node *gn_alloc(enum gitfs_node_type type)
{
	struct gitfs_node *gn;

	gn = calloc(1, sizeof(*gn));
	if (gn != NULL) {
		gn->type = type;
		gn->hold_count = 1;
	}
	return gn;
}

void gn_release(struct gitfs_node *gn)
{
	assert(gn->hold_count != 0);
	if (--gn->hold_count == 0) {
		assert(gn->opc->destroy != NULL);
		gn->opc->destroy(gn);
		if (gn->gitobj != NULL)
			gobj_release(gn->gitobj);
		free(gn);
	}
}

int gn_lookup_from(struct gitfs_node *gn, const char *path,
		   struct gitfs_node **resultp)
{
	struct gitfs_node *ogn;
	char elem[PATH_MAX + 1];
	const char *pp;
	int res;

	gn_hold(gn);

	for (;;) {
		if (*path == '/') {	/* Skip leading '/' characters */
			path++;
			continue;
		}
		if (*path == '\0')
			break;
		/* Find next "/" seperator in "path" */
		pp = path;
		do {
			pp++;
		} while (*pp != '/' && *pp != '\0');
		/* Copy this path element to "elem" */
		if ((unsigned int) (pp - path) >= sizeof(elem)) {
			gn_release(gn);
			return -ENAMETOOLONG;
		}
		memcpy(elem, path, pp - path);
		elem[pp - path] = '\0';
		path = pp;
		/* Now search in our current directory for this element */
		ogn = gn;
		if (ogn->type != GFN_DIR) {
			gn_release(ogn);
			return -ENOTDIR;
		}
		res = ogn->op.d->lookup(ogn, &gn, elem);
		gn_release(ogn);
		if (res != 0) {
			assert(res < 0);
			return res;
		}
	}
	*resultp = gn;
	return 0;
}

int gn_lookup_type(const char *path, struct gitfs_node **resultp,
		   enum gitfs_node_type type)
{
	int res;

	res = gn_lookup(path, resultp);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	if ((*resultp)->type == type)
		return 0;	/* Yep, type matched */
	switch (type) {
	case GFN_DIR:
		res = -ENOTDIR;
		break;
	case GFN_SYMLINK:
		res = -EINVAL;
		break;
	case GFN_FILE:
		res = ((*resultp)->type == GFN_DIR) ? -EISDIR : -EINVAL;
		break;
	}
	assert(res < 0);
	gn_release(*resultp);
	return res;
}
