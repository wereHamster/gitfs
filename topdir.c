/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <errno.h>
#include <stdlib.h>

static int topdir_lookup(struct gitfs_node *parent,
			 struct gitfs_node **resultp, const char *name)
{
	int ret;

	assert(parent == &gitfs_node_root);
	ret = tagroot_lookup(resultp, name);
	if (ret == -ENOENT)
		ret = autotree_lookup(resultp, name);
	if (ret == -ENOENT)
		worktree_lookup(resultp, name);
	assert(ret <= 0);
	return ret;
}

static int topdir_readdir(struct gitfs_node *gn,
			  struct api_readdir_state *ars)
{
	assert(gn == &gitfs_node_root);
	tagroot_readdir(ars);
	worktree_readdir(ars);
	autotree_readdir(ars);
	return 0;
}

static unsigned int topdir_count_subdirs(struct gitfs_node *gn)
{
	assert(gn == &gitfs_node_root);
	return tagroot_count_subdirs()
			+ autotree_count_subdirs()
			+ worktree_count_subdirs();
}

static void topdir_destroy(UNUSED_ARG(struct gitfs_node *gn))
	 __attribute__ ((noreturn));
static void topdir_destroy(UNUSED_ARG(struct gitfs_node *gn))
{
	/*
	 * Since we always keep a hold on the topdir held we should
	 * never get destroyed
	 */
	abort();
}

static const struct gitfs_dir_ops topdir_dir_ops = {
	.common = {
		.destroy = topdir_destroy,
	},
	.lookup = topdir_lookup,
	.readdir = topdir_readdir,
	.count_subdirs = topdir_count_subdirs,
};

struct gitfs_node gitfs_node_root = {
	.type = GFN_DIR,
	.op.d = &topdir_dir_ops,
	.hold_count = 1,
	.inum = 0,
	.parent = &gitfs_node_root,
	.t.d = {
		.children = EMPTY_RBTREE,
	},
};
