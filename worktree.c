/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <errno.h>

unsigned int worktree_count_subdirs(void)
{
	return 0;	// TODO
}

void worktree_readdir(struct api_readdir_state *ars)
{
	(void) ars; // TODO
}

int worktree_lookup(struct gitfs_node **resultp, const char *name)
{
	(void) resultp; (void) name;// TODO
	return -ENOENT;
}
