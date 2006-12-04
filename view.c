/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * Note: this structure doesn't need to be refcounted -- we only free it when
 * we're freeing it's "root" node in gn_release_nref().
 */
struct gitfs_view {
	struct gitfs_saved_node root;
	char *symbolic_name;
	char *backing_path;
	struct {
		char *str;	/* not '\0'-terminated */
		size_t len;
	} magic_symlink;
};

int gn_is_viewroot(const struct gitfs_node *gn)
{
	return gn->view != NULL && gn->view->root.gn == gn;
}

static void gitview_destroy(struct gitfs_view *gview)
{
	gn_unsave_node_noref(&gview->root);
	free(gview->symbolic_name);
	free(gview->backing_path);
	free(gview->magic_symlink.str);
	free(gview);
}

void gitview_free(struct gitfs_node *gn)
{
	if (gn_is_viewroot(gn))
		gitview_destroy(gn->view);
}

/* Mark the gnode as the root of a read-only view */
int gitview_start_readonly(struct gitfs_node *gn)
{
	struct gitfs_view *vw;
	size_t nameln;
	unsigned int levelsback;
	char *p;

	assert(gn->type == GFN_DIR);
	if (gn->view != NULL)
		return 0;	/* already setup! */
	vw = calloc(1, sizeof(*(gn->view)));
	if (vw == NULL)
		return -ENOMEM;
	nameln = strlen(gn->name);
	assert(nameln >= HEX_PTR_LEN);
	if (nameln > (HEX_PTR_LEN + 1)) {
		vw->symbolic_name = malloc(nameln - HEX_PTR_LEN);
		if (vw->symbolic_name == NULL) {
			free(vw);
			return -ENOMEM;
		}
		memcpy(vw->symbolic_name, gn->name,
		       nameln - (HEX_PTR_LEN + 1));
		vw->symbolic_name[nameln - (HEX_PTR_LEN + 1)] = '\0';
	}
	levelsback = 1 + gn_dirlevel(gn);
	vw->magic_symlink.len = (levelsback * strlen_const("../")) +
				 relative_path_to_gitdir_len;
	vw->magic_symlink.str = malloc(vw->magic_symlink.len);
	if (vw->magic_symlink.str == NULL) {
		free(vw->symbolic_name);
		free(vw);
		return -ENOMEM;
	}
	p = vw->magic_symlink.str;
	do {
		*p++ = '.';
		*p++ = '.';
		*p++ = '/';
	} while (--levelsback != 0);
	memcpy(p, relative_path_to_gitdir, relative_path_to_gitdir_len);
	gn->view = vw;
	gn_save_node_noref(&gn->view->root, gn);
	return 0;
}

static int git_magic_symlink_readlink(struct gitfs_node *gn,
				      char *result, size_t *rlen)
{
	size_t nlen;

	assert(gn->type == GFN_SYMLINK);
	assert(gn->view != NULL);
	nlen = strlen(gn->name);
	if (*rlen <= nlen + gn->view->magic_symlink.len)
		return -ENAMETOOLONG;
	memcpy(result, gn->view->magic_symlink.str,
	       gn->view->magic_symlink.len);
	memcpy(&result[gn->view->magic_symlink.len], gn->name, nlen);
	*rlen = nlen + gn->view->magic_symlink.len;
	return 0;
}

static size_t git_magic_symlink_link_len(struct gitfs_node *gn)
{
	assert(gn->type == GFN_SYMLINK);
	assert(gn->view != NULL);
	return gn->view->magic_symlink.len + strlen(gn->name);
}

static int git_head_stat(struct gitfs_node *gn, struct stat *sbuf)
{
	assert(gn->type == GFN_FILE);
	assert(gn->view != NULL);
	sbuf->st_size = HEX_PTR_LEN + 1;
	// TODO -- mtime...
	return 0;
}

static int git_head_open(UNUSED_ARG(struct gitfs_node *gn),
			 UNUSED_ARG(unsigned int flags))
{
	return 0;
}

static int git_head_pread(struct gitfs_node *gn,
			  void *buf, size_t size, off_t offset)
{
	struct gitobj_ptr_ascii answer;

	assert(gn->type == GFN_FILE);
	assert(gn->view != NULL);
	assert(offset >= 0);
	if (offset >= sizeof(answer.ascii))
		return 0;
	gitptr_ascii(&answer, &gn->view->root.gn->backing.gobj->hash);
	answer.ascii[sizeof(answer.ascii) - 1] = '\n';
	if (size > sizeof(answer.ascii) - offset)
		size = sizeof(answer.ascii) - offset;
	memcpy(buf, &answer.ascii[offset], size);
	return size;
}

static const struct {
	const char *name;
	enum gitfs_node_type type;
} magic_git_dir_entries[] = {
	{ "objects", GFN_SYMLINK },
	{ "description", GFN_SYMLINK },
	{ "config", GFN_SYMLINK },
	{ "HEAD",  GFN_FILE },
};

static int magic_git_dir_lookup(struct gitfs_node *parent,
				struct gitfs_node **resultp, const char *name)
{
	static const struct gitfs_symlink_ops magic_symlink_ops = {
		.readlink = git_magic_symlink_readlink,
		.link_len = git_magic_symlink_link_len,
	};
	static const struct gitfs_file_ops head_ops = {
		.common = {
			.stat = git_head_stat,
		},
		.open = git_head_open,
		.pread = git_head_pread,
	};
	unsigned int i;

	for (i = 0;
	     i < ((sizeof magic_git_dir_entries) /
		  (sizeof magic_git_dir_entries[0])); i++) {
		if (0 == strcmp(name, magic_git_dir_entries[i].name)) {
			*resultp = gn_alloc(parent, name);
			if (*resultp == NULL)
				return -ENOMEM;
			gn_set_type(*resultp, magic_git_dir_entries[i].type);
			if (magic_git_dir_entries[i].type == GFN_SYMLINK)
				(*resultp)->op.sl = &magic_symlink_ops;
			else
				(*resultp)->op.f = &head_ops;
			return 0;
		}
	}
	return -ENOENT;
}

static int magic_git_dir_readdir(struct gitfs_node *gn,
				 struct api_readdir_state *ars)
{
	unsigned int i;

	for (i = 0;
	     i < ((sizeof magic_git_dir_entries) /
		  (sizeof magic_git_dir_entries[0])); i++)
		(void) gn_add_dir_contents(gn, ars,
					   magic_git_dir_entries[i].name,
					   magic_git_dir_entries[i].type);
	return 0;
}

static int magic_git_dir_stat(struct gitfs_node *gn, struct stat *sbuf)
{
	(void) gn; (void) sbuf;	// TODO -- see what we should do here
	return 0;
}

static const char magic_git_dir[] = ".git";

int gitview_lookup(struct gitfs_node *parent, struct gitfs_node **resultp,
		   const char *name)
{
	assert(parent->view != NULL);
	if (gn_is_viewroot(parent) && 0 == strcmp(name, magic_git_dir)) {
		static const struct gitfs_dir_ops magic_git_dir_ops = {
			.common = {
				.stat = magic_git_dir_stat,
			},
			.lookup = magic_git_dir_lookup,
			.readdir = magic_git_dir_readdir,
		};
		*resultp = gn_alloc(parent, name);
		if (*resultp == NULL)
			return -ENOMEM;
		gn_set_type(*resultp, GFN_DIR);
		(*resultp)->op.d = &magic_git_dir_ops;
		return 0;
	}
	/*
	 * If we decide that we DON'T want to overlay on this file then
	 * we return the magic value ENOTTY.  ENOENT would be more logical
	 * but we want to be able to overlay a "hole" onto the git view
	 */
	return -ENOTTY;
}

void gitview_readdir(struct gitfs_node *gn, struct api_readdir_state *ars)
{
	assert(gn->view != NULL);
	if (gn_is_viewroot(gn))
		(void) gn_add_dir_contents(gn, ars, magic_git_dir, GFN_DIR);
}

void gitview_get_info(struct pcbuf *out, const struct gitfs_view *gview)
{
	struct gs_view_info vinfo;

	memset(&vinfo, 0, sizeof(vinfo));
	vinfo.hash = gview->root.gn->backing.gobj->hash;
	pcbuf_write_obj(out, vinfo);
	pcbuf_write(out, gview->symbolic_name,
		    strlen(gview->symbolic_name) + 1);
}
