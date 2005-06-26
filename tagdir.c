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
#include <fcntl.h>
#include <dirent.h>

struct git_tag {
	unsigned int levels_back;	/* Number of "../" to put in link */
	struct gitobj_ptr obj;
	time_t ctime, atime, mtime;
};

static int tag_stat(struct gitfs_node *gn, struct stat *st)
{
	assert(gn->type == GFN_SYMLINK);
	assert(gn->priv.gt != NULL);
	st->st_ctime = gn->priv.gt->ctime;
	st->st_atime = gn->priv.gt->atime;
	st->st_mtime = gn->priv.gt->mtime;
	return 0;
}

/*
 * Since our ->git_tag structure is dynamically allocated we must free
 * in on last gn_release()
 */
static void tag_destroy(struct gitfs_node *gn)
{
	assert(gn->type == GFN_SYMLINK);
	assert(gn->priv.gt != NULL);
	free(gn->priv.gt);
}

static size_t tag_link_len(struct gitfs_node *gn)
{
	struct git_tag *gt = gn->priv.gt;

	assert(gn->type == GFN_SYMLINK);
	assert(gt != NULL);

	return (gt->levels_back * strlen_const("../")) + HEX_PTR_LEN;
}

static int tag_readlink(struct gitfs_node *gn, char *result, size_t *rlen)
{
	static const char xd[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	struct git_tag *gt = gn->priv.gt;
	char *p = result;
	unsigned int i;
	const unsigned char *b;

	assert(gn->type == GFN_SYMLINK);
	assert(gt != NULL);
	if (*rlen <= tag_link_len(gn))
		return -ENAMETOOLONG;
	for (i = 0; i < gt->levels_back; i++) {
		memcpy(p, "../", strlen_const("../"));
		p += strlen_const("../");
	}
	b = &gt->obj.sha1[0];
	for (i = 0; i < sizeof(gt->obj.sha1); i++) {
		*p++ = xd[(*b >> 4) & 0xF];
		*p++ = xd[(*b >> 0) & 0xF];
		b++;
	}
	*rlen = p - result;
	return 0;
}

struct git_tag_dir {
	const char *path;
	// TODO - store strlen(path)?
	// struct git_tag_link *root;	// TODO - needed?
	// time_t dir_mtime;		// TODO - needed?
};

static int tagdir_stat(struct gitfs_node *gn, struct stat *st)
{
	struct stat bst;

	assert(gn->type == GFN_DIR);
	assert(gn->priv.gtd != NULL);
	assert(gn->priv.gtd->path != NULL);
	if (stat(gn->priv.gtd->path, &bst) == 0) {
		st->st_mtime = bst.st_mtime;
		st->st_atime = bst.st_atime;
		st->st_ctime = bst.st_ctime;
	}
	return 0;
}

static int tagdir_lookup(struct gitfs_node *parent,
			 struct gitfs_node **resultp, const char *name)
{
	static const struct gitfs_common_ops common_ops = {
		.stat = tag_stat,
		.destroy = tag_destroy,
	};
	static const struct gitfs_symlink_ops symlink_ops = {
		.readlink = tag_readlink,
		.link_len = tag_link_len,
	};
	char bfile[PATH_MAX];
	struct stat bst;
	struct git_tag *gt;
	int fd, res;

	assert(parent->type == GFN_DIR);
	assert(parent->priv.gtd != NULL);
	assert(parent->priv.gtd->path != NULL);
	res = create_fullpath(bfile, sizeof(bfile),
			      parent->priv.gtd->path, name);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	if (stat(bfile, &bst) != 0)
		return neg_errno();
	if (!S_ISREG(bst.st_mode))
		return -ENOENT;		/* We only are looking for files */
	gt = calloc(1, sizeof(*gt));
	if (gt == NULL)
		return -ENOMEM;
	gt->levels_back = 1;
	gt->ctime = bst.st_ctime;
	gt->atime = bst.st_atime;
	gt->mtime = bst.st_mtime;
	*resultp = gn_alloc(GFN_SYMLINK);
	if (*resultp == NULL) {
		free(gt);
		return -ENOMEM;
	}
	(*resultp)->opc = &common_ops;
	(*resultp)->op.sl = &symlink_ops;
	(*resultp)->priv.gt = gt;
	fd = open(bfile, O_RDONLY);
	if (fd < 0) {
		gn_release(*resultp);
		return neg_errno();
	}
	res = read_ptr(fd, &gt->obj);
	if (res != 0) {
		assert(res < 0);
		gn_release(*resultp);
		return res;
	}
	if (close(fd) != 0) {
		gn_release(*resultp);
		return neg_errno();
	}
	return 0;
}

static int tagdir_readdir(struct gitfs_node *gn,
			  struct api_readdir_state *ars)
{
	DIR *dp;
	struct dirent *de;
	struct stat st;
	char bfile[PATH_MAX];

	assert(gn->type == GFN_DIR);
	assert(gn->priv.gtd != NULL);
	assert(gn->priv.gtd->path != NULL);
	dp = opendir(gn->priv.gtd->path);
	if (dp == NULL)
		return neg_errno();
	for (;;) {
		de = readdir(dp);
		if (de == NULL)
			break;
		// TODO - it would be more efficient to just copy dir once
		if (create_fullpath(bfile, sizeof(bfile),
				    gn->priv.gtd->path, de->d_name) != 0)
			continue;
		if (stat(bfile, &st) != 0)
			continue;
		if (!S_ISREG(st.st_mode))
			continue;	/* We only are looking for files */
		/*
		 * We're looking for files that just contain a sha1 hash
		 * and maybe 1-2 bytes of whitespace.  We don't want to
		 * be slow and open them all, but we do skip ones that are
		 * obviously the wrong length
		 */
		if (st.st_size < HEX_PTR_LEN)
			continue;
		if (st.st_size > HEX_PTR_LEN + 2)
			continue;
		if (api_add_dir_contents(ars, de->d_name, GFN_SYMLINK) != 0)
			break;
	}
	if (closedir(dp) != 0)
		return neg_errno();
	return 0;
}

static const struct gitfs_common_ops tagdir_common_ops = {
	.stat = tagdir_stat,
};
static const struct gitfs_dir_ops tagdir_dir_ops = {
	.lookup = tagdir_lookup,
	.readdir = tagdir_readdir,
};

/* Stuff for the TAGS/ directory */
static struct git_tag_dir dirinfo_tags = {
	.path = "refs/tags",
};
static struct gitfs_node tagdir_tags = {
	.type = GFN_DIR,
	.opc = &tagdir_common_ops,
	.op.d = &tagdir_dir_ops,
	.hold_count = 1,
	.priv.gtd = &dirinfo_tags,
};
/* Ditto for the HEADS/ directory */
static struct git_tag_dir dirinfo_heads = {
	.path = "refs/heads",
};
static struct gitfs_node tagdir_heads = {
	.type = GFN_DIR,
	.opc = &tagdir_common_ops,
	.op.d = &tagdir_dir_ops,
	.hold_count = 1,
	.priv.gtd = &dirinfo_heads,
};

/*
 * This is what binds our statically-defined gitfs_nodes to an actual
 * location in the root directory
 */
static struct {
	const char *name;
	struct gitfs_node *node;
} tagdirs[] = {
	{ "TAGS", &tagdir_tags },
	{ "HEADS", &tagdir_heads },
};
#define num_tagdirs	(sizeof(tagdirs) / sizeof(tagdirs[0]))

int tagroot_lookup(struct gitfs_node **resultp, const char *name)
{
	unsigned int i;

	for (i = 0; i < num_tagdirs; i++)
		if (0 == strcmp(name, tagdirs[i].name)) {
			*resultp = tagdirs[i].node;
			gn_hold(*resultp);
			return 0;
		}
	return -ENOENT;
}

void tagroot_readdir(struct api_readdir_state *ars)
{
	unsigned int i;

	for (i = 0; i < num_tagdirs; i++)
		if (api_add_dir_contents(ars, tagdirs[i].name, GFN_DIR) != 0)
			break;
}

unsigned int tagroot_count_subdirs(void)
{
	return num_tagdirs;
}
