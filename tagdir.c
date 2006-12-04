/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
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
#include <sys/stat.h>

struct git_tag {
	unsigned int levels_back;	/* Number of "../" to put in link */
	struct gitobj_ptr obj;
	struct timespec ctim, atim, mtim;
};

static int tag_stat(struct gitfs_node *gn, struct stat *st)
{
	assert(gn->type == GFN_SYMLINK);
	assert(gn->priv.gt != NULL);
	st->st_ctim = gn->priv.gt->ctim;
	st->st_atim = gn->priv.gt->atim;
	st->st_mtim = gn->priv.gt->mtim;
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

#define NEEDS_ESCAPING(c) (((c) == ':' || (c) == '\\'))

static size_t strlen_w_escaping(const char *s)
{
	size_t result;

	for (result = 0; *s != '\0'; s++)
		result += NEEDS_ESCAPING(*s) ? 2 : 1;
	return result;
}

static size_t tag_link_len(struct gitfs_node *gn)
{
	struct git_tag *gt = gn->priv.gt;
	size_t result;

	assert(gn->type == GFN_SYMLINK);
	assert(gt != NULL);
	result = (gt->levels_back * strlen_const("../")) + HEX_PTR_LEN;
	do {
		result += 1 + strlen_w_escaping(gn->name);
		gn = gn->parent;
	} while (gn != &gitfs_node_root);
	return result;
}

static void add_escaped_name(char **p, const struct gitfs_node *gn)
{
	const char *n;

	if (gn == &gitfs_node_root)
		return;
	add_escaped_name(p, gn->parent);
	for (n = gn->name; *n != '\0'; n++) {
		if (NEEDS_ESCAPING(*n))
			*(*p)++ = '\\';
		*(*p)++ = *n;
	}
	*(*p)++ = ':';
}

static int tag_readlink(struct gitfs_node *gn, char *result, size_t *rlen)
{
	struct git_tag *gt = gn->priv.gt;
	char *p = result;
	unsigned int i;
	const unsigned char *b;

	assert(gn->type == GFN_SYMLINK);
	assert(gt != NULL);
	if (*rlen <= tag_link_len(gn))
		return -ENAMETOOLONG;
	for (i = 0; i < gt->levels_back; i++) {
		static const char dot_dot_slash[] = { '.', '.', '/' };
		memcpy(p, dot_dot_slash, sizeof(dot_dot_slash));
		p += sizeof(dot_dot_slash);
	}
	add_escaped_name(&p, gn);
	b = &gt->obj.sha1[0];
	for (i = 0; i < sizeof(gt->obj.sha1); i++) {
		*p++ = xdigit_lc[(*b >> 4) & 0xF];
		*p++ = xdigit_lc[(*b >> 0) & 0xF];
		b++;
	}
	*rlen = p - result;
	return 0;
}

struct git_tag_dir {
	const char *path;
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
	static const struct gitfs_symlink_ops symlink_ops = {
		.common = {
			.stat = tag_stat,
			.destroy = tag_destroy,
		},
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
	gt->ctim = bst.st_ctim;
	gt->atim = bst.st_atim;
	gt->mtim = bst.st_mtim;
	*resultp = gn_alloc(parent, name);
	if (*resultp == NULL) {
		free(gt);
		return -ENOMEM;
	}
	(*resultp)->type = GFN_SYMLINK;
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

	assert(gn->type == GFN_DIR);
	assert(gn->priv.gtd != NULL);
	assert(gn->priv.gtd->path != NULL);
	dp = opendir(gn->priv.gtd->path);
	if (dp == NULL)
		return neg_errno();
	for (;;) {
		struct stat st;
		char bfile[PATH_MAX];
		struct dirent *de = readdir(dp);
		if (de == NULL)
			break;
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
		if (gn_add_dir_contents(gn, ars,
					de->d_name, GFN_SYMLINK) != 0)
			break;
	}
	if (closedir(dp) != 0)
		return neg_errno();
	return 0;
}

#define DEFINE_TAGDIR(tname, tpath)					\
		{ .name = tname, .priv = { .path = tpath } }
static struct {
	const char *name;
	struct git_tag_dir priv;
	struct gitfs_node *gn;
} tagdirs[] = {
	DEFINE_TAGDIR("TAGS", "refs/tags"),
	DEFINE_TAGDIR("HEADS", "refs/heads"),
};
#define num_tagdirs	(sizeof(tagdirs) / sizeof(tagdirs[0]))

int tagroot_lookup(struct gitfs_node **resultp, const char *name)
{
	static const struct gitfs_dir_ops tagdir_dir_ops = {
		.common = {
			.stat = tagdir_stat,
		},
		.lookup = tagdir_lookup,
		.readdir = tagdir_readdir,
	};
	unsigned int i;

	for (i = 0; i < num_tagdirs; i++)
		if (0 == strcmp(name, tagdirs[i].name)) {
			assert(tagdirs[i].gn == NULL);
			tagdirs[i].gn = gn_alloc(&gitfs_node_root, name);
			*resultp = tagdirs[i].gn;
			if (*resultp == NULL)
				return -ENOMEM;
			gn_set_type(*resultp, GFN_DIR);
			(*resultp)->op.d = &tagdir_dir_ops;
			(*resultp)->priv.gtd = &tagdirs[i].priv;
			/*
			 * We take an extra reference so this gnode will
			 * stick around forever
			 */
			gn_hold(*resultp);
			return 0;
		}
	return -ENOENT;
}

void tagroot_readdir(struct api_readdir_state *ars)
{
	unsigned int i;

	for (i = 0; i < num_tagdirs; i++)
		if (api_add_dir_contents(ars, tagdirs[i].name, GFN_DIR,
			(tagdirs[i].gn == NULL) ? (uint64_t) -1
						: tagdirs[i].gn->inum) != 0)
			break;
}

unsigned int tagroot_count_subdirs(void)
{
	return num_tagdirs;
}
