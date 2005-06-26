/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fuse.h>
#include "cache.h"

struct api_readdir_state {
	void *buf;
	fuse_fill_dir_t filler;
};

/* Returns non-zero if we failed and can abort the readdir */
int api_add_dir_contents(struct api_readdir_state *ars, const char *name,
			 enum gitfs_node_type type)
{
	static const struct stat is_file = {
		.st_mode = S_IFREG | 0444,
	};
	static const struct stat is_dir = {
		.st_mode = S_IFDIR | 0555,
	};
	static const struct stat is_symlink = {
		.st_mode = S_IFLNK | 0777,
	};
	const struct stat *pst;

	pst = &is_file;
	switch (type) {
	case GFN_DIR:
		pst = &is_dir;
		break;
	case GFN_SYMLINK:
		pst = &is_symlink;
		break;
	case GFN_FILE:
		break;
	default:
		assert(0);
	}
	return ars->filler(ars->buf, name, pst, 0);
}

static uid_t my_uid;
static gid_t my_gid;

static int gitfs_getattr(const char *path, struct stat *sbuf)
{
	struct gitfs_node *gn;
	int res;

	assert(path != NULL);
	assert(sbuf != NULL);
	res = gn_lookup(path, &gn);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	memset(sbuf, 0, sizeof(*sbuf));
	sbuf->st_nlink = 1;
	sbuf->st_uid = my_uid;
	sbuf->st_gid = my_gid;
	sbuf->st_mode = (mode_t) -1;
	if (gn->opc->stat != NULL) {
		res = gn->opc->stat(gn, sbuf);
		if (res != 0) {
			assert(res < 0);
			gn_release(gn);
			return res;
		}
	}
	switch (gn->type) {
	case GFN_FILE:
		if (sbuf->st_mode == (mode_t) -1)
			sbuf->st_mode = 0444;
		sbuf->st_mode |= S_IFREG;
		if (gn->op.f->is_sticky != NULL && gn->op.f->is_sticky(gn))
			sbuf->st_mode |= S_ISVTX;
		break;
	case GFN_DIR:
		if (sbuf->st_mode == (mode_t) -1)
			sbuf->st_mode = 0555;
		sbuf->st_mode |= S_IFDIR;
		sbuf->st_nlink = 2;
		if (gn->op.d->count_subdirs != NULL)
			sbuf->st_nlink += gn->op.d->count_subdirs(gn);
		break;
	case GFN_SYMLINK:
		if (sbuf->st_mode == (mode_t) -1)
			sbuf->st_mode = 0777;
		sbuf->st_mode |= S_IFLNK;
		if (gn->op.sl->link_len != NULL)
			sbuf->st_size = gn->op.sl->link_len(gn);
		break;
	default:
		assert(0);
	}
	gn_release(gn);
	return 0;
}

static int gitfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	struct api_readdir_state ars;
	struct gitfs_node *gn;
	int res;

	assert(path != NULL);
	assert(buf != NULL);
	assert(filler != NULL);
	(void) offset;
	(void) fi;
	res = gn_lookup_type(path, &gn, GFN_DIR);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	ars.buf = buf;
	ars.filler = filler;
	(void) api_add_dir_contents(&ars, ".", GFN_DIR);
	(void) api_add_dir_contents(&ars, "..", GFN_DIR);
	res = gn->op.d->readdir(gn, &ars);
	assert(res <= 0);
	gn_release(gn);
	return res;
}

static int gitfs_readlink(const char *path, char *buf, size_t bufsiz)
{
	struct gitfs_node *gn;
	int res;
	size_t nsz;

	assert(path != NULL);
	assert(buf != NULL);
	res = gn_lookup_type(path, &gn, GFN_SYMLINK);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	nsz = bufsiz;
	res = gn->op.sl->readlink(gn, buf, &nsz);
	assert(res != 0 || nsz < bufsiz);
	gn_release(gn);
	if (res == 0)
		buf[nsz] = '\0';
	return res;
}

static int gitfs_open(const char *path, struct fuse_file_info *fi)
{
	struct gitfs_node *gn;
	int res;

	assert(path != NULL);
	assert(fi != NULL);
	res = gn_lookup_type(path, &gn, GFN_FILE);
	if (res != 0) {
		assert(res < 0);
		return res;
	}
	if (gn->op.f->open == NULL) {
		gn_release(gn);
		return -ENODEV;
	}
	if (gn->op.f->pwrite == NULL &&
	    ((fi->flags & O_ACCMODE) != O_RDONLY)) {
		gn_release(gn);
		return -EROFS;
	}
	res = gn->op.f->open(gn, fi->flags);
	if (res != 0) {
		assert(res < 0);
		gn_release(gn);
		return res;
	}
	fi->fh = (unsigned long) gn;
	return 0;
}

static int gitfs_release(const char *path, struct fuse_file_info *fi)
{
	struct gitfs_node *gn;

	assert(path != NULL);
	assert(fi != NULL);
	assert(fi->fh != 0);
	gn = (struct gitfs_node *) fi->fh;
	assert(gn->type == GFN_FILE);
	if (gn->op.f->close != NULL)
		gn->op.f->close(gn);
	gn_release(gn);
	return 0;
}

static int gitfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	struct gitfs_node *gn;

	assert(path != NULL);
	assert(fi != NULL);
	assert(fi->fh != 0);
	gn = (struct gitfs_node *) fi->fh;
	assert(gn->type == GFN_FILE);
	assert(gn->op.f->pread != NULL);
	return gn->op.f->pread(gn, buf, size, offset);
}

int api_umount(const char *path)
{
	(void) execlp("fusermount", "fusermount", "-u", path, NULL);
	fprintf(stderr, "fatal: cannot find fusemount binary in PATH!\n");
	return 8;
}

int api_mount(const char *path)
{
	static const struct fuse_operations oper = {
		.getattr = gitfs_getattr,
		.readlink = gitfs_readlink,
		.readdir = gitfs_readdir,
		.open = gitfs_open,
		.release = gitfs_release,
		.read = gitfs_read,
#if 0
		.write = gitfs_write,
		.truncate = gitfs_truncate,
		.statfs = gitfs_statfs,
		.utime = gitfs_utime,
		.mkdir = gitfs_mkdir,
		.unlink = gitfs_unlink,
		.rmdir = gitfs_rmdir,
		.rename = gitfs_rename,
		.symlink = gitfs_symlink,
		.link = gitfs_link,
		.chmod = gitfs_chmod,
#endif
	};
	char *args[10];
	int nargs = 0;

	my_uid = getuid();
	my_gid = getgid();
	args[nargs++] = "gitfs";
	if (gitfs_debug != 0)
		args[nargs++] = "-d";
	args[nargs++] = (char *) path;
	args[nargs] = NULL;
	return fuse_main(nargs, args, &oper);
}
