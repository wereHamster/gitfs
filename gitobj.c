/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#define _XOPEN_SOURCE 500	/* for pread() */
#include "gitfs.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include "cache.h"	/* from git core */

static int gitptr_to_fname(char *buf, size_t bufsiz, const char *dir,
			   const struct gitobj_ptr *gp)
{
	static const char xd[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	const unsigned char *b;
	unsigned int i;

	if (dir != NULL && *dir != '\0') {
		size_t dlen = strlen(dir);
		if (bufsiz <= dlen)
			return -ENAMETOOLONG;
		memcpy(buf, dir, dlen);
		buf += dlen;
		bufsiz -= dlen;
		if (buf[-1] != '/') {
			if (bufsiz < 1)
				return -ENAMETOOLONG;
			*buf++ = '/';
			bufsiz--;
		}
	}
	if (bufsiz < 2 + HEX_PTR_LEN)
		return -ENAMETOOLONG;
	b = &gp->sha1[0];
	for (i = 0; i < sizeof(gp->sha1); i++) {
		*buf++ = xd[(*b >> 4) & 0xF];
		*buf++ = xd[(*b >> 0) & 0xF];
		b++;
		if (i == 0)
			*buf++ = '/';
	}
	*buf = '\0';
	return 0;
}

static void gobj_close_file(struct gitobj *gobj)
{
	assert(gobj->type == GFN_FILE || gobj->type == GFN_SYMLINK);
	if (gobj->d.file.backing_fd >= 0) {
		(void) close(gobj->d.file.backing_fd);
		// TODO - check return value
		gobj->d.file.backing_fd = -1;
	}
}

static void gobj_destroy(struct gitobj *gobj)
{
	switch (gobj->type) {
	case GFN_DIR:
		gitdir_free(&gobj->d.dir);
		break;
	case GFN_FILE:
	case GFN_SYMLINK:
		gobj_close_file(gobj);
		break;
	default:
		assert(0);
	}
	/* TODO: remove from LRU and anything else */
}

void gobj_release(struct gitobj *gobj)
{
	assert(gobj->hold_count != 0);
	if (--gobj->hold_count == 0) {
		gobj_destroy(gobj);
		free(gobj);
	}
}

/*
 * TODO - since creating directory objects can be real expensive we're
 * eventually going to cache them at ->destroy time
 */
static struct gitobj *gobj_cache_lookup(const struct gitobj_ptr *ptr)
{
	(void) ptr;	// TODO - implement
	return NULL;
}

/*
 * We follow the same rules as git's "cat-file" command - we'll automatically
 * consider a "commit" the same as a "tree"
 */
static int raw_resolve_reference(const unsigned char *obuf,
				 unsigned char **nbufp, unsigned long *sizep,
				 const char *ref_str, size_t reflen,
				 char *type)
{
	struct gitobj_ptr nptr;

	if (*sizep < reflen + HEX_PTR_LEN ||
	    0 != memcmp(obuf, ref_str, reflen) ||
	    get_sha1_hex((const char *) &obuf[reflen], &nptr.sha1[0]) != 0)
		return -ENOLINK;
	*nbufp = read_sha1_file(&nptr.sha1[0], type, sizep);
	if (*nbufp == NULL)
		return -ENOENT;
	return 0;
}
#define resolve_reference(obuf, nbufp, sizep, rtype, type)		\
		raw_resolve_reference(obuf, nbufp, sizep,		\
			rtype " ", strlen_const(rtype " "), type)

/*
 * TODO -- it would help A LOT if we had a version of this that got the
 * type and size without actually decoding the file (from the pack header
 * or via zlib magic) but unfortunately the publicly-exposed GIT API doesn't
 * provide us a simple way of doing that.
 *
 * For the common case where we're called from gitobj_from_ptr() there's
 * no need to actually decode the compressed data yet
 */
static int git_read(const struct gitobj_ptr *ptr,
		    unsigned char **bufp, unsigned long *sizep,
		    enum gitfs_node_type *typep)
{
	char type[20];
	unsigned char *buf;
	int res;

	buf = read_sha1_file(&ptr->sha1[0], type, sizep);
	if (buf == NULL)
		return -ENOENT;
	*bufp = buf;
	if (0 == strcmp(type, "tag")) {
		res = resolve_reference(*bufp, &buf, sizep, "object", type);
		free(*bufp);
		if (res != 0) {
			assert(res < 0);
			return res;
		}
		*bufp = buf;
	}
	if (0 == strcmp(type, "commit")) {
		res = resolve_reference(*bufp, &buf, sizep, "tree", type);
		free(*bufp);
		if (res != 0) {
			assert(res < 0);
			return res;
		}
		*bufp = buf;
	}
	if (0 == strcmp(type, "tree")) {
		*typep = GFN_DIR;
	} else if (0 == strcmp(type, "blob")) {
		*typep = GFN_FILE;
		/* Note: this could actually turn out to be a symlink */
	} else {
		free(buf);		/* Unknown type */
		return -EIO;
	}
	return 0;
}

/* NOTE: we DON'T garauntee where the file pointer is in returned object */
static int gobj_open_file(struct gitobj *gobj)
{
	char fname[PATH_MAX];
	int ret, wfd;
	enum gitfs_node_type otype;
	unsigned char *odata;
	unsigned long osize;

	if (gobj->type != GFN_FILE && gobj->type != GFN_SYMLINK) {
		assert(gobj->type == GFN_DIR);
		return -EISDIR;
	}
	if (gobj->d.file.backing_fd >= 0)
		return gobj->d.file.backing_fd;
	ret = gitptr_to_fname(fname, sizeof(fname), ocache_dir, &gobj->hash);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	gobj->d.file.backing_fd = open(fname, O_RDONLY);
	if (gobj->d.file.backing_fd >= 0)
		return gobj->d.file.backing_fd;
	if (errno != ENOENT)
		return neg_errno();
	/* OK, it doesn't exist in cache yet; create it */
	wfd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0444);
	if (wfd < 0 && errno == ENOENT) {
		ret = recursive_mkdir(fname, 1);
		if (ret != 0) {
			assert(ret < 0);
			return ret;
		}
		wfd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0444);
	}
	if (wfd < 0)
		return neg_errno();
	// TODO - deal w/ errno==EEXIST a bit better
	// TODO - probably we should make it in a temporary filename and
	//  then move it into place so it's not visible until complete
	ret = git_read(&gobj->hash, &odata, &osize, &otype);
	if (ret == 0) {
		if (otype != GFN_FILE)
			ret = -EISDIR;
		else
			ret = write_safe(wfd, odata, osize);
	}
	if (ret != 0) {
		assert(ret < 0);
		(void) close(wfd);
		(void) unlink(fname);
		return ret;
	}
	if (close(wfd) != 0) {
		(void) unlink(fname);
		return neg_errno();
	}
	gobj->d.file.backing_fd = open(fname, O_RDONLY);
	if (gobj->d.file.backing_fd < 0)
		return neg_errno();	/* Weird! */
	return gobj->d.file.backing_fd;
}

static int gitfile_stat(struct gitobj *gobj, struct stat *sbuf)
{
	char fname[PATH_MAX];
	int ret;

	assert(gobj->type == GFN_FILE || gobj->type == GFN_SYMLINK);
	/* First, if we already have the file open, just use fstat */
	if (gobj->d.file.backing_fd >= 0) {
		if (fstat(gobj->d.file.backing_fd, sbuf) != 0)
			return neg_errno();
		return 0;
	}
	/* Next, if the object is the ocache, stat the ocache file */
	ret = gitptr_to_fname(fname, sizeof(fname), ocache_dir, &gobj->hash);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	ret = stat(fname, sbuf);
	if (ret == 0)
		return 0;
	if (errno != ENOENT)
		return neg_errno();
	/*
	 * If we don't have it in ocache just grab the size and use the
	 * atime that we already got from the backing git file
	 */
	sbuf->st_atime = 0;
	sbuf->st_size = gobj->d.file.size;
	return 0;
}

static int gitobj_stat(struct gitfs_node *gn, struct stat *sbuf)
{
	char fname[PATH_MAX];
	int ret;
	struct stat bst;

	assert(gn != NULL);
	assert(gn->gitobj != NULL);
	sbuf->st_mode = gn->gitobj->perm;
	ret = gitptr_to_fname(fname, sizeof(fname), "objects",
			      &gn->gitobj->hash);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	if (stat(fname, &bst) != 0) {
		struct packed_git *pg;
		if (errno != ENOENT)
			return neg_errno();
		/*
		 * If the backing sha1 file wasn't found it's likely that
		 * it's part of a git pack; just use the times on the pack
		 * file in that case
		 */
		pg = find_sha1_pack(&gn->gitobj->hash.sha1[0], packed_git);
		if (pg == NULL)
			return -ENOENT;
		if (stat(pg->pack_name, &bst) != 0)
		  	return neg_errno();
	}
	sbuf->st_ctime = bst.st_ctime;
	sbuf->st_atime = bst.st_atime;
	sbuf->st_mtime = bst.st_mtime;
	switch (gn->type) {
	case GFN_FILE:
	case GFN_SYMLINK:
		ret = gitfile_stat(gn->gitobj, &bst);
		if (ret != 0) {
			assert(ret < 0);
			return ret;
		}
		sbuf->st_size = bst.st_size;
		if (bst.st_atime > sbuf->st_atime)
			sbuf->st_atime = bst.st_atime;
		break;
	case GFN_DIR:
		{
			const struct gitdir *gd = &gn->gitobj->d.dir;
			assert(gn->gitobj->type == GFN_DIR);
			sbuf->st_atime = gd->atime;
			/* Old school UNIX: */
			sbuf->st_size = 16 * gd->nentries;
		}
		break;
	default:
		assert(0);
	}
	return 0;
}

static void gitobj_destroy(struct gitfs_node *gn)
{
	/*
	 * We don't need to do anything here since we keep all our private
	 * data in gn->gitobj which is reference counted and handled by the
	 * gnode layer
	 */
	(void) gn;
}

static int gitobj_open(struct gitfs_node *gn, unsigned int flags)
{
	int fd;

	(void) flags;		/* We're always read only */
	assert (gn->type == GFN_FILE);
	assert (gn->gitobj->type == GFN_FILE);
	fd = gobj_open_file(gn->gitobj);
	return (fd >= 0) ? 0 : fd;
}

static void gitobj_close(struct gitfs_node *gn)
{
	assert (gn->type == GFN_FILE);
	assert (gn->gitobj->type == GFN_FILE);
	gobj_close_file(gn->gitobj);
}

static int gitobj_pread(struct gitfs_node *gn,
			void *buf, size_t size, off_t offset)
{
	int fd;
	ssize_t rr;

	assert (gn->type == GFN_FILE);
	assert (gn->gitobj->type == GFN_FILE);
	fd = gobj_open_file(gn->gitobj);
	if (fd < 0)
		return fd;
	rr = pread(fd, buf, size, offset);
	return (rr < 0) ? neg_errno() : rr;
}

static int gitobj_lookup(struct gitfs_node *parent,
			 struct gitfs_node **resultp, const char *name)
{
	const struct gitdir_entry *e;

	assert (parent->type == GFN_DIR);
	assert (parent->gitobj->type == GFN_DIR);
	e = gitdir_find(&parent->gitobj->d.dir, name);
	if (e == NULL)
		return -ENOENT;
	return gitobj_lookup_byptr(e->ptr, resultp, e);
}

static int gitobj_readdir(struct gitfs_node *gn,
			  struct api_readdir_state *ars)
{
	assert (gn->type == GFN_DIR);
	assert (gn->gitobj->type == GFN_DIR);
	gitdir_readdir(&gn->gitobj->d.dir, ars);
	return 0;
}

static unsigned int gitobj_count_subdirs(struct gitfs_node *gn)
{
	assert (gn->type == GFN_DIR);
	assert (gn->gitobj->type == GFN_DIR);
	return gn->gitobj->d.dir.nsubdirs;
}

static int gitobj_readlink(struct gitfs_node *gn, char *result, size_t *rlen)
{
	struct stat bst;
	int fd, ret;
	ssize_t rr;

	assert (gn->type == GFN_SYMLINK);
	assert (gn->gitobj->type == GFN_SYMLINK);
	fd = gobj_open_file(gn->gitobj);
	if (fd < 0)
		return fd;
	if (fstat(fd, &bst) != 0) {
		ret = neg_errno();
		gobj_close_file(gn->gitobj);
		return ret;
	}
	if (*rlen <= bst.st_size) {
		gobj_close_file(gn->gitobj);
		return -ENAMETOOLONG;
	}
	*rlen = bst.st_size;
	rr = pread(fd, result, bst.st_size, 0);
	ret = (rr < 0) ? neg_errno() : (rr != bst.st_size) ? -EIO : 0;
	gobj_close_file(gn->gitobj);
	return ret;
}

static int gitobj_to_gnode(struct gitobj *gobj, struct gitfs_node **resultp)
{
	static const struct gitfs_common_ops common_ops = {
		.stat = gitobj_stat,
		.destroy = gitobj_destroy,
	};
	static const struct gitfs_file_ops file_ops = {
		.open = gitobj_open,
		.close = gitobj_close,
		.pread = gitobj_pread,
	};
	static const struct gitfs_dir_ops dir_ops = {
		.lookup = gitobj_lookup,
		.readdir = gitobj_readdir,
		.count_subdirs = gitobj_count_subdirs,
	};
	static const struct gitfs_symlink_ops symlink_ops = {
		.readlink = gitobj_readlink,
		/* No need for .link_len(); we handle that in .stat() */
	};

	(*resultp) = gn_alloc(gobj->type);
	if (*resultp == NULL)
		return -ENOMEM;
	(*resultp)->gitobj = gobj;
	gobj_hold(gobj);
	(*resultp)->opc = &common_ops;
	switch (gobj->type) {
	case GFN_FILE:
		(*resultp)->op.f = &file_ops;
		break;
	case GFN_DIR:
		(*resultp)->op.d = &dir_ops;
		break;
	case GFN_SYMLINK:
		(*resultp)->op.sl = &symlink_ops;
		break;
	default:
		assert(0);
	}
	return 0;
}

static int gitobj_from_ptr(struct gitobj **gop, const struct gitobj_ptr *ptr)
{
	struct gitobj *gobj;
	unsigned char *buf;
	unsigned long size;
	int ret;

	gobj = gobj_cache_lookup(ptr);
	if (gobj != NULL) {
		// ...
		*gop = gobj;
		return 0;
	}

	gobj = calloc(1, sizeof(*gobj));
	if (gobj == NULL)
		return -ENOMEM;
	memcpy(&gobj->hash, ptr, sizeof(gobj->hash));
	gobj->hold_count = 1;
	// TODO -- add to lru

	ret = git_read(ptr, &buf, &size, &gobj->type);
	if (ret != 0) {
		assert(ret < 0);
		free(gobj);
		return ret;
	}
	switch (gobj->type) {
	case GFN_DIR:
		ret = gitdir_parse(&gobj->d.dir, buf, size);
		if (ret != 0) {
			assert(ret < 0);
			free(buf);
			free(gobj);
			return ret;
		}
		// TODO - we really should grab the atime() from the
		// backing file before we read it or something... not
		// a big deal, though
		(void) time(&gobj->d.dir.atime);
		/*
		 * NOTE: we don't free(buf) here since the directory takes
		 * ownership of it as ->d.dir.backing_file; it's free'd
		 * when the object is destroyed
		 */
		break;
	case GFN_FILE:
		gobj->d.file.backing_fd = -1;
		gobj->d.file.size = size;
		free(buf);
		break;
	default:
		assert(0);
	}
	*gop = gobj;
	return 0;
}

int gitobj_lookup_byptr(const struct gitobj_ptr *ptr,
			struct gitfs_node **resultp,
			const struct gitdir_entry *dirent)
{
	struct gitobj *gobj;
	int ret;

	ret = gitobj_from_ptr(&gobj, ptr);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	if (dirent != NULL) {
		/*
		 * Certain information (permissions, symlink, ...) are stored
		 * in the directory entry
		 */
		gobj->perm = dirent->perm;
		if (gobj->type == GFN_FILE && dirent->type == GFN_SYMLINK)
			gobj->type = GFN_SYMLINK;
		if (gobj->type != dirent->type) {
			gobj_release(gobj);
			return -EIO;
		}
	} else {
		/*
		 * If we don't have an associated directory entry for this
		 * element (since we're looking it up directly from the
		 * hex values) just let fuseapi.c assign default permissions.
		 * Note that this also means that we'll see symlinks as
		 * normal files; that can't be prevented
		 */
		gobj->perm = (mode_t) -1;
	}
	ret = gitobj_to_gnode(gobj, resultp);
	assert(ret <= 0);
	gobj_release(gobj);
	return ret;
}
