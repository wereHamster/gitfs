/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#define _GNU_SOURCE	/* for pread() */
#include "gitfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

static inline void gobj_close_file(struct gitobj *gobj)
{
	assert(gobj->type == GFN_FILE);
	if (--gobj->open_count == 0)
		openfile_close(&gobj->d.file.of);
}

struct gitobj_pending_request {
	struct gitwork_cmd cmd;		/* must be first! */
	struct api_request *req;
	struct gitfs_saved_node sn;
	struct gitobj_pending_request *next;
	union {
		int (*openread)(int fd, void *buf, size_t size, off_t offset);
		int (*lookup)(int error, struct gitfs_node *gn);
	} finish;
	union {
		struct {
			size_t size;
			off_t offset;
		} readinfo;
		struct {
			enum gitfs_node_type de_type;
		} lookup;
		struct {
			struct stat *result_buf;
		} stat;
	} op;
};

/*
 * Allocate a new request for work which is waiting on the gitworker thread
 * and ask the FS api layer to save the current request.  After the structure
 * is filled in a little more it must be passed to gitwork_queue() to actually
 * send it to gitworker
 */
static struct gitobj_pending_request *gitwork_new(struct gitfs_node *gn)
{
	struct gitobj_pending_request *pr = calloc(1, sizeof(*pr));

	if (pr != NULL) {
		pr->req = api_save_request(gn);
		if (pr->req == NULL) {
			free(pr);
			pr = NULL;
		} else
			gn_save_node(&pr->sn, gn);
	}
	return pr;
}

static void gitwork_free(struct gitobj_pending_request *pr)
{
	gn_unsave_node(&pr->sn);
	free(pr);
}

/*
 * Either send a request to the gitworker thread or add it to the list of
 * "already pending" requests for a gitobj
 */
static void gitwork_queue(struct gitobj *gobj,
			  struct gitobj_pending_request *pr)
{
	gdbg("  ::GITWORK queued opcode=0x%X, gn=0x%p, first=%s",
	     pr->cmd.opcode, pr->sn.gn,
	     (gobj->pending == NULL) ? "yes" : "no");
	pr->cmd.gptr = &gobj->hash;
	if (likely(gobj->pending == NULL)) {
		pr->next = NULL;
		gobj->pending = pr;
		gitwork_add(&pr->cmd);
		return;
	}
	/*
	 * If there's already a pending request we don't actually pass it
	 * to the gitworker thread; instead we just insert this one into
	 * the list and wake up with -EAGAIN when the primary request is
	 * finished.  This way we prevent having the gitworker thread do
	 * redundant work
	 */
	pr->next = gobj->pending->next;
	gobj->pending->next = pr;
}

static int gobj_finish_pread(int fd, void *buf, size_t size, off_t offset)
{
	ssize_t rr = pread(fd, buf, size, offset);

	return (rr < 0) ? neg_errno() : rr;
}

static int gobj_finish_readlink(int fd, void *buf, size_t size,
				UNUSED_ARG(off_t offset))
{
	struct stat bst;
	ssize_t rr;

	assert(offset == 0);
	if (fstat(fd, &bst) != 0)
		return neg_errno();
	if (size <= bst.st_size)
		return -ENAMETOOLONG;
	rr = pread(fd, buf, bst.st_size, 0);
	return (rr != bst.st_size) ? -EIO : rr;
}

static inline int ocache_fname(char *out, size_t outlen,
			       const struct gitobj *gobj)
{
	return gitptr_to_fname(out, outlen, ocache_dir, &gobj->hash);
}

/*
 * Attempts to open a gitobj's backing file in ocache -- if it isn't
 * available right now asks the gitworker thread to make it available and
 * returns -EINPROGRESS.  Normally the "pr" argument will be NULL unless
 * we're retrying after a queued request -- in that rare case we want to
 * make sure we don't call api_save_request() again so we re-use the
 * gitobj_pending_request structure
 *
 * If this is a request to do a read instead of just an open then
 * buf/size/offset need to be set; otherwise they should just be zeroed
 */
static int gobj_openread_or_defer(struct gitfs_node *gn,
	struct gitobj_pending_request *pr,
	int (*finish)(int errfd, void *buf, size_t size, off_t offset),
	void *buf, size_t size, off_t offset)
{
	char fname[PATH_MAX];
	int ret;

	if (gn->backing.gobj->type != GFN_FILE) {
		assert(gn->backing.gobj->type == GFN_DIR);
		return -EISDIR;
	}
	ret = openfile_fd(&gn->backing.gobj->d.file.of);
	if (likely(ret >= 0)) {
	    got_fd:
		if (finish == NULL)
			return 0;	/* just an open() request */
		return finish(ret, buf, size, offset);
	}
	ret = ocache_fname(fname, sizeof(fname), gn->backing.gobj);
	if (unlikely(ret != 0)) {
		assert(ret < 0);
		return ret;
	}
	ret = openfile_open(&gn->backing.gobj->d.file.of, fname);
	if (likely(ret >= 0))
		goto got_fd;
	if (unlikely(ret != -ENOENT))
		return ret;
	/*
	 * OK, the object isn't in cache yet; ask the gitworker thread to
	 * put it there
	 */
	if (likely(pr == NULL)) {
		pr = gitwork_new(gn);
		if (pr == NULL)
			return -ENOMEM;
		pr->cmd.opcode = GITWORKER_ADD_TO_OCACHE;
		pr->finish.openread = finish;
		pr->op.readinfo.size = size;
		pr->op.readinfo.offset = offset;
	}
	gitwork_queue(gn->backing.gobj, pr);
	return -EINPROGRESS;
}

static void finish_defered_open(struct gitobj_pending_request *pr)
{
	static void *read_buf = NULL;
	static size_t read_buf_len = 0;
	int ret;

	if (unlikely(pr->cmd.error != 0 && pr->cmd.error != -EAGAIN)) {
		ret = pr->cmd.error;
		assert(ret < 0);
		goto error;
	}
	/* We need to allocate our own buffer -- the original one is gone */
	if (pr->finish.openread != NULL &&
	    unlikely(read_buf_len < pr->op.readinfo.size)) {
		void *n = realloc(read_buf, pr->op.readinfo.size);
		if (n == NULL) {
			ret = -ENOMEM;
			goto error;
		}
		read_buf = n;
		read_buf_len = pr->op.readinfo.size;
	}
	ret = gobj_openread_or_defer(pr->sn.gn, pr, pr->finish.openread,
			 (pr->finish.openread != NULL) ? read_buf : NULL,
			 pr->op.readinfo.size, pr->op.readinfo.offset);
	if (unlikely(ret < 0)) {
		/*
		 * It's actually theoretically possible for the file to go
		 * missing out of ocache while we were waiting to be woken
		 * up -- in that case we simply will have been re-queued
		 */
		if (unlikely(ret == -EINPROGRESS))
			return;
	    error:
		/*
		 * Error case -- if we weren't a pread we need to undo
		 * the increment of open_count
		 */
		if (pr->finish.openread != gobj_finish_pread)
			gobj_close_file(pr->sn.gn->backing.gobj);
	    return_no_data:
		api_complete_saved_request(pr->req, ret, NULL, 0);
	} else {		/* Non-error case */
		/* If we were an open command we don't want to return data */
		if (pr->finish.openread == NULL) {
			assert(ret == 0);
			goto return_no_data;
		}
		/*
		 * For non-error cases we DO want to keep the file open
		 * UNLESS it was a readlink (since there will not be a
		 * matching close() call)
		 */
		if (unlikely(pr->finish.openread == gobj_finish_readlink))
			gobj_close_file(pr->sn.gn->backing.gobj);
		api_complete_saved_request(pr->req, 0, read_buf, ret);
	}
	gitwork_free(pr);
}

static int gobj_stat_or_defer(struct gitfs_node *gn,
			      char *backing_file, struct stat *sbuf)
{
	char fname[PATH_MAX];
	struct stat bst;
	int ret;

	if (backing_file == NULL) {
		ret = gitptr_to_fname(fname, sizeof(fname), "objects",
				      &gn->backing.gobj->hash);
		if (unlikely(ret != 0)) {
			assert(ret < 0);
			return ret;
		}
		backing_file = fname;
	}
	assert(backing_file != NULL);
	if (stat(backing_file, &bst) != 0) {
		ret = neg_errno();
		/*
		 * If we just looked for the given file in the objects/
		 * directory and didn't find it it could be because its a
		 * member of a pack.  Ask the gitworker to find it for us
		 */
		if (ret == -ENOENT && backing_file == fname) {
			struct gitobj_pending_request *pr;
			pr = gitwork_new(gn);
			if (pr == NULL)
				return -ENOMEM;
			pr->cmd.opcode = GITWORKER_FIND_PACKNAME;
			pr->op.stat.result_buf = sbuf;
			gitwork_queue(gn->backing.gobj, pr);
			return -EINPROGRESS;
		}
		return ret;
	}
	sbuf->st_ctime = bst.st_ctime;
	sbuf->st_atime = bst.st_atime;
	sbuf->st_mtime = bst.st_mtime;
	switch (gn->type) {
	case GFN_FILE:
	case GFN_SYMLINK:
		assert(gn->backing.gobj->type == GFN_FILE);
		/* First, if we already have the file open, just use fstat */
		ret = openfile_stat(&gn->backing.gobj->d.file.of, &bst);
		if (ret == 0)
			goto found_backing_file;
		if (ret != -EBADF) {
			assert(ret < 0);
			return ret;
		}
		/* Next, if the object is the ocache, stat the ocache file */
		ret = ocache_fname(fname, sizeof(fname), gn->backing.gobj);
		if (unlikely(ret != 0)) {
			assert(ret < 0);
			return ret;
		}
		ret = stat(fname, &bst);
		if (ret == 0) {
		    found_backing_file:
			sbuf->st_size = bst.st_size;
			if (bst.st_atime > sbuf->st_atime)
				sbuf->st_atime = bst.st_atime;
			break;
		}
		if (errno != ENOENT)
			return neg_errno();
		/*
		 * If we couldn't find the backing file, just use the size
		 * we remember and don't bother with atime
		 */
		sbuf->st_size = gn->backing.gobj->d.file.size;
		break;
	case GFN_DIR:
		assert(gn->backing.gobj->type == GFN_DIR);
		sbuf->st_atim = gn->stat.atime;
		/* Old school UNIX: */
		sbuf->st_size = 16 * gn->backing.gobj->d.dir.nentries;
		break;
	default:
		assert(0);
	}
	return 0;
}

static void finish_defered_stat(struct gitobj_pending_request *pr)
{
	switch (pr->cmd.error) {
	case -EAGAIN:
		/*
		 * In case we never got ran (due to another request for this
		 * object already being in the pipe) just try again -- we
		 * know we can't complete the stat without this info
		 */
		gitwork_queue(pr->sn.gn->backing.gobj, pr);
		return;
	case 0:
		assert(pr->cmd.answer.pack_filename != NULL);
		pr->cmd.error = gobj_stat_or_defer(pr->sn.gn,
					 pr->cmd.answer.pack_filename,
					 pr->op.stat.result_buf);
		/*
		 * It's impossible gobj_stat_or_defer() to defer again -- the
		 * only reason it would have defered is if it wanted to know
		 * the pack name and we just told it!
		 */
		assert(pr->cmd.error != -EINPROGRESS);
		break;
	default:
		assert(pr->cmd.error < 0);
	}
	api_complete_saved_request(pr->req, pr->cmd.error, NULL, 0);
	gitwork_free(pr);
}

static int gitobj_stat(struct gitfs_node *gn, struct stat *sbuf)
{
	return gobj_stat_or_defer(gn, NULL, sbuf);
}

static int gitobj_open(struct gitfs_node *gn, UNUSED_ARG(unsigned int flags))
{
	int ret;

	assert (gn->type == GFN_FILE);
	assert (gn->backing.gobj->type == GFN_FILE);
	gn->backing.gobj->open_count++;
	ret = gobj_openread_or_defer(gn, NULL, NULL, NULL, 0, 0);
	/*
	 * If we got an error we need to un-do the open_count increment
	 * above
	 */
	if (unlikely(ret != 0 && ret != -EINPROGRESS))
		gobj_close_file(gn->backing.gobj);
	return ret;
}

static int gitobj_pread(struct gitfs_node *gn,
			void *buf, size_t size, off_t offset)
{
	assert (gn->type == GFN_FILE);
	assert (gn->backing.gobj->type == GFN_FILE);
	return gobj_openread_or_defer(gn, NULL, gobj_finish_pread,
				     buf, size, offset);
}

static void gitobj_close(struct gitfs_node *gn)
{
	assert (gn->type == GFN_FILE);
	assert (gn->backing.gobj->type == GFN_FILE);
	gobj_close_file(gn->backing.gobj);
}

static int gitobj_readlink(struct gitfs_node *gn, char *result, size_t *rlen)
{
	int ret;

	assert (gn->type == GFN_SYMLINK);
	assert (gn->backing.gobj->type == GFN_FILE);
	gn->backing.gobj->open_count++;
	ret = gobj_openread_or_defer(gn, NULL, gobj_finish_readlink,
				     result, *rlen, 0);
	if (likely(ret != -EINPROGRESS)) {
		/*
		 * If we didn't get delayed we need to undo the open_count
		 * change (since we won't have a matching ->close() call)
		 */
		gobj_close_file(gn->backing.gobj);
		if (likely(ret >= 0)) {
			*rlen = ret;
			ret = 0;
		}
	}
	return ret;
}

/*
 * For normal lookups there's no need for any further work after
 * gitobj_lookup_byptr(), so we provide this empty callback
 */
static int null_finish_lookup(int error, UNUSED_ARG(struct gitfs_node *gn))
{
	return error;
}

static int gitobj_lookup(struct gitfs_node *parent,
			 struct gitfs_node **resultp, const char *name)
{
	const struct gitdir_entry *e;

	assert (parent->type == GFN_DIR);
	assert (parent->backing.gobj->type == GFN_DIR);
	timespec(&parent->stat.atime);
	e = gitdir_find(&parent->backing.gobj->d.dir, name,
			&parent->t.d.last_lookup_offset);
	if (e == NULL)
		return -ENOENT;
	*resultp = gn_alloc(parent, name);
	if (*resultp == NULL)
		return -ENOMEM;
	return gitobj_lookup_byptr(e->ptr, *resultp, e->type,
				   e->perm, null_finish_lookup);
}

static int gitobj_readdir(struct gitfs_node *gn,
			  struct api_readdir_state *ars)
{
	assert (gn->type == GFN_DIR);
	assert (gn->backing.gobj->type == GFN_DIR);
	gitdir_readdir(&gn->backing.gobj->d.dir, gn, ars);
	timespec(&gn->stat.atime);
	return 0;
}

static unsigned int gitobj_count_subdirs(struct gitfs_node *gn)
{
	assert (gn->type == GFN_DIR);
	assert (gn->backing.gobj->type == GFN_DIR);
	return gn->backing.gobj->d.dir.nsubdirs;
}

static inline struct gitobj *rbtree_to_gitobj(struct rb_node *rb)
{
	char *ptr = (char *) rb;

	ptr -= (size_t) &((struct gitobj *) 0)->rb_active;
	return (struct gitobj *) ptr;
}

static struct rb_tree active_gobjs = EMPTY_RBTREE;

/*
 * In order to avoid calls to memcmp we do an initial check of the first
 * word just as an "unsigned long".  Note that this means that the first
 * part of the comparison is done in host-byte-order while the remainder
 * is done byte-by-byte (i.e. in network-byte-order)  This is actually OK --
 * it doesn't matter to the tree how we do the comparisons as long as we're
 * consistent about it
 */
static inline unsigned long gitptr2ulong(const struct gitobj_ptr *ptr)
{
	return *((const unsigned long *) &ptr->sha1[0]);
}

/*
 * Returns non-zero if the given pointers are equal, otherwise zero.
 * If "treeptr" is less than "ourptr" also increments the "rpp" pointer
 */
static inline int gitptr_match(const struct gitobj_ptr *treeptr,
			       const struct gitobj_ptr *ourptr,
			       struct rb_node ***rpp)
{
	long diff = gitptr2ulong(treeptr) - gitptr2ulong(ourptr);

	if (diff == 0) {
		diff = memcmp(&treeptr->sha1[sizeof(unsigned long)],
			      &ourptr->sha1[sizeof(unsigned long)],
			      sizeof(ourptr->sha1) - sizeof(unsigned long));
		if (likely(diff == 0))
			return 1;
	}
	if (diff < 0)
		(*rpp)++;
	return 0;
}

/*
 * Find (and hold) an existing gitobj for a particular hash.  If it doesn't
 * exist create a new one with type GFN_INCOMPLETE
 */
static struct gitobj *gobj_find_or_create(const struct gitobj_ptr *ptr)
{
	struct gitobj *gobj;
	struct rb_node **rp;

	rbtree_walk(&active_gobjs, rp) {
		gobj = rbtree_to_gitobj(*rp);
		rp = &(*rp)->child[0];
		if (gitptr_match(&gobj->hash, ptr, &rp) != 0) {
			gobj_hold(gobj);
			return gobj;
		}
	}
	/* Nope, not found - allocate a new one */
	gobj = calloc(1, sizeof(*gobj));
	if (gobj != NULL) {
		memcpy(&gobj->hash, ptr, sizeof(gobj->hash));
		gobj->hold_count = 1;
		gobj->type = GFN_INCOMPLETE;
		rbtree_insert(rp, &gobj->rb_active);
	}
	return gobj;
}

void gobj_release(struct gitobj *gobj)
{
	assert(gobj->hold_count != 0);
	if (--gobj->hold_count != 0)
		return;			/* object still held */
	assert(gobj->open_count == 0);
	switch (gobj->type) {
	case GFN_DIR:
		gitdir_free(&gobj->d.dir);
		break;
	case GFN_FILE:
		assert(gobj->d.file.of.backing_fd < 0);
		break;
	case GFN_INCOMPLETE:
		break;
	default:
		assert(0);
	}
	rbtree_delete(&gobj->rb_active);
	free(gobj);
}

static int finish_gobj_lookup(struct gitfs_node *gn,
			      enum gitfs_node_type de_type)
{
	static const struct gitfs_file_ops file_ops = {
		.common = {
			.stat = gitobj_stat,
		},
		.open = gitobj_open,
		.close = gitobj_close,
		.pread = gitobj_pread,
	};
	static const struct gitfs_dir_ops dir_ops = {
		.common = {
			.stat = gitobj_stat,
		},
		.lookup = gitobj_lookup,
		.readdir = gitobj_readdir,
		.count_subdirs = gitobj_count_subdirs,
	};
	static const struct gitfs_symlink_ops symlink_ops = {
		.common = {
			.stat = gitobj_stat,
		},
		.readlink = gitobj_readlink,
		/* No need for .link_len(); we handle that in .stat() */
	};

	assert(gn->backing.gobj != NULL);
	assert(gn->backing.gobj->type != GFN_INCOMPLETE);
	assert(gn->type == GFN_INCOMPLETE);
	/*
	 * Certain information (permissions, symlink, ...) are stored in the
	 * directory entry
	 */
	switch (de_type) {
	case GFN_SYMLINK:
		if (gn->backing.gobj->type == GFN_FILE) {
			gn_set_type(gn, GFN_SYMLINK);
			break;
		}
		/* FALLTHROUGH */
	default:
		if (de_type != gn->backing.gobj->type) {
			gn_release(gn);
			return -EIO;
		}
		/* FALLTHROUGH */
	case GFN_INCOMPLETE:
		gn_set_type(gn, gn->backing.gobj->type);
	}

	switch (gn->type) {
	case GFN_FILE:
		gn->op.f = &file_ops;
		break;
	case GFN_DIR:
		gn->op.d = &dir_ops;
		break;
	case GFN_SYMLINK:
		gn->op.sl = &symlink_ops;
		break;
	default:
		assert(0);
	}
	return 0;
}

static void fill_gitobj_from_ocache(struct gitobj *gobj)
{
	char fname[PATH_MAX];
	struct stat st;

	assert(gobj->type == GFN_INCOMPLETE);
	if (ocache_fname(fname, sizeof(fname), gobj) == 0 &&
	    stat(fname, &st) == 0) {
		/*
		 * If the object exists in the ocache then it MUST be a
		 * GFN_FILE (GFN_DIR objects are only parsed and kept in
		 * memory -- never in ocache) so we don't need to ask
		 * the gitworker thread about it
		 */
		gobj->type = GFN_FILE;
		openfile_init(&gobj->d.file.of);
		gobj->d.file.size = st.st_size;
	}
}

static int gobj_lookup_or_defer(struct gitfs_node *gn,
				enum gitfs_node_type de_type,
				struct gitobj_pending_request *pr,
				int (*finish)(int error,
					      struct gitfs_node *gn))
{
	if (likely(gn->backing.gobj->type != GFN_INCOMPLETE)) {
	    have_gobj:
		return finish(finish_gobj_lookup(gn, de_type), gn);
	}
	fill_gitobj_from_ocache(gn->backing.gobj);
	if (unlikely(gn->backing.gobj->type != GFN_INCOMPLETE))
		goto have_gobj;
	/*
	 * OK, we don't have the actual object yet -- ask the gitworker to
	 * grab it for us
	 */
	if (likely(pr == NULL)) {
		pr = gitwork_new(gn);
		if (pr == NULL) {
			gn_release(gn);
			return -ENOMEM;
		}
		/*
		 * We supply the expected type (if any) to the gitworker
		 * so it can save work if possible
		 */
		pr->cmd.answer.open.type = de_type;
		pr->cmd.opcode = GITWORKER_OBJECT_INFO;
		pr->finish.lookup = finish;
		pr->op.lookup.de_type = de_type;
	}
	gitwork_queue(gn->backing.gobj, pr);
	return -EINPROGRESS;
}

int gitobj_lookup_byptr(const struct gitobj_ptr *ptr,
			struct gitfs_node *gn,
			enum gitfs_node_type de_type, mode_t de_mode,
			int (*finish)(int error, struct gitfs_node *gn))
{
	struct gitobj *gobj;

	gobj = gobj_find_or_create(ptr);
	if (gobj == NULL) {
		gn_release(gn);
		return -ENOMEM;
	}
	gn->backing.gobj = gobj;	/* Inherits our reference */
	gn->stat.perm = de_mode;
	return gobj_lookup_or_defer(gn, de_type, NULL, finish);
}

/*
 * OK, we got our GITWORKER_OBJECT_INFO work item back from the gitworker
 * thread; fill in the gobj structure with what we found
 */
static int fill_gitobj_from_worker_result(struct gitobj *gobj,
					  struct gitwork_cmd *cmd)
{
	int ret = 0;

	assert(cmd->opcode == GITWORKER_OBJECT_INFO);
	assert(cmd->error == 0);
	if (unlikely(gobj->type != GFN_INCOMPLETE)) {
		/* We already got parsed! */
		assert(gobj->type == cmd->answer.open.type);
		goto done;
	}
	switch (cmd->answer.open.type) {
	case GFN_DIR:
		assert(cmd->answer.open.buf != NULL);
		ret = gitdir_parse(&gobj->d.dir, cmd->answer.open.buf,
				   cmd->answer.open.size);
		if (unlikely(ret != 0)) {
			assert(ret < 0);
			break;
		}
		/*
		 * NOTE: we don't free(cmd->answer.open.buf) here since the
		 * directory takes ownership of it as ->d.dir.backing_file;
		 * it's free()'d when the object is destroyed
		 */
		goto done_nofree;
	case GFN_FILE:
		openfile_init(&gobj->d.file.of);
		gobj->d.file.size = cmd->answer.open.size;
		free(cmd->answer.open.buf);
		break;
	default:
		assert(0);
	}
    done:
	free(cmd->answer.open.buf);
    done_nofree:
	gobj->type = cmd->answer.open.type;
	return ret;
}

static void finish_defered_lookup(struct gitobj_pending_request *pr)
{
	int ret;

	if (pr->cmd.error == 0) {
		ret = fill_gitobj_from_worker_result(pr->sn.gn->backing.gobj,
						     &pr->cmd);
		if (ret != 0)
			goto error;
	} else if (pr->cmd.error != -EAGAIN) {
		ret = pr->cmd.error;
	    error:
		assert(ret < 0);
		gn_release_notlast(pr->sn.gn);
		goto done;
	}
	ret = gobj_lookup_or_defer(pr->sn.gn, pr->op.lookup.de_type,
				   pr, pr->finish.lookup);
	if (unlikely(ret == -EINPROGRESS))
		return;
    done:
	assert(pr->sn.gn->parent != NULL);
	gn_finish_defered_lookups(pr->sn.gn->parent, pr->req, ret);
	gitwork_free(pr);
}

/* Called each time the gitworker thread has completes a request */
void gitwork_finish(struct gitwork_cmd *gwcmd)
{
	struct gitobj_pending_request *pr, *next;

	pr = (struct gitobj_pending_request *) gwcmd;
	assert(&pr->cmd == gwcmd);
	assert(pr->sn.gn->backing.gobj->pending == pr);
	pr->sn.gn->backing.gobj->pending = NULL;
	for (;;) {
		gdbg("  ::GITWORK complete opcode=0x%X, gn=0x%p, first=%s, "
		     "error=%d", pr->cmd.opcode, pr->sn.gn,
		     (gwcmd == (struct gitwork_cmd *) pr) ? "yes" : "no",
		     pr->cmd.error);
		next = pr->next;
		pr->next = NULL;
		switch (pr->cmd.opcode) {
		case GITWORKER_OBJECT_INFO:
			finish_defered_lookup(pr);
			break;
		case GITWORKER_ADD_TO_OCACHE:
			finish_defered_open(pr);
			break;
		case GITWORKER_FIND_PACKNAME:
			finish_defered_stat(pr);
			break;
		default:
			assert(0);
		}
		pr = next;
		if (pr == NULL)
			break;
		/*
		 * If there's other requests attached to this one they didn't
		 * actually get submitted to the gitworker thread... have
		 * the requester see if the desired work is now done and if
		 * not resubmit the request
		 */
		pr->cmd.error = -EAGAIN;
	}
}

/* IMPLEMENTATION OF "gitfs _dump_gobj" DEBUGGING COMMAND: */

struct gobj_dump_result {
	unsigned long hold_count, open_count;
	struct gitobj_ptr ptr;
	char type;		/* on EOF, type is '\0' */
};

static void fill_gobj_dump_result(struct gobj_dump_result *dr,
				  const struct gitobj *gobj)
{
	dr->hold_count = gobj->hold_count;
	dr->open_count = gobj->open_count;
	dr->ptr = gobj->hash;
	switch (gobj->type) {
	case GFN_FILE:
		dr->type = 'F';
		break;
	case GFN_DIR:
		dr->type = 'D';
		break;
	case GFN_INCOMPLETE:
		dr->type = '?';
		break;
	default:
		dr->type = '!';
	}
}

static inline int gobj_dump_filt_match(const struct gobj_dump_filter *filt,
				       const struct gitobj_ptr *ptr)
{
	if (filt->ptrbytes != 0 &&
	    0 != memcmp(&filt->ptr, ptr, filt->ptrbytes))
		return 0;
	if (filt->last_nibble != 0 &&
	    0 != ((filt->last_nibble ^ ptr->sha1[filt->ptrbytes]) & 0xF0))
		return 0;
	return 1;
}

void gobj_dump_answer(struct pcbuf *out, const struct gobj_dump_filter *filt)
{
	struct gobj_dump_result dr;
	struct gitobj *gobj;

	/* Sanity check filter */
	if (unlikely(filt->ptrbytes > sizeof(filt->ptr) ||
	    (filt->ptrbytes == sizeof(filt->ptr) && filt->last_nibble != 0)))
		goto eof;
	if (filt->ptrbytes == sizeof(filt->ptr)) {
		/* It's fully specifed; just find that item */
		struct rb_node **rp;
		rbtree_walk(&active_gobjs, rp) {
			gobj = rbtree_to_gitobj(*rp);
			rp = &(*rp)->child[0];
			if (gitptr_match(&gobj->hash, &filt->ptr, &rp) != 0) {
				fill_gobj_dump_result(&dr, gobj);
				pcbuf_write_obj(out, dr);
				break;
			}
		}
	} else {
		struct rb_node *rb = rbtree_first(&active_gobjs);
		/*
		 * If it's not fully specified, then we need to walk all the
		 * active objects and print all that match.  Since we don't
		 * always store them in strict lexical order we can't just
		 * find the matching subtree, unfortunately.  This is just a
		 * debugging path so it's really not worth worring about
		 */
		while (rb != NULL) {
			gobj = rbtree_to_gitobj(rb);
			if (gobj_dump_filt_match(filt, &gobj->hash) != 0) {
				fill_gobj_dump_result(&dr, gobj);
				pcbuf_write_obj(out, dr);
			}
			rb = rbtree_next(rb);
		}
	}
    eof:
	memset(&dr, 0, sizeof(dr));
	dr.type = '\0';
	pcbuf_write_obj(out, dr);
}

struct dcmd_gobj_dump_state {
	int print_hash;
	unsigned int count;
};

static enum service_result gobj_dump_worker(const void *data, void *state)
{
	const struct gobj_dump_result *dr = data;
	struct dcmd_gobj_dump_state *dst = state;

	if (dr->type == '\0')
		return SERVICED_EOF;
	dst->count++;
	if (dst->print_hash != 0) {
		struct gitobj_ptr_ascii pa;
		gitptr_ascii(&pa, &dr->ptr);
		fwrite(&pa.ascii[0], 1, HEX_PTR_LEN, stdout);
		putchar(' ');
	}
	printf("%c %5lu", dr->type, dr->hold_count);
	if (dr->open_count > 0)
		printf(" (open: %lu)", dr->open_count);
	putchar('\n');
	return SERVICED_OK;
}

static int make_gobj_dump_filt(struct gobj_dump_filter *filt, const char *s)
{
	unsigned int state = 0, lastnib = 0;

	assert(filt->ptrbytes == 0);
	assert(filt->last_nibble == 0);
	for (; *s != '\0'; s++) {
		unsigned int nib;
		if (*s >= '0' && *s <= '9')
			nib = *s - '0';
		else if (*s >= 'A' && *s <= 'F')
			nib = *s - ('A' - 10);
		else if (*s >= 'a' && *s <= 'f')
			nib = *s - ('a' - 10);
		else
			return -1;
		switch (state) {
		case 0:
			lastnib = nib << 4;
			state = 1;
			break;
		case 1:
			if (filt->ptrbytes >= sizeof(filt->ptr.sha1))
				goto too_long;
			filt->ptr.sha1[filt->ptrbytes++] = lastnib | nib;
			state = 0;
			break;
		default:
			assert(0);
		}
	}
	if (state != 0) {
		if (filt->ptrbytes >= sizeof(filt->ptr.sha1)) {
		    too_long:
			assert(filt->ptrbytes >= sizeof(filt->ptr.sha1));
			return -1;
		}
		filt->last_nibble = lastnib | 1;
	}
	return 0;
}

static int dcmd_dump_gobj(UNUSED_ARG(int argn), char * const *argv)
{
	struct gitfs_server_connection *gsc;
	struct gobj_dump_filter filt;
	struct gobj_dump_result rbuf;
	struct dcmd_gobj_dump_state dstate;

	memset(&filt, 0, sizeof(filt));
	if (argv[1] != NULL &&
	    (argv[2] != NULL || make_gobj_dump_filt(&filt, argv[1]) != 0)) {
		print_usage();
		return 4;
	}
	gsc = gs_connection_open();
	if (gsc == NULL)
		return 8;
	dstate.count = 0;
	dstate.print_hash = (filt.ptrbytes < sizeof(filt.ptr.sha1));
	if (gs_dump_gobj(gsc, &filt, &rbuf, sizeof(rbuf),
			 gobj_dump_worker, &dstate) != 0)
		return 8;
	gs_connection_close(gsc);
	if (filt.ptrbytes == 0 && filt.last_nibble == 0) {
		if (dstate.count != 0)
			putchar('\n');
		printf("%u git objects total in cache\n", dstate.count);
	} else if (dstate.count == 0) {
		errno = ENOENT;
		perror(argv[0]);
		return 1;
	}
	return 0;
}
const struct gitfs_subcommand debug_cmd_dump_gobj = {
	.cmd = "_dump_gobj",
	.handler = &dcmd_dump_gobj,
	.usage = "& [-d] _dump_gobj [sha1]",
};
