/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  api-fuse.c -- interface between the FUSE filesystem API and the rest
 *  of the filesystem.  For portability, no other code should be concerned
 *  with the details of how FUSE works
 *
 *  For more information about FUSE visit:	http://fuse.sf.net/
 */
#include "gitfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/socket.h>
/*
 * We don't need any help from the fuse library but we still need to link
 * against <linux/fuse.h> for the ABI definitions
 */
#include FUSE_HEADER

#define GITFS_MAX_FUSE_WRITE	(4096)

static const char fusermount[] = "fusermount";
static const char fusermount_error[] =
			"fatal: cannot find fusermount binary in $PATH!\n";

int api_umount_and_exit(const char *path)
{
	(void) execlp(fusermount, fusermount, "-u", "-z",
		      path, NULL);
	perror("execlp(fusermount -u)");
	fputs(fusermount_error, stderr);
	return 8;
}

#ifndef POLLWRNORM
#  define POLLWRNORM (0)
#endif /* !POLLWRNORM */
static struct pollfd fuse_poll_write = {
	.events = POLLOUT | POLLWRNORM,
};
#define fuse_fd		(fuse_poll_write.fd)
static const char *fuse_mountpoint;

static void close_lowfd(void)
{
	int fd, ret;

	for (fd = 0; fd < 3; fd++) {
		(void) close(fd);
		ret = open("/dev/null",
			   (fd == STDIN_FILENO) ? O_RDONLY : O_WRONLY);
		assert(ret == fd);
		/* Just to be paranoid; clear close-on-exec */
		ret = fcntl(fd, F_GETFD);
		if (ret >= 0)
			(void) fcntl(fd, F_SETFD, ret & ~FD_CLOEXEC);
	}
}

void api_umount(void)
{
	pid_t child;

	(void) close(fuse_fd);
	child = vfork();
	if (child < 0) {
		perror("fork");
		return;		/* not much we can do here */
	}
	if (child == 0) {	/* in child... */
		close_lowfd();
		_exit(api_umount_and_exit(fuse_mountpoint));
	}
	(void) waitpid(child, NULL, 0);
}

static void exec_mount_helper(const char *path, int socketfd, int rdonly)
{
	char fd_str[10];
	const char *opts = "ro,fsname=gitfs";

	fcntl(socketfd, F_SETFD, 0);
	snprintf(fd_str, sizeof(fd_str), "%d", socketfd);
	if (setenv("_FUSE_COMMFD", fd_str, 1) != 0) {
		errno = ENOMEM;
		perror("setenv");
		return;
	}
	if (rdonly == 0)
		opts += strlen_const("ro,");
	(void) execlp(fusermount, fusermount, "-o", opts, path, NULL);
	perror("execlp(fusermount)");
	fputs(fusermount_error, stderr);
}

static int receive_fuse_devfd(int socketfd)
{
	struct msghdr msg;
	struct iovec iov;
	char ccmsg[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	char fakebuf;

	iov.iov_base = &fakebuf;
	iov.iov_len = 1;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);
	for (;;) {
		int rv = recvmsg(socketfd, &msg, 0);
		if (rv > 0)
			break;
		if (rv == 0) {
			fputs("Got EOF while waiting for fuse fd!\n", stderr);
			return -1;
		}
		if (errno != EINTR) {
			perror("recvmsg");
			return -1;
		}
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "got control message of unknown type %d\n",
			(int) cmsg->cmsg_type);
		return -1;
	}
	return *((int *) CMSG_DATA(cmsg));
}

static uid_t my_uid;
static gid_t my_gid;

struct fuse_out {
	struct fuse_out_header hdr;
	union {
		struct fuse_entry_out entry;
		struct fuse_attr_out attr;
		struct fuse_open_out open;
		struct fuse_write_out write;
		struct fuse_statfs_out statfs;
		struct fuse_getxattr_out getxattr;
		struct fuse_init_out init;
		struct fuse_lk_out lock;
		char read[0];
	} arg;
};

/*
 * This is all the state that we keep around inside a request; if the
 * lower levels decide to save a request this structure is kept around
 * until it is completed
 */
struct api_request {
	struct fuse_out out;
	struct iovec iov[2];
	/*
	 * When a reply gets defered via api_save_request() the ->complete
	 * function will get set to a handler function that does any request
	 * post-processing needed.  It gets passed the negative-errno result
	 * from the lower levels and returns a (possibly modified)
	 * negative-errno
	 */
	int (*complete)(int error);
	struct gitfs_saved_node sn;
	/*
	 * If the kernel indicates that a succesful operation was interrupted
	 * we are responsible for unwinding it
	 */
	void (*rollback)(void);
	/*
	 * Values that need to be preserved across save/complete for specific
	 * operations
	 */
	union {
		struct {
			off_t offset;
			size_t len;
			struct api_readdir_state *rs;
		} readdir;
		struct {
			struct stat sbuf;
		} stat;
		struct {
			struct api_request *next;
		} freelist;
	} op;
};

/*
 * A stack of recently freed api_request structures -- saves the cost of a
 * malloc+free most of the time
 */
static struct api_request *request_freelist = NULL;
static unsigned int request_freelist_count = 0;
#define REQUEST_FREELIST_MAXENTRIES	(35)

static struct api_request *apirequest_alloc(void)
{
	struct api_request *req = request_freelist;

	if (req == NULL)
		req = malloc(sizeof(*req));
	else {
		assert(request_freelist_count > 0);
		request_freelist_count--;
		request_freelist = req->op.freelist.next;
	}
	if (req != NULL) {
		req->iov[0].iov_base = &req->out;
		req->complete = NULL;
	}
	return req;
}

static inline void apirequest_free(struct api_request *req)
{
	if (request_freelist_count >= REQUEST_FREELIST_MAXENTRIES) {
		assert(request_freelist_count == REQUEST_FREELIST_MAXENTRIES);
		free(req);
	} else {
		req->op.freelist.next = request_freelist;
		request_freelist = req;
		request_freelist_count++;
	}
}

static struct api_request *cur_req;	/* currently in-progress request */

int api_open_mount(const char *path, int rdonly)
{
	int spair[2];
	pid_t child;

	fuse_mountpoint = path;
	my_uid = getuid();
	my_gid = getgid();

	/* Allocate initial cur_req */
	cur_req = apirequest_alloc();
	if (cur_req == NULL) {
		perror("apirequest_alloc");
		return -1;
	}
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, spair) != 0) {
		perror("socketpair");
		return -1;
	}
	assert(spair[0] >= 0);
	assert(spair[1] >= 0);
	child = vfork();
	if (child < 0) {
		perror("vfork");
		return -1;
	}
	if (child == 0) {	/* In child... */
		(void) close(spair[1]);
		exec_mount_helper(path, spair[0], rdonly);
		return -1;
	}
	(void) close(spair[0]);
	fuse_fd = receive_fuse_devfd(spair[1]);
	(void) close(spair[1]);
	(void) waitpid(child, NULL, 0);
	if (fuse_fd >= 0 && set_nonblock(fuse_fd) != 0) {
		close(fuse_fd);
		fuse_fd = -1;
	}
	return fuse_fd;
}

struct fuse_in {
	struct fuse_in_header hdr;
	union {
		struct fuse_forget_in forget;
		struct {
			struct fuse_mknod_in chdr;
			char name[0];
		} mknod;
		struct {
			struct fuse_mkdir_in chdr;
			char name[0];
		} mkdir;
		struct {
			struct fuse_rename_in chdr;
			char names[0];	/* old, '\0', new, '\0' */
		} rename;
		struct {
			struct fuse_link_in chdr;
			char name[0];
		} link;
		struct fuse_setattr_in setattr;
		struct fuse_open_in open;	/* _OPEN and _CREATE */
		struct fuse_release_in release;
		struct fuse_flush_in flush;
		struct fuse_read_in read;
		struct {
			struct fuse_write_in chdr;
			char data[0];
		} write;
		struct fuse_fsync_in fsync;
		struct {
			struct fuse_setxattr_in chdr;
			char name[0];
			/*
			 * after '\0'-terminated name, the attribute to set
			 * is sent.  It's length is given in chdr.size
			 */
		} setxattr;
		struct {
			struct fuse_getxattr_in chdr;
			char name[0];
		} getxattr;
		struct fuse_init_in init;
		struct fuse_lk_in lock;
		struct fuse_access_in access;
		struct fuse_interrupt_in interrupt;
		/*
		 * lookup, unlink, rmdir, and removexattr just take a
		 * string; no per-command header.  symlink takes two
		 * names (just like rename above) but with no per-command
		 * header
		 */
		char name[0];
	} arg;
};

static inline struct gitfs_node *find_nodeid(const struct fuse_in *in)
{
	struct gitfs_node *gn = gn_lookup_inum(in->hdr.nodeid);

	if (gn == NULL && in->hdr.nodeid == FUSE_ROOT_ID) {
		gn = &gitfs_node_root;
		gn_hold(gn);
	}
	return gn;
}

static int generic_stat_start(void)
{
	memset(&cur_req->op.stat.sbuf, 0, sizeof(cur_req->op.stat.sbuf));
	cur_req->op.stat.sbuf.st_nlink = 1;
	cur_req->op.stat.sbuf.st_uid = my_uid;
	cur_req->op.stat.sbuf.st_gid = my_gid;
	cur_req->op.stat.sbuf.st_mode = (mode_t) -1;
	return (cur_req->sn.gn->op.c->stat == NULL) ? 0 :
		cur_req->sn.gn->op.c->stat(cur_req->sn.gn,
					   &cur_req->op.stat.sbuf);
}

static void generic_stat_complete(struct fuse_attr *attr)
{
	switch (cur_req->sn.gn->type) {
	case GFN_FILE:
		if (cur_req->sn.gn->op.f->is_sticky != NULL &&
		    cur_req->sn.gn->op.f->is_sticky(cur_req->sn.gn)) {
			if (cur_req->op.stat.sbuf.st_mode == (mode_t) -1)
				cur_req->op.stat.sbuf.st_mode = 0644;
			cur_req->op.stat.sbuf.st_mode |= S_ISVTX;
		} else if (cur_req->op.stat.sbuf.st_mode == (mode_t) -1)
			cur_req->op.stat.sbuf.st_mode = 0444;
		cur_req->op.stat.sbuf.st_mode |= S_IFREG;
		break;
	case GFN_DIR:
		if (cur_req->op.stat.sbuf.st_mode == (mode_t) -1)
			cur_req->op.stat.sbuf.st_mode = 0555;
		cur_req->op.stat.sbuf.st_mode |= S_IFDIR;
		cur_req->op.stat.sbuf.st_nlink = 2;
		if (cur_req->sn.gn->op.d->count_subdirs != NULL)
			cur_req->op.stat.sbuf.st_nlink +=
			  cur_req->sn.gn->op.d->count_subdirs(cur_req->sn.gn);
		break;
	case GFN_SYMLINK:
		if (cur_req->op.stat.sbuf.st_mode == (mode_t) -1)
			cur_req->op.stat.sbuf.st_mode = 0777;
		cur_req->op.stat.sbuf.st_mode |= S_IFLNK;
		if (cur_req->sn.gn->op.sl->link_len != NULL)
			cur_req->op.stat.sbuf.st_size =
			    cur_req->sn.gn->op.sl->link_len(cur_req->sn.gn);
		break;
	default:
		assert(0);
	}
	attr->ino = (cur_req->op.stat.sbuf.st_ino != 0)
			? cur_req->op.stat.sbuf.st_ino
			: (cur_req->sn.gn->inum == 0)
			? FUSE_ROOT_ID
			: (cur_req->sn.gn->inum & 0xFFFFFFFF);
	attr->mode = cur_req->op.stat.sbuf.st_mode;
	attr->nlink = cur_req->op.stat.sbuf.st_nlink;
	attr->uid = cur_req->op.stat.sbuf.st_uid;
	attr->gid = cur_req->op.stat.sbuf.st_gid;
	attr->rdev = cur_req->op.stat.sbuf.st_rdev;
	attr->size = cur_req->op.stat.sbuf.st_size;
	attr->blocks = cur_req->op.stat.sbuf.st_blocks;
	attr->atime = cur_req->op.stat.sbuf.st_atime;
	attr->atimensec = cur_req->op.stat.sbuf.st_atim.tv_nsec;
	attr->mtime = cur_req->op.stat.sbuf.st_mtime;
	attr->mtimensec = cur_req->op.stat.sbuf.st_mtim.tv_nsec;
	attr->ctime = cur_req->op.stat.sbuf.st_ctime;
	attr->ctimensec = cur_req->op.stat.sbuf.st_ctim.tv_nsec;
}

/*
 * When the lower-level requests decide to defer completion of a request
 * via the api_save_request() API this gets set to non-NULL.  The service
 * function below test this to determine whether they should just complete
 * immediately or if they should set cur_req->complete to the proper
 * handler which is then called from api_complete_saved_request()
 */
static struct api_request *next_cur_req = NULL;
#define request_was_saved()	(unlikely(next_cur_req != NULL))

static int lookup_stat_complete(int error)
{
	/*
	 * Since the FUSE lookup command holds a reference (which is dropped
	 * at FORGET time) we only gn_release() the node if the lookup
	 * fails in the end
	 */
	if (error == 0)
		generic_stat_complete(&cur_req->out.arg.entry.attr);
	else
		gn_release(cur_req->sn.gn);
	return error;
}

#define ENTRY_REVALIDATE_TIME	(1) /* sec */
#define ATTR_REVALIDATE_TIME	(1) /* sec */

static int lookup_complete(int error)
{
	if (error == 0) {
		struct fuse_entry_out *ent = &cur_req->out.arg.entry;
		assert(cur_req->sn.gn->inum != 0);
		assert(cur_req->sn.gn->type != GFN_INCOMPLETE);
		ent->nodeid = cur_req->sn.gn->inum;
		assert(ent->nodeid != FUSE_ROOT_ID);
		ent->generation = 1;	// TODO
		ent->entry_valid = ENTRY_REVALIDATE_TIME;
		ent->entry_valid_nsec = 0;
		ent->attr_valid = ATTR_REVALIDATE_TIME;
		ent->attr_valid_nsec = 0;
		error = generic_stat_start();
		if (request_was_saved())
			cur_req->complete = lookup_stat_complete;
		else
			(void) lookup_stat_complete(error);
	}
	return error;
}

static int fuse_lookup(const struct fuse_in *in)
{
	struct gitfs_node *parent;
	int res;

	gdbg("  LOOKUP: %u/%s", (unsigned int) in->hdr.nodeid, in->arg.name);
	parent = find_nodeid(in);
	if (parent == NULL)
		return -ENOENT;
	assert(0 != strcmp(in->arg.name, "."));
	assert(0 != strcmp(in->arg.name, ".."));
	res = gn_lookup_in(parent, in->arg.name, &cur_req->sn.gn);
	gn_release(parent);
	if (request_was_saved())
		cur_req->complete = lookup_complete;
	else
		res = lookup_complete(res);
	return res;
}

/*
 * ->rollback() handler for things which return a held reference to a fuse
 * node (LOOKUP, MKNOD, MKDIR, SYMLINK, LINK)
 */
static void hold_rollback(void)
{
	gn_release(cur_req->sn.gn);
}

static void fuse_forget(__u64 nodeid, __u64 refcnt)
{
	gdbg("  FORGET: nodeid=%u, count=%u",
	     (unsigned int) nodeid, (unsigned int) refcnt);
	if (nodeid != FUSE_ROOT_ID) {
		struct gitfs_node *gn = gn_lookup_inum(nodeid);
		assert(gn != NULL);
		gn_release_nref(gn, refcnt);
	}
}

/* Like find_nodeid() except makes sure the result is the expected type */
static int find_nodeid_type(const struct fuse_in *in,
			    struct gitfs_node **resultp,
			    enum gitfs_node_type type)
{
	int res = 0;

	*resultp = find_nodeid(in);
	if (*resultp == NULL)
		return -ENOENT;
	if ((*resultp)->type != type) {
		switch (type) {
		case GFN_DIR:
			res = -ENOTDIR;
			break;
		case GFN_SYMLINK:
			res = -EINVAL;
			break;
		case GFN_FILE:
			res = ((*resultp)->type == GFN_DIR)
					? -EISDIR : -EINVAL;
			break;
		default:
			assert(0);
		}
		assert(res < 0);
		gn_release(*resultp);
	}
	return res;
}

static int getattr_complete(int error)
{
	if (error == 0)
		generic_stat_complete(&cur_req->out.arg.attr.attr);
	return error;
}

static int fuse_getattr(const struct fuse_in *in)
{
	int error;

	cur_req->sn.gn = find_nodeid(in);
	gdbg("  GETATTR: nodeid=%u", (unsigned int) in->hdr.nodeid);
	if (cur_req->sn.gn == NULL)
		return -ENOENT;
	cur_req->out.arg.attr.attr_valid = ATTR_REVALIDATE_TIME;
	cur_req->out.arg.attr.attr_valid_nsec = 0;
	error = generic_stat_start();
	gn_release(cur_req->sn.gn);
	if (request_was_saved())
		cur_req->complete = getattr_complete;
	else
		(void) getattr_complete(error);
	return error;
}

/*
 * req->complete function for operations that don't need any further
 * processing in the api_complete_saved_request() path
 */
static int empty_complete(int err)
{
	return err;
}

static int fuse_readlink(const struct fuse_in *in)
{
	int res = find_nodeid_type(in, &cur_req->sn.gn, GFN_SYMLINK);

	if (res == 0) {
		static char linkval[PATH_MAX + 1];
		cur_req->iov[1].iov_base = linkval;
		cur_req->iov[1].iov_len = sizeof(linkval);
		res = cur_req->sn.gn->op.sl->readlink(cur_req->sn.gn,
					   linkval, &cur_req->iov[1].iov_len);
		assert(res != 0 ||
		       cur_req->iov[1].iov_len <= sizeof(linkval));
		gn_release(cur_req->sn.gn);
		if (request_was_saved())
			cur_req->complete = empty_complete;
	}
	return res;
}

static int open_complete(int error)
{
	if (error != 0) {
		assert(error < 0);
		cur_req->sn.gn->open_count--;
		gn_release(cur_req->sn.gn);
	}
	return error;
}

static int fuse_open(const struct fuse_in *in)
{
	int res;

	res = find_nodeid_type(in, &cur_req->sn.gn, GFN_FILE);
	if (res != 0)
		return res;
	if (cur_req->sn.gn->op.f->open == NULL) {
		gn_release(cur_req->sn.gn);
		return -ENODEV;
	}
	if (cur_req->sn.gn->op.f->pwrite == NULL &&
	    ((in->arg.open.flags & O_ACCMODE) != O_RDONLY)) {
		gn_release(cur_req->sn.gn);
		return -EROFS;
	}
	cur_req->out.arg.open.fh = (unsigned long) cur_req->sn.gn;
	cur_req->out.arg.open.open_flags =
		(cur_req->sn.gn->t.f.direct_io != 0) ?
		FOPEN_DIRECT_IO : FOPEN_KEEP_CACHE;
	cur_req->sn.gn->open_count++;
	res = cur_req->sn.gn->op.f->open(cur_req->sn.gn, in->arg.open.flags);
	if (request_was_saved())
		cur_req->complete = open_complete;
	else
		(void) open_complete(res);
	return res;
}

static void open_cleanup(void)
{
	assert(cur_req->sn.gn->open_count > 0);
	cur_req->sn.gn->open_count--;
	gn_release(cur_req->sn.gn);
}

static inline struct gitfs_node *fh_to_gnode(__u64 fh)
{
	assert(fh != 0);
	return (struct gitfs_node *) (unsigned long) fh;
}

static void fuse_release(const struct fuse_in *in)
{
	cur_req->sn.gn = fh_to_gnode(in->arg.release.fh);
	assert(cur_req->sn.gn->type == GFN_FILE);
	if (cur_req->sn.gn->op.f->close != NULL)
		cur_req->sn.gn->op.f->close(cur_req->sn.gn);
	open_cleanup();
}

static int fuse_read(const struct fuse_in *in)
{
	static char *read_buf = NULL;
	static size_t read_buf_len = 0;
	int res;
	off_t offset = in->arg.read.offset;

	if (offset < 0)
		return -EINVAL;
	cur_req->sn.gn = fh_to_gnode(in->arg.read.fh);
	assert(cur_req->sn.gn->type == GFN_FILE);
	assert(cur_req->sn.gn->op.f->pread != NULL);
	if (read_buf_len < in->arg.read.size) {
		char *n = realloc(read_buf, in->arg.read.size);
		if (n == NULL)
			return -ENOMEM;
		read_buf = n;
		read_buf_len = in->arg.read.size;
	}
	/*
	 * Note: if ->pread() elects to save the request it will have to
	 * allocate its own buffer to put the data into; ours will be
	 * reused for the next op
	 */
	res = cur_req->sn.gn->op.f->pread(cur_req->sn.gn, read_buf,
			      in->arg.read.size, offset);
	cur_req->iov[1].iov_base = read_buf;
	cur_req->iov[1].iov_len = res;
	if (request_was_saved())
		cur_req->complete = empty_complete;
	return (res < 0) ? res : 0;
}

struct api_readdir_state {
	struct gitfs_node *gn;
	int status;	/* >1 unfilled, 0 filled, <0 error dring fill */
	unsigned char *buf, *bufend;
	size_t buf_left;
};

static inline struct api_readdir_state *fh_to_readdir(__u64 fh)
{
	assert(fh != 0);
	return (struct api_readdir_state *) (unsigned long) fh;
}

static inline size_t rs_size(const struct api_readdir_state *rs)
{
	return rs->bufend - rs->buf;
}

static inline void rewind_dir(struct api_readdir_state *rs)
{
	rs->buf_left = rs_size(rs);
	rs->status = 1;
}

static int fuse_opendir(const struct fuse_in *in)
{
	struct api_readdir_state *rs;
	int res;

	res = find_nodeid_type(in, &cur_req->sn.gn, GFN_DIR);
	if (res != 0)
		return res;
	assert(cur_req->sn.gn->op.d->readdir != NULL);
	rs = malloc(sizeof(*rs));
	if (rs == NULL) {
		gn_release(cur_req->sn.gn);
		return -ENOMEM;
	}
	cur_req->sn.gn->open_count++;
	rs->gn = cur_req->sn.gn;
	rs->buf = NULL;
	rs->bufend = NULL;
	rewind_dir(rs);
	cur_req->out.arg.open.fh = (unsigned long) rs;
	cur_req->out.arg.open.open_flags = FOPEN_KEEP_CACHE;
	return 0;
}

static void destroy_readdir_state(struct api_readdir_state *rs)
{
	assert(rs->gn->open_count > 0);
	rs->gn->open_count--;
	gn_release(rs->gn);
	free(rs->buf);
	free(rs);
}

static void opendir_rollback(void)
{
	destroy_readdir_state((struct api_readdir_state *)
				(unsigned long) cur_req->out.arg.open.fh);
}

static inline __u32 git_type_to_dirent(enum gitfs_node_type gt)
{
	switch (gt) {
	case GFN_DIR:
		return S_IFDIR >> 12;
	case GFN_SYMLINK:
		return S_IFLNK >> 12;
	default:
		assert(gt == GFN_FILE);
	}
	return S_IFREG >> 12;
}

/* Returns non-zero if we failed and can abort the readdir */
int api_add_dir_contents(struct api_readdir_state *rs, const char *name,
			 enum gitfs_node_type type, gitfs_inum_t inum)
{
	size_t namelen, desize, padding;
	struct fuse_dirent *de;

	assert(rs->status <= 0);
	if (rs->status != 0)
		goto done;
	namelen = strlen(name);
	desize = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
	padding = desize - (FUSE_NAME_OFFSET + namelen);
	if (rs->buf_left < desize) {
		unsigned char *n;
		size_t osize, nsize;
		osize = rs_size(rs);
		nsize = (osize == 0) ? 512 : (osize * 2);
		if ((nsize - osize) < desize)
			nsize += desize; /* just incase "desize" is HUGE */
		n = realloc(rs->buf, nsize);
		if (n == NULL) {
			rs->status = -ENOMEM;
			goto done;
		}
		rs->buf = n;
		rs->bufend = &n[nsize];
		rs->buf_left += (nsize - osize);
	}
	assert(rs->buf_left >= desize);
	assert(&rs->bufend[-rs->buf_left] >= rs->buf);
	de = (struct fuse_dirent *) &rs->bufend[-rs->buf_left];
	de->ino = (inum == 0) ? FUSE_ROOT_ID : (inum & 0xFFFFFFFF);
	de->off = desize + (((unsigned char *) de) - rs->buf);
	de->namelen = namelen;
	de->type = git_type_to_dirent(type);
	memcpy(de->name, name, namelen);
	gdbg("  READDIR: adding \"%s\" @%u type=0x%X inum=%u", name,
	     (unsigned int) de->off, (unsigned int) de->type,
	     (unsigned int) de->ino);
	rs->buf_left -= desize;
	if (padding != 0)
		memset(&rs->bufend[-(rs->buf_left + padding)], 0, padding);
    done:
	return rs->status;
}

static int readdir_complete(int error)
{
	assert(cur_req->op.readdir.rs->status <= 0);
	assert(error <= 0);
	if (cur_req->op.readdir.rs->status == 0)
		cur_req->op.readdir.rs->status = error;
	if (cur_req->op.readdir.rs->status == 0) {
		cur_req->iov[1].iov_len = cur_req->op.readdir.len;
		if (cur_req->op.readdir.offset >=
		    rs_size(cur_req->op.readdir.rs))
			cur_req->iov[1].iov_len = 0;
		else {
			unsigned char *is = cur_req->op.readdir.rs->buf +
						cur_req->op.readdir.offset;
			cur_req->iov[1].iov_base = is;
			if (is + cur_req->iov[1].iov_len >
				&cur_req->op.readdir.rs->bufend[
					-cur_req->op.readdir.rs->buf_left])
				cur_req->iov[1].iov_len =
				  &cur_req->op.readdir.rs->bufend[
				  -cur_req->op.readdir.rs->buf_left] - is;
		}
		gdbg("  READDIR: returning %u/%u bytes",
		     (unsigned int) cur_req->iov[1].iov_len,
		     (unsigned int) cur_req->op.readdir.len);
	}
	return cur_req->op.readdir.rs->status;
}

// TODO - we should really support having the lower gnode layer tell us
// if the directory changes; if it hasn't then we don't need to do the
// invalidate-on-rewind AND we can cache the rs->buf

static int fuse_readdir(const struct fuse_in *in)
{
	struct api_readdir_state *rs = fh_to_readdir(in->arg.read.fh);
	int res = 0;

	gdbg("  READDIR: reading @%u", (unsigned int) in->arg.read.offset);
	if (in->arg.read.offset == 0)
		rewind_dir(rs);	/* force directory rescan on rewinddir() */
	cur_req->op.readdir.rs = rs;
	cur_req->op.readdir.offset = in->arg.read.offset;
	cur_req->op.readdir.len = in->arg.read.size;
	if (rs->status > 0) {
		static const char dotdot[] = "..";
		rs->status = 0;
		(void) api_add_dir_contents(rs, dotdot + 1,
					    GFN_DIR, rs->gn->inum);
		(void) api_add_dir_contents(rs, dotdot, GFN_DIR,
					    rs->gn->parent->inum);
		res = rs->gn->op.d->readdir(rs->gn, rs);
	}
	if (request_was_saved())
		cur_req->complete = readdir_complete;
	else
		res = readdir_complete(res);
	return res;
}

static void fuse_releasedir(const struct fuse_in *in)
{
	destroy_readdir_state(fh_to_readdir(in->arg.release.fh));
}

static void empty_rollback(void)
{
	/* nothing */
}

/* returns non-zero if we shouldn't retry the write */
static int fuse_handle_write_error(void)
{
	switch (errno) {
	case EAGAIN:
		/*
		 * I don't believe this actually can happen to a fuse device,
		 * but just for safety we'll wait for writability here
		 */
		gdbg("   WAITING FOR WRITABILITY");
		if (poll(&fuse_poll_write, 1, -1) < 0)
			switch (errno) {
			case EAGAIN:
			case EINTR:
				break;
			default:
				perror("polling fuse device for writability");
				return 1;
			}
		/* FALLTHROUGH */
	case EINTR:		/* just retry */
		return 0;
	case ENOENT:		/* the tricky one */
		/*
		 * if a write to a fuse device returns ENOENT this indicates
		 * that the filesystem request was interrupted and we may
		 * need to rollback
		 */
		gdbg("   CANCELLED %llu", cur_req->out.hdr.unique);
		if (cur_req->out.hdr.error == 0)
			cur_req->rollback();
		break;
	default:		/* not much we can do */
		perror("writing fuse device");
	}
	return 1;
}

/*
 * Sends a reply to FUSE based on "cur_req" unless the current request has
 * been saved via "api_save_request()"
 */
static void fuse_request_reply_or_save(void)
{
	assert(cur_req != next_cur_req);
	if (request_was_saved()) {
		assert(cur_req->complete != NULL);
		cur_req = next_cur_req;
		next_cur_req = NULL;
		return;
	}
	gdbg("R: uniq %llu, err=%d, len=%u+%u",
	     cur_req->out.hdr.unique, (int) cur_req->out.hdr.error,
	     (unsigned int) cur_req->out.hdr.len,
	     (unsigned int) cur_req->iov[1].iov_len);
	if (cur_req->out.hdr.error != 0) {
		assert(cur_req->out.hdr.error < 0);
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
	} else if (cur_req->iov[1].iov_len != 0) {
		assert(cur_req->iov[0].iov_base == &cur_req->out);
		cur_req->iov[0].iov_len = cur_req->out.hdr.len;
		cur_req->out.hdr.len += cur_req->iov[1].iov_len;
		for (;;) {
			ssize_t s = writev(fuse_fd, cur_req->iov, 2);
			if (s >= 0) {
				assert(((size_t) s) ==
				       (cur_req->iov[0].iov_len +
					cur_req->iov[1].iov_len));
				break;
			}
			if (fuse_handle_write_error())
				break;
		}
		return;
	}
	for (;;) {
		ssize_t s = write(fuse_fd, &cur_req->out,
				  cur_req->out.hdr.len);
		if (s >= 0) {
			assert(((size_t) s) == cur_req->out.hdr.len);
			break;
		}
		if (fuse_handle_write_error())
			break;
	}
}

/*
 * Prepares the current request to be defered for later.  Can return NULL
 * if insufficient resources were avaialble
 */
struct api_request *api_save_request(struct gitfs_node *gn)
{
	next_cur_req = apirequest_alloc();
	if (next_cur_req == NULL)
		return NULL;
	gn_save_node(&cur_req->sn, gn);
	return cur_req;
}

/*
 * For LOOKUP requests the lower level code might not know the gnode that
 * we're working with yet at the point we need to do a save request -- in
 * that case we must assign it later via this function
 */
void api_saved_request_set_gnode(struct api_request *ipc,
				 struct gitfs_node *gn)
{
	assert(gn != NULL);
	assert(ipc->sn.gn == NULL);
	gn_save_node(&ipc->sn, gn);
}

/*
 * Called to finish a request previously defered by api_save_request()
 * For derefered read or readlink operations the caller must pass in a
 * buffer with the results
 */
void api_complete_saved_request(struct api_request *ipc, int error,
				char *buf, size_t buflen)
{
	int (*complete_fn)(int);
	struct gitfs_node *hgn;

	assert(next_cur_req == NULL);
	assert(error <= 0);
	assert(error != 0 || ipc->sn.gn != NULL);
	apirequest_free(cur_req);
	cur_req = ipc;
	/*
	 * We need to un-save the gnode early (in case the completion
	 * function re-saves the request) but we want to hold on to the
	 * reference for the duration
	 */
	hgn = ipc->sn.gn;
	if (hgn != NULL)
		gn_hold(hgn);
	gn_unsave_node(&ipc->sn);
	ipc->iov[1].iov_base = buf;
	ipc->iov[1].iov_len = buflen;
	complete_fn = ipc->complete;
	ipc->complete = NULL;	/* sanity checking */
	ipc->out.hdr.error = complete_fn(error);
	/* Now drop the hold we took earlier */
	if (hgn != NULL)
		gn_release(hgn);
	/*
	 * Remember: it's possible that ->complete() could have re-saved
	 * the request
	 */
	fuse_request_reply_or_save();
}

static void too_short(const char *for_what, unsigned int len)
{
	fprintf(stderr, "read of %u bytes from FUSE device too short "
		"for %s\n", len, for_what);
}

static int fuse_inited = 0;

static enum service_result look_for_init_cmd(const struct fuse_in *in,
						 size_t cmdlen)
{
	struct fuse_out reply;

	if (in->hdr.opcode != FUSE_INIT) {
		reply.hdr.len = sizeof(reply.hdr);
		reply.hdr.unique = in->hdr.unique;
		reply.hdr.error = -EPROTO;
		(void) write(fuse_fd, &reply.hdr, sizeof(reply.hdr));
		return SERVICED_OK;
	}
	if (cmdlen < (sizeof(in->hdr) + sizeof(in->arg.init))) {
		too_short("init command", cmdlen);
		return SERVICED_ERROR;
	}
	if (in->arg.init.major != FUSE_KERNEL_VERSION) {
		fprintf(stderr, "FUSE kernel is interface version %u, "
			"expected %d\n", (unsigned int) in->arg.init.major,
			FUSE_KERNEL_VERSION);
		return SERVICED_ERROR;
	}
	reply.hdr.len = sizeof(reply.hdr) + sizeof(reply.arg.init);
	reply.hdr.unique = in->hdr.unique;
	reply.hdr.error = 0;
	reply.arg.init.major = FUSE_KERNEL_VERSION;
	reply.arg.init.minor = FUSE_KERNEL_MINOR_VERSION;
	reply.arg.init.max_write = GITFS_MAX_FUSE_WRITE;
	if (write(fuse_fd, &reply,
		  sizeof(reply.hdr) + sizeof(reply.arg.init)) < 0) {
		perror("sending FUSE_INIT reply");
		return SERVICED_ERROR;
	}
	gdbg("gitfs: entering command loop");
	fuse_inited = 1;
	return SERVICED_OK;
}

/*
 * Called when main.c's poll() loop indicates that there may be work
 * waiting for us on the FUSE file descriptor.  Returns:
 *   SERVICED_EOF: filesystem was unmounted; FUSE indicates a clean
 *		       shutdown
 *   SERVICED_ERROR: serious error, bail out
 *   SERVICED_OK: we're happy
 */
enum service_result api_service_poll(void)
{
	union {
		struct fuse_in f;
		unsigned char storage[GITFS_MAX_FUSE_WRITE +
				sizeof(struct fuse_write_in) +
				sizeof(struct fuse_in_header)];
		unsigned char minsize[FUSE_MIN_READ_BUFFER];
	} in;
	int rv = read(fuse_fd, in.storage, sizeof(in));

	if (unlikely(rv < (int) sizeof(in.f.hdr))) {
		if (rv < 0) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
			case ENOENT:
				return SERVICED_OK;
			case ENODEV:
				return SERVICED_EOF;
			}
			perror("reading from FUSE device");
			return SERVICED_ERROR;
		}
		too_short("command", rv);
		return SERVICED_ERROR;
	}
	if (unlikely(fuse_inited == 0))
		return look_for_init_cmd(&in.f, rv);
	/* Process normal command: */
	assert(cur_req != NULL);
	assert(next_cur_req == NULL);
	cur_req->rollback = empty_rollback;
	cur_req->iov[1].iov_len = 0;
	cur_req->out.hdr.unique = in.f.hdr.unique;
	gdbg("Q: uniq %llu, opcode %u, nodeid=%llu, alen=%u",
	     in.f.hdr.unique, in.f.hdr.opcode, in.f.hdr.nodeid,
	     rv - sizeof(in.f.hdr));
	switch (in.f.hdr.opcode) {
	case FUSE_LOOKUP:
		cur_req->rollback = hold_rollback;
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr) +
					sizeof(cur_req->out.arg.entry);
		cur_req->out.hdr.error = fuse_lookup(&in.f);
		break;
	case FUSE_FORGET:
		fuse_forget(in.f.hdr.nodeid, in.f.arg.forget.nlookup);
		return SERVICED_OK;	/* forget sends no reply */
	case FUSE_GETATTR:
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr) +
					sizeof(cur_req->out.arg.attr);
		cur_req->out.hdr.error = fuse_getattr(&in.f);
		break;
	case FUSE_READLINK:
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
		cur_req->out.hdr.error = fuse_readlink(&in.f);
		break;
	case FUSE_OPEN:
		cur_req->rollback = open_cleanup;
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr) +
					sizeof(cur_req->out.arg.open);
		cur_req->out.hdr.error = fuse_open(&in.f);
		break;
	case FUSE_RELEASE:
		cur_req->out.hdr.error = 0;
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
		fuse_release(&in.f);
		break;
	case FUSE_READ:
		cur_req->out.hdr.error = fuse_read(&in.f);
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
		break;
	case FUSE_OPENDIR:
		cur_req->rollback = opendir_rollback;
		cur_req->out.hdr.len =  sizeof(cur_req->out.hdr) +
					sizeof(cur_req->out.arg.open);
		cur_req->out.hdr.error = fuse_opendir(&in.f);
		break;
	case FUSE_READDIR:
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
		cur_req->out.hdr.error = fuse_readdir(&in.f);
		break;
	case FUSE_RELEASEDIR:
		cur_req->out.hdr.error = 0;
		cur_req->out.hdr.len = sizeof(cur_req->out.hdr);
		fuse_releasedir(&in.f);
		break;
	case FUSE_INTERRUPT:
		/* TODO */
		return SERVICED_OK;	/* interrupt sends no reply */
#if 0				/* Not implemented yet... */
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_LINK:
		cur_req->rollback = hold_rollback;
		/* ... */

	case FUSE_CREATE:
		cur_req->rollback = open_cleanup;
		/* ... */


	case FUSE_FLUSH:
	case FUSE_FSYNC:
	case FUSE_STATFS:
	case FUSE_WRITE:
	case FUSE_SETATTR:	/* chmod/chown/truncate */
	case FUSE_FSYNCDIR:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_RENAME:
	case FUSE_SETXATTR:
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
	case FUSE_REMOVEXATTR:
	case FUSE_GETLK:
	case FUSE_SETLK:
	case FUSE_SETLKW:
	case FUSE_ACCESS:
#endif
	default:
		cur_req->out.hdr.error = -ENOSYS;
	}
	fuse_request_reply_or_save();
	return SERVICED_OK;
}
