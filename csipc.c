/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005-2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  csipc.c -- Routines for servicing the client/server communication channel
 */

#define _GNU_SOURCE	/* for asprintf() */
#include "gitfs.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

static char *ipc_socket_name = NULL;
static int ipc_socket_fd = -1;
static size_t ipcdisc_size;

void csipc_fini(void)
{
	if (ipc_socket_fd >= 0) {
		(void) close(ipc_socket_fd);
		ipc_socket_fd = -1;
	}
	if (ipc_socket_name != NULL) {
		(void) unlink(ipc_socket_name);
		free(ipc_socket_name);
		ipc_socket_name = NULL;
	}
}

int csipc_init(void)
{
	struct sockaddr_un uaddr;

	if (asprintf(&ipc_socket_name, "/tmp/fuse-socket.%u",
		     (unsigned int) getpid()) < 0) {
		errno = ENOMEM;
		perror("asprintf");
		ipc_socket_name = NULL;
		return -1;
	}
	ipcdisc_size = (sizeof(gitfs_inum_t) + 1) + strlen(ipc_socket_name);
	ipc_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ipc_socket_fd < 0) {
		perror("socket(AF_UNIX)");
		free(ipc_socket_name);
		ipc_socket_name = NULL;
		return -1;
	}
	(void) unlink(ipc_socket_name);
	uaddr.sun_family = AF_UNIX;
	strncpy(uaddr.sun_path, ipc_socket_name, sizeof(uaddr.sun_path));
	if (bind(ipc_socket_fd, (struct sockaddr *) &uaddr,
		 SUN_LEN(&uaddr)) != 0) {
		perror("bind(AF_UNIX)");
		csipc_fini();
		return -1;
	}
	if (listen(ipc_socket_fd, 20) != 0) {
		perror("listen(AF_UNIX)");
		csipc_fini();
		return -1;
	}
	if (set_nonblock(ipc_socket_fd) != 0 ||
	    epoll_add(ipc_socket_fd, &ipc_socket_fd) != 0) {
		csipc_fini();
		return -1;
	}
	gdbg("CSIPC: created socket \"%s\"\n", ipc_socket_name);
	return 0;
}

/*
 * IPC DISCOVERY ROUTINES:
 *
 * Directories inside a repository have a special hidden file
 * CSIPC_DISCOVERY_FILE.  Reading this provides two things:
 *   1. the inode # of the parent directory
 *   2. the the path to the UNIX domain socket for this filesystem
 */
#define CSIPC_INODE_NUM		(5)

static int ipcdisc_stat(UNUSED_ARG(struct gitfs_node *gn), struct stat *sbuf)
{
	sbuf->st_size = ipcdisc_size;
	sbuf->st_ino = CSIPC_INODE_NUM;
	return 0;
}

static int ipcdisc_open(UNUSED_ARG(struct gitfs_node *gn),
			UNUSED_ARG(unsigned int flags))
{
	return 0;
}

static int ipcdisc_pread(struct gitfs_node *gn, void *buf,
			 size_t size, off_t offset)
{
	if (offset != 0)
		return -EINVAL;
	if (size < ipcdisc_size)
		return -EFBIG;
	memcpy(buf, &gn->parent->inum, sizeof(gn->parent->inum));
	memcpy(buf + sizeof(gn->parent->inum), ipc_socket_name,
	       ipcdisc_size - sizeof(gn->parent->inum));
	return ipcdisc_size;
}

int csipc_discovery_node(struct gitfs_node *parent,
			 struct gitfs_node **resultp)
{
	static const struct gitfs_file_ops ipcdisc_ops = {
		.common = {
			.stat = ipcdisc_stat,
		},
		.open = ipcdisc_open,
		.pread = ipcdisc_pread,
	};

	*resultp = gn_alloc(parent, CSIPC_DISCOVERY_FILE);
	if (*resultp == NULL)
		return -ENOMEM;
	gn_set_type(*resultp, GFN_FILE);
	(*resultp)->op.f = &ipcdisc_ops;
	return 0;
}

/* SERVER-SIDE ROUTINES: */

struct csipc_open_file {
	struct rb_node rb;	/* keep first */
	csipc_fh_t fh;
	struct gitfs_saved_node s;
};

struct csipc_client;
typedef enum service_result (*csop_service_fn)(struct csipc_client *cli);

struct csipc_client {
	int sfd;
	struct rb_tree files;
	csipc_fh_t next_fh;
	int last_writeavail;
	struct pcbuf in, out;
	csop_service_fn service;
	union {
		struct {
			uint32_t varlen;
		} conf_fetch;
	} state;
	unsigned int client_num;	/* for debugging messages only */
};

static struct rb_node **csfile_walk(struct csipc_client *cli, csipc_fh_t fh)
{
	struct rb_node **rp;

	rbtree_walk(&cli->files, rp) {
		csipc_fh_t tf = ((struct csipc_open_file *) *rp)->fh;
		if (fh == tf)
			break;
		rp = &(*rp)->child[fh > tf];
	}
	return rp;
}

static struct gitfs_node *csipc_file(struct csipc_client *cli, csipc_fh_t fh)
{
	struct rb_node *rp = *csfile_walk(cli, fh);

	return RB_IS_NIL(rp) ? NULL : ((struct csipc_open_file *) rp)->s.gn;
}

/* like csipc_file() but returns the underlying "csipc_open_file" struct */
static struct csipc_open_file *csipc_ofile(struct csipc_client *cli,
					   csipc_fh_t fh)
{
	struct rb_node *rp = *csfile_walk(cli, fh);

	return RB_IS_NIL(rp) ? NULL : (struct csipc_open_file *) rp;
}

static csipc_fh_t csipc_add_file(struct csipc_client *cli,
				 struct gitfs_node *gn)
{
	struct csipc_open_file *of;
	struct rb_node **rp;

	of = malloc(sizeof(*of));
	if (of == NULL)
		return -ENOMEM;
	gn_save_node(&of->s, gn);	/* increases hold count */
    again:
	of->fh = cli->next_fh++;
	if (unlikely(of->fh < 0)) {	/* wraparound! */
		cli->next_fh = 0;
		goto again;
	}
	rp = csfile_walk(cli, of->fh);
	if (unlikely(!RB_IS_NIL(*rp)))
		goto again;
	rbtree_insert(rp, &of->rb);
	return of->fh;
}

static void csipc_destroy_file(struct csipc_open_file *of)
{
	gn_unsave_node(&of->s);
	rbtree_delete(&of->rb);
	free(of);
}

static void csipc_client_fini(struct csipc_client *cli)
{
	for (;;) {
		struct csipc_open_file *of;
		of = (struct csipc_open_file *) rbtree_first(&cli->files);
		if (of == NULL)
			break;
		csipc_destroy_file(of);
	}
	pcbuf_destroy(&cli->in);
	pcbuf_destroy(&cli->out);
	free(cli);
}

/*
 * Macros with embeded "return" statements are inherently evil, but these
 * are just too useful to avoid.  Sorry.
 */
#define csipc_get_bytes_or_return(cli, objp, objlen)			\
do {									\
	ssize_t for_res;						\
	assert((cli)->in.error == 0);					\
	if (unlikely((cli)->in.cur_size < (objlen)))			\
		return SERVICED_OK;	/* not enough data yet */	\
	for_res = pcbuf_read(&(cli)->in, (objp), (objlen));		\
	assert(for_res == (ssize_t) (objlen));				\
} while (0)
#define csipc_fetch_or_return(cli, objp)				\
		csipc_get_bytes_or_return((cli), (objp), sizeof(*(objp)))

static enum service_result cliserv_getopcode(struct csipc_client *cli);

static inline void csipc_client_command_finished(struct csipc_client *cli)
{
	cli->service = cliserv_getopcode;
}

/* In: inode number; Out: file handle or -errno */
static enum service_result csop_open_inode(struct csipc_client *cli)
{
	gitfs_inum_t inum;
	csipc_fh_t fh;
	struct gitfs_node *gn;

	csipc_fetch_or_return(cli, &inum);
	gn = gn_lookup_inum(inum);
	if (gn == NULL) {
		/* inode 0 isn't on the gnode hash */
		fh = (inum == 0)
			? csipc_add_file(cli, &gitfs_node_root)
			: -ENOENT;
	} else {
		fh = csipc_add_file(cli, gn);
		gn_release(gn);
	}
	pcbuf_write_obj(&cli->out, fh);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: -errno */
static enum service_result csop_close(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct csipc_open_file *of;

	csipc_fetch_or_return(cli, &fh);
	of = csipc_ofile(cli, fh);
	if (of == NULL)
		fh = -EBADF;
	else {
		csipc_destroy_file(of);
		fh = 0;
	}
	pcbuf_write_obj(&cli->out, fh);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: file handle or -errno */
static enum service_result csop_dupfd(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct gitfs_node *gn;

	csipc_fetch_or_return(cli, &fh);
	gn = csipc_file(cli, fh);
	fh = (gn == NULL) ? -EBADF : csipc_add_file(cli, gn);
	pcbuf_write_obj(&cli->out, fh);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: '\0'-terminated name (empty on error) */
static enum service_result csop_getname(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct gitfs_node *gn;

	csipc_fetch_or_return(cli, &fh);
	gn = csipc_file(cli, fh);
	if (gn == NULL || gn->parent == gn) {
		static const char nul = '\0';
		pcbuf_write_obj(&cli->out, nul);
	} else
		pcbuf_write(&cli->out, gn->name, 1 + strlen(gn->name));
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: nothing */
static enum service_result csop_cd_up(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct csipc_open_file *of;

	csipc_fetch_or_return(cli, &fh);
	of = csipc_ofile(cli, fh);
	if (of != NULL && of->s.gn->parent != of->s.gn) {
		struct gitfs_node *parent = of->s.gn->parent;
		gn_hold(parent);
		gn_unsave_node(&of->s);
		gn_save_node(&of->s, parent);
		gn_release_notlast(parent);
	}
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: filter; Out: list of matching objects */
static enum service_result csop_dump_gobj(struct csipc_client *cli)
{
	struct gobj_dump_filter filt;

	csipc_fetch_or_return(cli, &filt);
	gobj_dump_answer(&cli->out, &filt);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: list type/perm/sha1/name tuples */
static enum service_result csop_gls(struct csipc_client *cli)
{
	csipc_fh_t fh;

	csipc_fetch_or_return(cli, &fh);
	gitdir_ls_answer(&cli->out, csipc_file(cli, fh));
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: nothing; Out: list of inode dump structure */
static enum service_result csop_dump_ino(struct csipc_client *cli)
{
	ino_dump_answer(&cli->out);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: inode dump structure */
static enum service_result csop_dump_ino_single(struct csipc_client *cli)
{
	csipc_fh_t fh;

	csipc_fetch_or_return(cli, &fh);
	ino_dump_single_answer(&cli->out, csipc_file(cli, fh));
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: true or false*/
static enum service_result csop_is_viewroot(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct gitfs_node *gn;
	int32_t answer = -EBADF;

	csipc_fetch_or_return(cli, &fh);
	gn = csipc_file(cli, fh);
	if (gn != NULL)
		answer = gn_is_viewroot(gn);
	pcbuf_write_obj(&cli->out, answer);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

/* In: file handle; Out: -error, struct gs_view_info */
static enum service_result csop_get_view_info(struct csipc_client *cli)
{
	csipc_fh_t fh;
	struct gitfs_node *gn;
	int32_t error;

	csipc_fetch_or_return(cli, &fh);
	gn = csipc_file(cli, fh);
	error = 0;
	if (gn == NULL)
		error = -EBADF;
	else if (gn->view == NULL)
		error = -ENODEV;
	pcbuf_write_obj(&cli->out, error);
	if (error == 0)
		gitview_get_info(&cli->out, gn->view);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

static enum service_result cliserv_conf_fetch_pt2(struct csipc_client *cli)
{
	char var[cli->state.conf_fetch.varlen + 1];

	csipc_get_bytes_or_return(cli, var, cli->state.conf_fetch.varlen);
	var[cli->state.conf_fetch.varlen] = '\0';
	conf_answer_client_query(&cli->out, var);
	csipc_client_command_finished(cli);
	return SERVICED_OK;
}

static enum service_result csop_conf_fetch(struct csipc_client *cli)
{
	csipc_fetch_or_return(cli, &cli->state.conf_fetch.varlen);
	/*
	 * OK, we've read the length and stashed it in our state.  Since
	 * the rest might not be available yet we have to do the rest in
	 * its own handler function
	 */
	cli->service = cliserv_conf_fetch_pt2;
	return SERVICED_OK;
}

typedef uint32_t csipc_opcode_t;
#define CSOP_OPEN_INODE		(0)
#define CSOP_CLOSE		(1)
#define CSOP_DUPFD		(2)
#define CSOP_GETNAME		(3)
#define CSOP_CD_UP		(4)
#define CSOP_DUMP_GOBJ		(5)
#define CSOP_GLS		(6)
#define CSOP_DUMP_INO		(7)
#define CSOP_DUMP_INO_SINGLE	(8)
#define CSOP_IS_VIEWROOT	(9)
#define CSOP_GET_VIEW_INFO	(10)
#define CSOP_CONF_FETCH		(11)

static enum service_result cliserv_getopcode(struct csipc_client *cli)
{
	static const csop_service_fn services[] = {
		[CSOP_OPEN_INODE] = csop_open_inode,
		[CSOP_CLOSE] = csop_close,
		[CSOP_DUPFD] = csop_dupfd,
		[CSOP_GETNAME] = csop_getname,
		[CSOP_CD_UP] = csop_cd_up,
		[CSOP_DUMP_GOBJ] = csop_dump_gobj,
		[CSOP_GLS] = csop_gls,
		[CSOP_DUMP_INO] = csop_dump_ino,
		[CSOP_DUMP_INO_SINGLE] = csop_dump_ino_single,
		[CSOP_IS_VIEWROOT] = csop_is_viewroot,
		[CSOP_GET_VIEW_INFO] = csop_get_view_info,
		[CSOP_CONF_FETCH] = csop_conf_fetch,
	};
	csipc_opcode_t opcode;

	csipc_fetch_or_return(cli, &opcode);
	gdbg("CSIPC: client %u opcode %u",
	     cli->client_num, (unsigned int) opcode);
	if (unlikely(opcode >= (sizeof(services) / sizeof(services[0])))) {
	    bad_opcode:
		gdbg("CSIPC: client %u sent unknown opcode %u",
		    cli->client_num, (unsigned int) opcode);
		return SERVICED_ERROR;
	}
	cli->service = services[opcode];
	if (cli->service == NULL) {
		csipc_client_command_finished(cli);
		goto bad_opcode;
	}
	return SERVICED_OK;
}

static void csipc_client_init(int fd)
{
	static unsigned int next_client_num = 1;
	struct csipc_client *cli = malloc(sizeof(*cli));

	if (cli == NULL) {
		gdbg("CSIPC: no memory to handle new client!");
		(void) close(fd);
		return;
	}
	cli->sfd = fd;
	cli->files = empty_rbtree;
	cli->next_fh = 0;
	cli->last_writeavail = 0;
	csipc_client_command_finished(cli);
	pcbuf_init(&cli->in);
	pcbuf_init(&cli->out);
	cli->client_num = next_client_num++;
	epoll_add(fd, cli);
	gdbg("CSIPC: new client %u", cli->client_num);
}

static void csipc_client_die(struct csipc_client *cli,
			     const char *etype, int error)
{
	assert(error >= 0);
	if (error != 0)
		gdbg("CSIPC: client %u dying on %s error: %s",
		     cli->client_num, etype, strerror(error));
	else
		gdbg("CSIPC: client %u closing", cli->client_num);
	(void) epoll_del(cli->sfd);
	(void) close(cli->sfd);
	csipc_client_fini(cli);
}

static void csipc_client_service(struct csipc_client *cli)
{
	enum service_result (*func)(struct csipc_client *cli);
	int res;

	/* First, read in any data that arrived */
	res = pcbuf_fromfd(&cli->in, cli->sfd);
	if ((res != 0 && res != -EAGAIN) || cli->in.error != 0) {
		res = -res;
		if (res == 0)
			res = cli->in.error;
		assert(res > 0);
		if (res == ECHILD)
			res = 0;	/* normal hangup */
		csipc_client_die(cli, "input", res);
		return;
	}
	/* Next, run the service routine currently in place */
	do {
		enum service_result sr;
		func = cli->service;
		sr = func(cli);
		if (sr != SERVICED_OK) {
			csipc_client_die(cli, "processing",
				 (sr == SERVICED_EOF) ? 0 : -EIO);
			return;
		}
		/*
		 * As a convinience, if the callback function updated
		 * ->service, run the new callback immediately
		 */
	} while (func != cli->service);
	/* Then write out what we can */
	res = pcbuf_tofd(&cli->out, cli->sfd);
	if ((res != 0 && res != -EAGAIN) || cli->out.error != 0) {
		res = -res;
		if (res == 0)
			res = cli->out.error;
		assert(res > 0);
		csipc_client_die(cli, "output", res);
		return;
	}
	/* Last, tell epoll if we're waiting on writability or not */
	res = (cli->out.cur_size > 0);
	if (res != cli->last_writeavail) {
		if (epoll_mod(cli->sfd, cli, res ? O_RDWR : O_RDONLY) != 0) {
			csipc_client_die(cli, "epoll setting", errno);
			return;
		}
		cli->last_writeavail = res;
	}
}

enum service_result csipc_service(void *token)
{
	if (likely(token != &ipc_socket_fd))
		csipc_client_service(token);
	else
		for (;;) {
			struct sockaddr_un cliaddr;
			socklen_t addrlen = sizeof(cliaddr);
			int fd = accept(ipc_socket_fd, &cliaddr, &addrlen);
			if (fd < 0) {
				fd = errno;
				if (fd == EINTR || fd == EAGAIN)
					break;
				perror("accept");
				return SERVICED_ERROR;
			}
			if (set_nonblock(fd) != 0) {
				(void) close(fd);
				return SERVICED_ERROR;
			}
			csipc_client_init(fd);
		}
	return SERVICED_OK;
}

/* CLIENT-SIDE ROUTINES: */

struct gitfs_server_connection {
	int fd;
	char rbuf[4096];	/* must be a power of two! */
	unsigned int rptr, wptr;
};

enum gs_wait_type {
	GSWAIT_READ = POLLIN | POLLERR | POLLHUP | POLLRDNORM,
	GSWAIT_WRITE = POLLOUT | POLLERR | POLLHUP | POLLWRNORM,
};
static int gs_wait(const struct gitfs_server_connection *gsc,
		   enum gs_wait_type wtype)
{
	struct pollfd pfd;

	pfd.fd = gsc->fd;
	pfd.events = (short) wtype;
	if (poll(&pfd, 1, -1) < 0 && errno != EINTR) {
		perror("CSIPC: poll");
		return -1;
	}
	return 0;
}

static int gs_write(const struct gitfs_server_connection *gsc,
		    const void *data, size_t datalen)
{
	while (datalen > 0) {
		int rv = write(gsc->fd, data, datalen);
		if (rv <= 0) {
			if (rv == 0)
				goto wait;
			switch (errno) {
			case EAGAIN:
			    wait:
				if (gs_wait(gsc, GSWAIT_WRITE) != 0)
					return -1;
				/* FALLTHROUGH */
			case EINTR:
				continue;
			}
			perror("CSIPC: write");
			return -1;
		}
		assert(rv <= (int) datalen);
		datalen -= rv;
		data += rv;
	}
	return 0;
}

static int gs_read(struct gitfs_server_connection *gsc,
		   void *data, size_t datalen)
{
	assert(datalen <= sizeof(gsc->rbuf));
	while (gsc->wptr - gsc->rptr < datalen) {
		int rv;
		char *start = &gsc->rbuf[gsc->wptr % sizeof(gsc->rbuf)];
		const char *end = &gsc->rbuf[gsc->rptr % sizeof(gsc->rbuf)];
		if (end <= start)
			end = &gsc->rbuf[sizeof(gsc->rbuf)];
	    again:
		assert(end > start);
		rv = read(gsc->fd, start, (size_t) (end - start));
		if (rv <= 0) {
			if (rv == 0) {
				fprintf(stderr, "CSIPC: EOF while reading\n");
				return -1;
			}
			switch (errno) {
			case EAGAIN:
				if (gs_wait(gsc, GSWAIT_READ) != 0)
					return -1;
				/* FALLTHROUGH */
			case EINTR:
				goto again;
			}
			perror("CSIPC: read");
			return -1;
		}
		gsc->wptr += rv;
		assert(gsc->wptr - gsc->rptr <= sizeof(gsc->rbuf));
	}
	/*
	 * OK, we have at least datalen bytes in the ring buffer, we just
	 * have to copy out them to "data"
	 */
	while (datalen > 0) {
		const char *start, *end;
		size_t to_copy;
		assert(gsc->rptr != gsc->wptr);
		start = &gsc->rbuf[gsc->rptr % sizeof(gsc->rbuf)];
		end = &gsc->rbuf[gsc->wptr % sizeof(gsc->rbuf)];
		if (end <= start)
			end = &gsc->rbuf[sizeof(gsc->rbuf)];
		assert(end > start);
		to_copy = end - start;
		if (to_copy > datalen)
			to_copy = datalen;
		memcpy(data, start, to_copy);
		gsc->rptr += to_copy;
		data += to_copy;
		datalen -= to_copy;
	}
	return 0;
}

/* Helper function to send a command and get a response */
static int gs_cmd_resp(struct gitfs_server_connection *gsc,
		       const void *cmd, size_t cmdlen,
		       void *reply, size_t replylen)
{
	if (gs_write(gsc, cmd, cmdlen) != 0 ||
	    gs_read(gsc, reply, replylen) != 0)
		return -1;
	return 0;
}

csipc_fh_t gs_open_inode(struct gitfs_server_connection *gsc,
			 gitfs_inum_t inum)
{
	struct {
		csipc_opcode_t opcode;
		gitfs_inum_t inum;
	} cmd;
	csipc_fh_t reply;

	cmd.opcode = CSOP_OPEN_INODE;
	cmd.inum = inum;
	if (gs_cmd_resp(gsc, &cmd, sizeof(cmd), &reply, sizeof(reply)) != 0)
		reply = -EIO;
	return reply;
}

void gs_connection_close(struct gitfs_server_connection *gsc)
{
	if (gsc != NULL) {
		(void) close(gsc->fd);
		free(gsc);
	}
}

/* Called from the client to connect to the server */
struct gitfs_server_connection *gs_connection_open(void)
{
	struct gitfs_server_connection *gsc;
	struct sockaddr_un uaddr;
	struct {
		gitfs_inum_t inum;
		char path[sizeof(uaddr.sun_path)];
	} discresult;
	int dfd, res;
	csipc_fh_t fh;
	struct stat st;

	gsc = malloc(sizeof(*gsc));
	if (gsc == NULL) {
		fprintf(stderr, "CSIPC: couldn't allocate memory!\n");
		return NULL;
	}
	gsc->rptr = gsc->wptr = 0;
	memset(&discresult.path, 0, sizeof(discresult.path));
	gsc->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (gsc->fd < 0) {
		perror("socket");
		free(gsc);
		return NULL;
	}
	dfd = open(CSIPC_DISCOVERY_FILE, O_RDONLY);
	if (dfd < 0) {
		fprintf(stderr, "Not a gitfs filesystem.\n");
		gs_connection_close(gsc);
		return NULL;
	}
	/* double check to make SURE we got the right file */
	if (fstat(dfd, &st) != 0 || st.st_ino != CSIPC_INODE_NUM) {
		fprintf(stderr, "Not a gitfs filesystem.\n");
		(void) close(dfd);
		gs_connection_close(gsc);
		return NULL;
	}
    read_again:
	res = read(dfd, &discresult, sizeof(discresult));
	if (res < (int) (sizeof(discresult.inum) + 2)) {
		if (res < 0) {
			if (errno == EINTR)
				goto read_again;
			perror("read(\"" CSIPC_DISCOVERY_FILE "\")");
		} else
			fprintf(stderr, "Short read (%d bytes) during "
				"IPC discovery!\n", res);
		(void) close(dfd);
		gs_connection_close(gsc);
		return NULL;
	}
	uaddr.sun_family = AF_UNIX;
	memcpy(uaddr.sun_path, discresult.path, sizeof(uaddr.sun_path));
	if (connect(gsc->fd, (const struct sockaddr *) &uaddr,
		    SUN_LEN(&uaddr)) != 0) {
		perror("connect(gitfs IPC)");
		(void) close(dfd);
		gs_connection_close(gsc);
		return NULL;
	}
	if (set_nonblock(gsc->fd) != 0) {
		(void) close(dfd);
		gs_connection_close(gsc);
		return NULL;
	}
	/*
	 * Note: we open the initial inode BEFORE we close the discovery
	 * file.  This makes sure that the inum is pinned in the server since
	 * it's the discovery file's parent!
	 */
	fh = gs_open_inode(gsc, discresult.inum);
	if (close(dfd) != 0) {
		perror("close(\"" CSIPC_DISCOVERY_FILE "\")");
		gs_connection_close(gsc);
		return NULL;
	}
	/*
	 * Our caller should be able to assume that the initial open became
	 * filehandle zero
	 */
	if (fh != 0) {
		if (fh < 0)
			fprintf(stderr, "CSIPC: initial open had error "
				"from server: %s\n", strerror(-fh));
		else
			fprintf(stderr, "CSIPC: got non-zero file handle "
				"(%d) from initial open!\n", (int) fh);
		gs_connection_close(gsc);
		return NULL;
	}
	return gsc;
}

int gs_close(struct gitfs_server_connection *gsc, csipc_fh_t fh)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	int32_t reply;

	cmd.opcode = CSOP_CLOSE;
	cmd.fh = fh;
	if (gs_cmd_resp(gsc, &cmd, sizeof(cmd), &reply, sizeof(reply)) != 0)
		reply = -EIO;
	return reply;
}

csipc_fh_t gs_dupfd(struct gitfs_server_connection *gsc, csipc_fh_t fh)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	csipc_fh_t reply;

	cmd.opcode = CSOP_DUPFD;
	cmd.fh = fh;
	if (gs_cmd_resp(gsc, &cmd, sizeof(cmd), &reply, sizeof(reply)) != 0)
		reply = -EIO;
	return reply;
}

static int gs_read_tonul(struct gitfs_server_connection *gsc,
			 char *buf, size_t buflen)
{
	char c;

	while (buflen > 0) {
		if (gs_read(gsc, buf, sizeof(*buf)) != 0)
			return -EIO;
		if (*buf == '\0')
			return 0;
		buf++;
		buflen--;
	}
	/* We overflowed; still consume bytes from the socket */
	do {
		if (gs_read(gsc, &c, sizeof(c)) != 0)
			return -EIO;
	} while (c != '\0');
	return -E2BIG;
}

int gs_getname(struct gitfs_server_connection *gsc, csipc_fh_t fh,
	       char *buf, size_t buflen)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	int res;

	cmd.opcode = CSOP_GETNAME;
	cmd.fh = fh;
	res = gs_write(gsc, &cmd, sizeof(cmd));
	if (res == 0)
		res = gs_read_tonul(gsc, buf, buflen);
	return res;
}

int gs_cd_up(const struct gitfs_server_connection *gsc, csipc_fh_t fh)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;

	cmd.opcode = CSOP_CD_UP;
	cmd.fh = fh;
	return gs_write(gsc, &cmd, sizeof(cmd));
}

int gs_dump_gobj(struct gitfs_server_connection *gsc,
		 const struct gobj_dump_filter *filt,
		 void *buf, size_t buflen,
		 enum service_result (*work)(const void *data, void *state),
		 void *state)
{
	enum service_result sres;
	struct {
		csipc_opcode_t opcode;
		struct gobj_dump_filter filt;
	} cmd;

	cmd.opcode = CSOP_DUMP_GOBJ;
	cmd.filt = *filt;
	if (gs_write(gsc, &cmd, sizeof(cmd)) != 0)
		return -1;
	do {
		if (gs_read(gsc, buf, buflen) != 0)
			return -1;
		sres = work(buf, state);
	} while (sres == SERVICED_OK);
	return (sres == SERVICED_EOF) ? 0 : -1;
}

static void failed_to_copy_name(void)
{
	gdbg("CSIPC: gls: failed to copy name!");
}

int gs_gls(struct gitfs_server_connection *gsc, csipc_fh_t fh,
	   enum service_result (*work)(enum gitfs_node_type type,
				       mode_t perm,
				       const struct gitobj_ptr *ptr,
				       const char *name))
{
	enum service_result sres;
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;

	cmd.opcode = CSOP_GLS;
	cmd.fh = fh;
	if (gs_write(gsc, &cmd, sizeof(cmd)) != 0)
		return -1;
	do {
		struct {
			enum gitfs_node_type type;
			mode_t mode;
			struct gitobj_ptr ptr;
		} lsitem;
		char name[PATH_MAX];
	    next_item:
		if (gs_read(gsc, &lsitem, sizeof(lsitem)) != 0)
			return -1;
		switch (gs_read_tonul(gsc, name, sizeof(name))) {
		case 0:
			break;
		case -E2BIG:
			failed_to_copy_name();
			goto next_item;
		default:
			return -1;
		}
		sres = work(lsitem.type, lsitem.mode, &lsitem.ptr, name);
	} while (sres == SERVICED_OK);
	return (sres == SERVICED_EOF) ? 0 : -1;
}

int gs_dump_ino_single(struct gitfs_server_connection *gsc, csipc_fh_t fh,
		       void *buf, size_t buflen,
		       enum service_result (*work)(const void *data,
						   const char *name,
						   void *state),
		       void *state)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	char name[PATH_MAX];

	cmd.opcode = CSOP_DUMP_INO_SINGLE;
	cmd.fh = fh;
	if (gs_write(gsc, &cmd, sizeof(cmd)) != 0)
		return -1;
	if (gs_read(gsc, buf, buflen) != 0)
		return -1;
	switch (gs_read_tonul(gsc, name, sizeof(name))) {
	case 0:
		break;
	case -E2BIG:
		failed_to_copy_name();
		/* FALLTHROUGH */
	default:
		return -1;
	}
	return (work(buf, name, state) == SERVICED_OK) ? 0 : -1;
}

int gs_dump_ino(struct gitfs_server_connection *gsc, void *buf, size_t buflen,
		enum service_result (*work)(const void *data,
					    const char *name, void *state),
		void *state)
{
	static const csipc_opcode_t opcode = CSOP_DUMP_INO;
	enum service_result sres;

	if (gs_write(gsc, &opcode, sizeof(opcode)) != 0)
		return -1;
	do {
		char name[PATH_MAX];
	    next_item:
		if (gs_read(gsc, buf, buflen) != 0)
			return -1;
		switch (gs_read_tonul(gsc, name, sizeof(name))) {
		case 0:
			break;
		case -E2BIG:
			failed_to_copy_name();
			goto next_item;
		default:
			return -1;
		}
		sres = work(buf, name, state);
	} while (sres == SERVICED_OK);
	return (sres == SERVICED_EOF) ? 0 : -1;
}

int gs_is_viewroot(struct gitfs_server_connection *gsc, csipc_fh_t fh)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	int32_t reply;

	cmd.opcode = CSOP_IS_VIEWROOT;
	cmd.fh = fh;
	if (gs_cmd_resp(gsc, &cmd, sizeof(cmd), &reply, sizeof(reply)) != 0)
		reply = -EIO;
	return reply;
}

int gs_get_view_info(struct gitfs_server_connection *gsc, csipc_fh_t fh,
		     struct gs_view_info *vinfo, size_t reslen)
{
	struct {
		csipc_opcode_t opcode;
		csipc_fh_t fh;
	} cmd;
	int32_t error;

	if (reslen < sizeof(*vinfo))
		return -E2BIG;
	cmd.opcode = CSOP_GET_VIEW_INFO;
	cmd.fh = fh;
	if (gs_cmd_resp(gsc, &cmd, sizeof(cmd), &error, sizeof(error)) != 0)
		return -EIO;
	if (error != 0) {
		assert(error < 0);
		return error;
	}
	if (gs_read(gsc, vinfo, sizeof(*vinfo)) != 0)
		return -EIO;
	return gs_read_tonul(gsc, vinfo->symbolic_name,
			     reslen - sizeof(*vinfo));
}

int gs_conf_raw_fetch(struct gitfs_server_connection *gsc, const char *var,
		      char *result, size_t reslen)
{
	struct {
		csipc_opcode_t opcode;
		uint32_t varlen;
		/* followed by variable name, not '\0'-terminated */
	} cmd;
	uint32_t found;

	cmd.opcode = CSOP_CONF_FETCH;
	cmd.varlen = strlen(var);
	if (gs_write(gsc, &cmd, sizeof(cmd)) != 0 ||
	    gs_cmd_resp(gsc, var, cmd.varlen, &found, sizeof(found)) != 0)
		return -EIO;
	if (found == 0)
		return -ENOENT;
	return gs_read_tonul(gsc, result, reslen);
}
