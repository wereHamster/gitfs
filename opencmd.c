/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  opencmd.c -- popen()-like interface for raw file descriptors
 */

#include "gitfs.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/wait.h>

static int clear_close_on_exec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
		return -1;
	return 0;
}

struct opencmd_pids {
	struct rb_node rb;	/* Keep first! */
	int fd;
	pid_t pid;
};

static struct rb_tree opencmd_pids = EMPTY_RBTREE;

static struct rb_node **opencmds_walk(int fd)
{
	struct rb_node **rp;

	rbtree_walk(&opencmd_pids, rp) {
		int tfd = ((struct opencmd_pids *) (*rp))->fd;
		if (tfd == fd)
			break;
		rp = &(*rp)->child[fd > tfd];
	}
	return rp;
}

static void dup_cmdfd(int ofd, int nfd, int close_stderr)
{
	int fd;

	if (ofd == nfd)
		return;
	(void) close(ofd);
	fd = dup2(nfd, ofd);
	if (fd < 0) {
		if (close_stderr == 0)
			perror("dup2(STDIN)");
		_exit(EX_OSERR);
	}
	assert(fd == ofd);
	(void) close(nfd);
}

static void open_devnull(int ofd, int mode, int close_stderr)
{
	int fd;

	(void) close(ofd);
	fd = open("/dev/null", mode);
	if (fd < 0) {
		if (close_stderr == 0)
			perror("open(\"/dev/null\")");
		_exit(EX_OSERR);
	}
	assert(fd == ofd);
}

/* Dir is 0 for fromcmd, 1 for tocmd */
static int open_cmd(const char *cmd, char * const argv[], int dir,
		    int other_fd, int close_stderr)
{
	struct opencmd_pids *op;
	int pipefd[2];

	assert(dir == 0 || dir == 1);
	op = malloc(sizeof(*op));
	if (op == NULL)
		return -ENOMEM;
	if (pipe(pipefd) != 0) {
		int ret = -errno;
		if (close_stderr == 0)
			perror("pipe");
		free(op);
		return ret;
	}
	assert(pipefd[0] >= 0);
	assert(pipefd[1] >= 0);
	op->fd = pipefd[dir];
	{
		struct rb_node **rp = opencmds_walk(op->fd);
		assert(RB_IS_NIL(*rp));
		rbtree_insert(rp, &op->rb);
	}
	op->pid = vfork();
	if (op->pid < 0) {
		int ret = -errno;
		if (close_stderr == 0)
			perror("vfork");
		(void) close(pipefd[0]);
		(void) close(pipefd[1]);
		rbtree_delete(&op->rb);
		free(op);
		return ret;
	}
	if (op->pid == 0) {	/* In child */
		int tfd;
		(void) close(op->fd);
		/* Prepare stdin */
		tfd = (dir == 0) ? other_fd : pipefd[0];
		if (tfd >= 0)
			dup_cmdfd(STDIN_FILENO, tfd, close_stderr);
		else
			open_devnull(STDIN_FILENO, O_RDONLY, close_stderr);
		/* Prepare stdout */
		tfd = (dir == 1) ? other_fd : pipefd[1];
		if (tfd >= 0)
			dup_cmdfd(STDOUT_FILENO, tfd, close_stderr);
		else
			open_devnull(STDOUT_FILENO, O_WRONLY, close_stderr);
		/* Prepare stderr */
		if (close_stderr != 0)
			open_devnull(STDERR_FILENO, O_WRONLY, 1);
		if (clear_close_on_exec(STDIN_FILENO) < 0 ||
		    clear_close_on_exec(STDOUT_FILENO) < 0 ||
		    clear_close_on_exec(STDERR_FILENO) < 0) {
			/* No need to check close_stderr any longer */
			perror("clear_close_on_exec");
			_exit(EX_OSERR);
		}
		(void) execvp(cmd, argv);
		if (close_stderr == 0)
			perror("execvp");
		_exit(EX_UNAVAILABLE);
	}
	/* In parent */
	(void) close(pipefd[1 - dir]);
	return op->fd;
}

int open_fromcmd(const char *cmd, char * const argv[], int stdin_fd,
		 int close_stderr)
{
	return open_cmd(cmd, argv, 0, stdin_fd, close_stderr);
}

int open_tocmd(const char *cmd, char * const argv[], int stdout_fd,
	       int close_stderr)
{
	return open_cmd(cmd, argv, 1, stdout_fd, close_stderr);
}

int close_cmd(int fd)
{
	union {
		struct opencmd_pids *op;
		struct rb_node *rp;
	} c;
	int status, rv = 0;

	c.rp = *opencmds_walk(fd);
	if (RB_IS_NIL(c.rp))
		return -ESRCH;
	rbtree_delete(c.rp);
	assert(c.rp == &c.op->rb);
	if (close(c.op->fd) != 0)
		rv = neg_errno();
	/* We have to wait() for our children or they'll become zombies */
	for (;;) {
		pid_t wp = waitpid(c.op->pid, &status, 0);
		if (wp >= 0) {
			assert(wp == c.op->pid);
			break;
		}
		status = neg_errno();
		if (status != -EINTR)
			break;
	}
	free(c.op);
	return (rv == 0) ? status : rv;
}
