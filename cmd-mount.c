/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#define _GNU_SOURCE		/* for sigset(), canonicalize_file_name() */
#include "gitfs.h"
#include "defaults.h"
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "cache.h"		/* from git core */

/* Set up git to read from the current directory */
static int prepare_git_environment(void)
{
	static const struct {
		const char *s;
	} to_unset[] = {
		{ ALTERNATE_DB_ENVIRONMENT },
		{ "SHA1_FILE_DIRECTORIES" },
		{ DB_ENVIRONMENT },
		{ "SHA1_FILE_DIRECTORY" },
		{ INDEX_ENVIRONMENT },
	};
	unsigned int i;

	for (i = 0; i < sizeof(to_unset) / sizeof(to_unset[0]); i++)
		unsetenv(to_unset[i].s);
	if (setenv(GIT_DIR_ENVIRONMENT, ".", 1) != 0) {
		perror("setenv");
		return -1;
	}
	return 0;
}

static int chdir_to_git(const char *path)
{
	struct stat dummy_st;

	if (chdir(path) != 0) {
		perror("chdir to git dir");
		return -1;
	}
	/*
	 * For convinience, if it looks like the user didn't specify the
	 * final "/.git" part of the path, assume it was there
	 */
	if (stat(".git/objects/.", &dummy_st) == 0)
		(void) chdir(".git");
	return 0;
}

static unsigned int count_path_elements(const char *path)
{
	unsigned int answer = 0;

	if (*path == '\0')
		goto done;
	for (;;) {
		answer++;
		do {
			if (*++path == '\0')
				goto done;
		} while (*path != '/');
	}
    done:
	return answer;
}

char *relative_path_to_gitdir;
size_t relative_path_to_gitdir_len;

/*
 * Initialize "relative_path_to_git" to be a relative pathname for reaching
 * the current directory (i.e. the ".git/" dir) suitable for making symlinks
 */
static int mk_relative_path_to_gitdir(const char *mntpt)
{
	char *curpath, *v;
	size_t mskip, cskip;
	unsigned int dotdot_needed;

	curpath = canonicalize_file_name(".");
	if (curpath == NULL) {
		perror("getting current path");
		return -1;
	}
	assert(mntpt[0] == '/');
	assert(curpath[0] == '/');
	mskip = cskip = 1;
	for (;;) {
		size_t elemsize;
		const char *p;
		if (mntpt[mskip] == '/') {
			mskip++;
			continue;
		}
		if (curpath[cskip] == '/') {
			cskip++;
			continue;
		}
		if (mntpt[mskip] == '\0' || curpath[cskip] == '\0')
			break;
		/* find the size of the current element */
		p = &mntpt[mskip];
		do {
			p++;
		} while (*p != '/' && *p != '\0');
		elemsize = p - &mntpt[mskip];
		assert(elemsize > 0);
		if (0 != memcmp(&mntpt[mskip], &curpath[cskip], elemsize))
			break;
		p = &curpath[cskip + elemsize];
		if (*p != '/' && *p != '\0')
			break;
		mskip += elemsize;
		cskip += elemsize;
	}
	dotdot_needed = count_path_elements(&mntpt[mskip]);
	mskip = strlen(&curpath[cskip]);	/* reusing here... */
	relative_path_to_gitdir = malloc(
		(strlen_const("../") * dotdot_needed) + mskip + 2);
	if (relative_path_to_gitdir == NULL) {
		perror("allocating memory for relative_path_to_gitdir");
		free(curpath);
		return -1;
	}
	v = relative_path_to_gitdir;
	while (dotdot_needed-- != 0) {
		*v++ = '.';
		*v++ = '.';
		*v++ = '/';
	}
	if (mskip != 0) {
		memcpy(v, &curpath[cskip], mskip);
		v += mskip;
		*v++ = '/';
	}
	*v = '\0';
	free(curpath);
	relative_path_to_gitdir_len = v - relative_path_to_gitdir;
	return 0;
}

const char *ocache_dir = DEFAULT_OBJECT_CACHE_DIR;	// TODO allow override

static int selfpipe_fds[2];
#define SELFPIPE_CHECK	(selfpipe_fds[0])
#define SELFPIPE_SEND	(selfpipe_fds[1])

/*
 * This is the "self-pipe trick" for handling signals syncronously inside a
 * poll() loop.  See:
 *   http://cr.yp.to/docs/selfpipe.html
 */
static int selfpipe_setup(void)
{
	if (pipe(selfpipe_fds) < 0) {
		perror("pipe");
		return -1;
	}
	if (set_nonblock(SELFPIPE_CHECK) != 0 ||
	    set_nonblock(SELFPIPE_SEND) != 0)
		return -1;
	return 0;
}

void selfpipe_ping(void)
{
	static const char dummy = '\0';

	(void) write(SELFPIPE_SEND, &dummy, sizeof(dummy));
}

static int please_exit = 0;

static enum service_result selfpipe_service_poll(void)
{
	char dummy;

	if (unlikely(please_exit != 0))
		return SERVICED_EOF;
	gitwork_service_replies();
	/*
	 * Note -- there could be more than one than character in the selfpipe
	 * but we can't read more than one or we'd expose ourselves to a
	 * race condition where an asynchronous notifier hits us while we're
	 * in the character-reading loop.  Instead we'll just get woken up
	 * the next time through the poll() loop
	 */
	(void) read(SELFPIPE_CHECK, &dummy, 1);
	return SERVICED_OK;
}

static void got_signal(UNUSED_ARG(int sig))
{
	please_exit = 1;
	selfpipe_ping();
}

static int set_signals(void)
{
	static const struct {
		int sig;
		void (*handler)(int);
	} hands[] = {
		{ SIGHUP, got_signal },
		{ SIGINT, got_signal },
		{ SIGTERM, got_signal },
		{ SIGPIPE, SIG_IGN },
	};
	unsigned int i;

	if (selfpipe_setup() != 0)
		return -1;
	for (i = 0; i < (sizeof(hands) / sizeof(hands[0])); i++)
		if (sigset(hands[i].sig, hands[i].handler) == SIG_ERR)
			return -1;
	return 0;
}

/* string suitable for use in a temporary file name */
char instance_str[128];

static void mk_instance_str(void)
{
	char hostname[256];

	if (gethostname(hostname, sizeof(hostname)) != 0)
		hostname[0] = '\0';
	else {
		char *h = hostname;
		/* POSIX doesn't garauntee '\0' termination */
		hostname[sizeof(hostname) - 1] = '\0';
		while (*h != '\0' && *h != '.')
			h++;
		*h = '\0';
	}
	snprintf(instance_str, sizeof(instance_str),
		 "._%u,%s", (unsigned int) getpid(), hostname);
}

static int epoll_fd;

int epoll_add(int fd, void *token)
{
	struct epoll_event epev;
	int res;

	epev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
	epev.data.ptr = token;
	res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &epev);
	if (res != 0)
		perror("epoll_ctl(EPOLL_CTL_ADD)");
	return res;
}

int epoll_mod(int fd, void *token, int newmode)
{
	struct epoll_event epev;
	int res;

	switch (newmode) {
	case O_RDONLY:
		epev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
		break;
	case O_WRONLY:
		epev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
		break;
	case O_RDWR:
		epev.events = EPOLLIN | EPOLLPRI | EPOLLOUT |
				EPOLLERR | EPOLLHUP;
		break;
	default:
		assert(0);
	}
	epev.data.ptr = token;
	res = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epev);
	if (res != 0)
		perror("epoll_ctl(EPOLL_CTL_MOD)");
	return res;
}

int epoll_del(int fd)
{
	int res;

	res = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	if (res != 0)
		perror("epoll_ctl(EPOLL_CTL_DEL)");
	return res;
}

static int cmd_mount(int argn, char * const *argv)
{
	int n, mntfd;
	int run_in_foreground = 0;
	enum service_result res = SERVICED_OK;
	char *mount_location;
	static const struct gitcmd_option mount_opts[] = {
		{
			.name = "ro",
			.type = GOP_BOOL,
		},
	};

	while (n = getopt(argn, argv, "Fro:"), n != EOF)
		switch (n) {
		case 'F':
			run_in_foreground = 1;
			break;
		case 'r':
			*((const char **) &optarg) = "ro";
			/* FALLTHROUGH */
		case 'o':
			if (add_command_line_option(optarg) != 0)
				return 8;
			break;
		default:
			print_usage();
			return 8;
		}
	argv += optind;
	if (argv[0] == NULL || argv[1] == NULL || argv[2] != NULL) {
		print_usage();
		return 8;
	}
	mk_instance_str();
	mount_location = canonicalize_file_name(argv[1]);
	if (mount_location == NULL) {
		perror("can't resolve mount location");
		return 4;
	}
	if (chdir_to_git(argv[0]) != 0)
		return 8;
	if (mk_relative_path_to_gitdir(mount_location) != 0)
		return 8;
	if (prepare_git_environment() != 0)
		return 8;
	if (gitfs_server_read_config() != 0)
		return 8;
	epoll_fd = epoll_create(20);
	if (epoll_fd < 0) {
		perror("epoll_create");
		return 4;
	}
	if (csipc_init() != 0) {
		close(epoll_fd);
		return 8;
	}
	n = server_conf_bool_validate("ro", mount_opts, 0);
	if (n < 0 || (mntfd = api_open_mount(mount_location, n)) < 0) {
		close(epoll_fd);
		csipc_fini();
		return 4;
	}
	if (epoll_add(mntfd, NULL) != 0) {
		api_umount();
		close(epoll_fd);
		csipc_fini();
		return 4;
	}
	if (gitfs_debug == 0 && run_in_foreground == 0 && daemon(1, 0) != 0) {
		perror("daemonize");
		api_umount();
		close(epoll_fd);
		csipc_fini();
		return 4;
	}
	if (gitwork_init() != 0) {
		api_umount();
		close(epoll_fd);
		csipc_fini();
		gitwork_fini();
		return 8;
	}
	if (set_signals() != 0) {
		perror("sigset");
		api_umount();
		close(epoll_fd);
		csipc_fini();
		gitwork_fini();
		return 8;
	}
	if (epoll_add(SELFPIPE_CHECK, &SELFPIPE_CHECK) != 0) {
		api_umount();
		close(epoll_fd);
		csipc_fini();
		gitwork_fini();
		return 4;
	}
	do {
		struct epoll_event epev;
		assert(res == SERVICED_OK);
		n = epoll_wait(epoll_fd, &epev, 1, -1);
		if (unlikely(n <= 0)) {
			if (n != 0)
				switch (errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					perror("epoll_wait");
					res = SERVICED_ERROR;
				}
		} else if (likely(epev.data.ptr == NULL))
			res = api_service_poll();
		else if (epev.data.ptr == &SELFPIPE_CHECK)
			res = selfpipe_service_poll();
		else
			res = csipc_service(epev.data.ptr);
	} while (res == SERVICED_OK);
	csipc_fini();
	gitwork_fini();
	api_umount();
	close(epoll_fd);
	return (res == SERVICED_ERROR) ? 4 : 0;
}
static const char *mount_aliases[] = { "mnt", NULL };
const struct gitfs_subcommand scmd_mount = {
	.cmd = "mount",
	.aliases = mount_aliases,
	.handler = &cmd_mount,
	.usage =
	  "& [-d] mount [-r] [-F] [-o <option>[=<value>]] "
						"<gitdir> <mntpoint>\n"
	  "\t"	"-r : mount read-only\n"
	  "\t"	"-F : run in foreground, unmount on clean exit\n"
	  "\t"	"-o : override configuration option",
};

static int cmd_umount(UNUSED_ARG(int argn), char * const *argv)
{
	if (argv[1] == NULL || argv[2] != NULL) {
		print_usage();
		return 8;
	}
	return api_umount_and_exit(argv[1]);
}
static const char *umount_aliases[] = { "unmount", "umnt", "unmnt", NULL };
const struct gitfs_subcommand scmd_umount = {
	.cmd = "umount",
	.aliases = umount_aliases,
	.handler = &cmd_umount,
	.usage = "& [-d] umount <mntpoint>",
};
