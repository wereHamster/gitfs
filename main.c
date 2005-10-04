/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#define _GNU_SOURCE		/* for sigset() */
#include "gitfs.h"
#include "defaults.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
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

static void print_usage(const char *argv0)
{
	argv0 += basename_offset(argv0);
	fprintf(stderr,
	  "%s: usage:\n"
	  "\t"	"%s [-f] [-d] [-O <ocache_dir>] <gitdir> <mntpoint>\n"
	  "\t"  "%s -u [-d] <mntpoint>\n"
	  "\n"
	  "Options:\n"
	  "\t"	"-f : run in foreground, unmount on clean exit\n"
	  "\t"	"-d : turn on debugging mode (implies -f)\n"
	  "\t"	"-O : specify object cache directory\n"
	  "\t"	"-u : unmount gitfs filesystem\n",
		argv0, argv0, argv0);
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

int gitfs_debug = 0;
const char *ocache_dir = DEFAULT_OBJECT_CACHE_DIR;
int gitfs_please_exit = 0;

static void got_signal(int sig)
{
	(void) sig;
	gitfs_please_exit = 1;
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

	for (i = 0; i < (sizeof(hands) / sizeof(hands[0])); i++)
		if (sigset(hands[i].sig, hands[i].handler) == SIG_ERR)
			return -1;
	return 0;
}

int main(int argn, char * const *argv)
{
	const char *argv0;
	int n;
	int do_umount = 0;
	int got_mount_arg = 0;
	int run_in_foreground = 0;

	argv0 = argv[0];
	while (n = getopt(argn, argv, "fduO:"), n != EOF)
		switch (n) {
		case 'f':
			run_in_foreground = 1;
			break;
		case 'd':
			gitfs_debug = 1;
			break;
		case 'u':
			do_umount = 1;
			break;
		case 'O':
			ocache_dir = optarg;
			got_mount_arg = 1;
			break;
		default:
			print_usage(argv0);
			return 8;
		}
	argv += optind;

	if (do_umount != 0) {
		if (argv[0] == NULL || argv[1] != NULL ||
		    got_mount_arg != 0) {
			print_usage(argv0);
			return 8;
		}
		return api_umount(argv[0]);
	}
	if (argv[0] == NULL || argv[1] == NULL || argv[2] != NULL) {
		print_usage(argv0);
		return 8;
	}
	if (chdir_to_git(argv[0]) != 0)
		return 8;
	if (prepare_git_environment() != 0)
		return 8;
	n = api_prepare_mount(argv[1]);
	if (n != 0)
		return n;
	if (gitfs_debug == 0 && run_in_foreground == 0 && daemon(1, 0) != 0) {
		perror("daemonize");
		api_abandon_mount();
		return 8;
	}
	if (set_signals() != 0) {
		perror("sigset");
		api_abandon_mount();
		return 8;
	}
	return api_run_mount();
}
