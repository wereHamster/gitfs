/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include "defaults.h"
#include <stdio.h>
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
	  "\t"	"%s [-d] [-O <ocache_dir>] <gitdir> <mntpoint>\n"
	  "\t"  "%s [-u] [-d] <mntpoint>\n"
	  "\n"
	  "Options:\n"
	  "\t"	"-d : turn on debugging mode (runs in foreground)\n"
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

// TODO -- currently I can't turn gitfs_debug OFF.  fuse_main() calls
//   the libc daemon() function when not in debugging mode which does
//   a chdir("/"), wiping out the effect of the chdir_to_git()  I'll
//   look into working around this later
int gitfs_debug = 1;
const char *ocache_dir = DEFAULT_OBJECT_CACHE_DIR;

int main(int argn, char * const *argv)
{
	const char *argv0;
	int c;
	int do_umount = 0;
	int got_mount_arg = 0;

	argv0 = argv[0];
	for (;;) {
		c = getopt(argn, argv, "duO:");
		if (c == EOF)
			break;
		switch (c) {
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
	if (chdir_to_git(argv[0]) != 0) {
		perror("chdir to git root");
		return 8;
	}
	if (prepare_git_environment() != 0)
		return 8;
	return api_mount(argv[1]);
}
