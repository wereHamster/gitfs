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

int gitfs_debug = 0;

static const char *argv0;
static const struct gitfs_subcommand *gitfs_subcommands[];
static const struct gitfs_subcommand *subcommand = NULL;

static void print_subcommand_usage(FILE *fp, const char *prefix,
				   const struct gitfs_subcommand *sc)
{
	const char *s;
	int start_of_line = 1;

	s = sc->usage;
	assert(s != NULL);
	for (;;) {
		const char *e;
		char c;
		e = s;
		do {
			c = *e;
			if (c == '&')
				break;
			if (c == '\0') {
				if (e == s)
					return;
				break;
			}
			e++;
		} while (c != '\n');
		if (start_of_line != 0)
			fputs(prefix, fp);
		(void) fwrite(s, sizeof(*s), e - s, fp);
		start_of_line = 1;
		if (c == '&') {
			start_of_line = 0;
			fputs(argv0, fp);
			c = *++e;
		}
		if (c == '\0') {
			putc('\n', fp);
			break;
		}
		s = e;
	}
}

void print_usage(void)
{
	static const char prefix[] = "\t";

	fprintf(stderr, "%s: ", argv0);
	if (subcommand != NULL) {
		fprintf(stderr, "%s usage:\n", subcommand->cmd);
		print_subcommand_usage(stderr, prefix, subcommand);
	} else {
		unsigned int i;
		const struct gitfs_subcommand *sc;
		fputs("usage:\n", stderr);
		for (i = 0;; i++) {
			sc = gitfs_subcommands[i];
			if (sc == NULL)
				break;
			if (sc->cmd[0] != '_')
				print_subcommand_usage(stderr, prefix, sc);
		}
	}
	fputs(	"\n"
		"Global options:\n"
		"\t"	"-d : turn on debugging mode\n",
		stderr);
}

static const struct gitfs_subcommand scmd_help;

/*
 * This is searched linearly at startup time, so its a good idea to keep
 * commonly used commands near the top
 */
static const struct gitfs_subcommand *gitfs_subcommands[] = {
	&scmd_mount,
	&scmd_umount,
	&scmd_help,
	&scmd_pwd,
	&scmd_gls,
	/* debugging-only commands: */
	&debug_cmd_dump_gobj,
	&debug_cmd_dump_ino,
	NULL,
};

static int subcommand_matches(const struct gitfs_subcommand *sc,
			      const char *str)
{
	unsigned int i;

	if (0 == strcmp(sc->cmd, str))
		return 1;
	if (sc->aliases == NULL)
		return 0;
	for (i = 0; sc->aliases[i] != NULL; i++)
		if (0 == strcmp(sc->aliases[i], str))
			return 1;
	return 0;
}

static int cmd_help(UNUSED_ARG(int argn), char * const *argv)
{
	const struct gitfs_subcommand *sc;
	unsigned int i;

	if (argv[1] == NULL) {
		int first = 1;
		for (i = 0;; i++) {
			sc = gitfs_subcommands[i];
			if (sc == NULL)
				break;
			if (gitfs_debug == 0 && sc->cmd[0] == '_')
				continue;
			if (first == 0)
				putchar('\n');
			print_subcommand_usage(stdout, "", sc);
			first = 0;
		}
	} else if (argv[2] != NULL) {
		print_usage();
		return 8;
	} else {
		for (i = 0;; i++) {
			sc = gitfs_subcommands[i];
			if (sc == NULL)
				break;
			if (subcommand_matches(sc, argv[1])) {
				print_subcommand_usage(stdout, "", sc);
				return 0;
			}
		}
		fprintf(stderr, "%s: unknown command \"%s\"\n",
			argv0, argv[1]);
		return 4;
	}
	return 0;
}
static const char *help_aliases[] = { "?", NULL };
static const struct gitfs_subcommand scmd_help = {
	.cmd = "help",
	.aliases = help_aliases,
	.handler = &cmd_help,
	.usage = "& [-d] help [<command>]",
};

/*
 * We don't want to use getopt() for the top-level options since it can
 * get confused when the sub-commands use it
 */
static int process_main_option(const char *opt)
{
	static int got_dashdash = 0;

	if (got_dashdash != 0 || opt[0] != '-' || opt[1] == '\0')
		return -1;
	if (opt[1] == '-' && opt[2] == '\0') {
		got_dashdash = 1;
		return 0;
	}
	for (++opt; *opt != '\0'; opt++)
		switch (*opt) {
		case 'd':
			gitfs_debug++;
			break;
		default:
			print_usage();
			return -1;
		}
	return 0;
}

int main(int argn, char * const *argv)
{
	unsigned int i;

	argv0 = basename(argv[0]);
	do {
		argv++;
		argn--;
		if (argv[0] == NULL) {
			print_usage();
			return 8;
		}
	} while (process_main_option(argv[0]) == 0);
	for (i = 0;; i++) {
		subcommand = gitfs_subcommands[i];
		if (subcommand == NULL) {
			print_usage();
			return 8;
		}
		if (subcommand_matches(subcommand, argv[0]))
			break;
	}
	return subcommand->handler(argn, argv);
}
