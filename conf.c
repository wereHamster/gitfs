/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2006  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "cache.h"		/* for git_config() */

struct config_setting {
	struct rb_node rb;	/* keep first! */
	char *val;
	char var[0];		/* keep last! */
};

static inline struct config_setting *rbtree_to_conf(struct rb_node *rb)
{
	struct config_setting *cs = (struct config_setting *) rb;

	assert(rb == &cs->rb);
	return cs;
}

static struct rb_tree gitfsconf = EMPTY_RBTREE;

/*
 * Temporary tree to hold the options given on the command line.  In the
 * server they are moved into gitfsconf after parsing the command line.
 * In clients they are checked before querying the server
 */
static struct rb_tree from_cmd_line = EMPTY_RBTREE;

static struct rb_node **conftree_walk(struct rb_tree *rbt,
				      const char *var, size_t varlen)
{
	struct rb_node **rp;

	rbtree_walk(rbt, rp) {
		struct config_setting *s = rbtree_to_conf(*rp);
		int cmp = strncmp(var, s->var, varlen);
		if (cmp == 0) {
			if (s->var[varlen] == '\0')
				break;
			cmp = 1;
		}
		rp = &(*rp)->child[cmp < 0];
	}
	return rp;
}

static int add_conf_to_tree(struct rb_tree *rbt,
			    const char *var, size_t varlen, const char *val)
{
	struct rb_node **rp;
	struct config_setting *s;
	char *copyval;

	if (varlen == 0)
		return 0;	/* silently ignore empty option name */
	copyval = strdup(val);
	if (copyval == NULL)
		return -1;
	rp = conftree_walk(rbt, var, varlen);
	if (RB_IS_NIL(*rp)) {
		s = malloc((sizeof(*s) + 1) + varlen);
		if (s == NULL) {
			free(copyval);
			return -1;
		}
		memcpy(&s->var[0], var, varlen);
		s->var[varlen] = '\0';
		rbtree_insert(rp, &s->rb);
	} else {	/* config item already exists? just replace */
		s = rbtree_to_conf(*rp);
		free(s->val);
	}
	s->val = copyval;
	return 0;
}

/* parse option=value strings from command line */
int add_command_line_option(const char *ostr)
{
	const char *v;
	size_t varlen;
	int rv;

	v = ostr;
	while (*v != '\0' && *v != '=')
		v++;
	varlen = v - ostr;
	if (*v == '\0')
		v = "1";	/* default value */
	else
		v++;
	rv = add_conf_to_tree(&from_cmd_line, ostr, varlen, v);
	if (rv != 0)
		fprintf(stderr, "Error: no memory to record \"%s\" option\n",
			ostr);
	return rv;
}

#ifdef NDEBUG
#define assert_options_in_order(list, count)	do { } while (0)
#else /* !NDEBUG */
static void assert_options_in_order(const struct gitcmd_option *list,
				    unsigned int count)
{
	unsigned int i;

	for (i = 1; i < count; i++)
		assert(strcmp(list[i - 1].name, list[i].name) < 0);
}
#endif /* NDEBUG */

static const struct gitcmd_option *find_opt_in_list(
					const struct gitcmd_option *list,
					unsigned int count,
					const char *var)
{
	if (count >= 1) {
		int l, r;
		l = 0;
		r = count - 1;
		do {
			int cr;
			unsigned int i;
			assert(l >= 0);
			assert(r < (int) count);
			i = (l + r) / 2;
			cr = strcmp(var, list[i].name);
			if (cr == 0)
				return &list[i];
			if (cr < 0)
				r = i - 1;
			else
				l = i + 1;
		} while (r >= l);
	}
	return NULL;
}

static int string_to_bool_val(const char *str)
{
	static const struct {
		const char *s;
		int val;
	} aliases[] = {
		{ "true",	1 },
		{ "false",	0 },
		{ "yes",	1 },
		{ "no",		0 },
	};
	unsigned int i;

	if ((str[0] == '0' || str[0] == '1') && str[1] == '\0')
		return str[0] - '0';
	for (i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
		if (0 == strcasecmp(str, aliases[i].s))
			return aliases[i].val;
	return -1;
}

static int validate_one(const struct gitcmd_option *gop, const char *val)
{
	switch (gop->type) {
	case GOP_BOOL:
		if (string_to_bool_val(val) < 0) {
			fprintf(stderr, "Invalid boolean value \"%s\" "
				"specified for %s option\n", val, gop->name);
			return -1;
		}
		break;
	case GOP_UINT:
	{
		uint64_t n;
		if (convert_uint64(val, &n) != 0) {
			fprintf(stderr, "Invalid unsigned integer \"%s\" "
				"specified for %s option\n", val, gop->name);
			return -1;
		}
		if (n < gop->range.min) {
			fprintf(stderr, "Value %llu is too small for %s "
				"option (minimum is %llu)\n",
				(unsigned long long) n, gop->name,
				(unsigned long long) gop->range.min);
			return -1;
		}
		if (gop->range.max > 0 && n > gop->range.max) {
			fprintf(stderr, "Value %llu is too large for %s "
				"option (maximum is %llu)\n",
				(unsigned long long) n, gop->name,
				(unsigned long long) gop->range.max);
			return -1;
		}
	}
		break;
	default:
		break;
	}
	if (gop->validate == NULL)
		return 0;
	return gop->validate(gop, val);
}

int validate_command_line_options_wcount(const struct gitcmd_option *list,
					 unsigned int count)
{
	struct rb_node *rb;

	assert_options_in_order(list, count);
	for (rb = rbtree_first(&from_cmd_line); rb != NULL;
	     rb = rbtree_next(rb)) {
		const struct gitcmd_option *gop;
		const struct config_setting *s = rbtree_to_conf(rb);
		gop = find_opt_in_list(list, count, s->var);
		if (gop == NULL) {
			fprintf(stderr, "Unknown option \"%s\" specified on "
				"command line\n", s->var);
			return -1;
		}
		if (validate_one(gop, s->val) != 0)
			return -1;
	}
	return 0;
}

static int gitfs_config_file_worker(const char *var, const char *val)
{
	static const char prefix[] = { 'g', 'i', 't', 'f', 's', '.' };
	int rv;

	if (0 != memcmp(var, prefix, sizeof(prefix)))
		return 0;
	var += sizeof(prefix);
	rv = add_conf_to_tree(&gitfsconf, var, strlen(var), val);
	if (rv != 0)
		fputs("Error: out of memory while reading git config\n",
		      stderr);
	return rv;
}

int gitfs_server_read_config(void)
{
	struct stat dummy_st;

	/* If there's a normal git config file, read it */
	if (stat("config", &dummy_st) == 0 &&
	    git_config(gitfs_config_file_worker) != 0)
		return -1;
	/*
	 * Now take all of the entries previously put into the "from_cmd_line"
	 * and add them to the "gitfsconf" tree, overriding any values we just
	 * read.  This has the advantage that we only need to do lookups
	 * in one place
	 */
	for (;;) {
		struct config_setting *s;
		struct rb_node **rp;
		s = rbtree_to_conf(rbtree_first(&from_cmd_line));
		if (s == rbtree_to_conf(NULL))
			break;		/* tree is now empty */
		rbtree_delete(&s->rb);
		rp = conftree_walk(&gitfsconf, s->var, strlen(s->var));
		if (RB_IS_NIL(*rp))
			rbtree_insert(rp, &s->rb);
		else {
			char *newval = s->val;
			free(s);
			s = rbtree_to_conf(*rp);
			free(s->val);
			s->val = newval;
		}
	}
	return 0;
}

static struct config_setting *find_config_setting(struct rb_tree *tree,
						  const char *var)
{
	struct rb_node *rb = *conftree_walk(tree, var, strlen(var));

	return RB_IS_NIL(rb) ? NULL : rbtree_to_conf(rb);
}

/* Answer a query to the configuration database over the csipc link */
void conf_answer_client_query(struct pcbuf *out, const char *var)
{
	const struct config_setting *s = find_config_setting(&gitfsconf, var);
	uint32_t found;

	found = (s != NULL);
	pcbuf_write_obj(out, found);
	if (found != 0)
		pcbuf_write(out, s->val, 1 + strlen(s->val));
}

/* Functions callable from the server to check configuration: */

int server_conf_bool_wvalid(const char *var,
			    const struct gitcmd_option *list,
			    unsigned int count, int defval)
{
	const struct config_setting *s = find_config_setting(&gitfsconf, var);

	if (s == NULL)
		return defval;
	if (list != NULL) {
		const struct gitcmd_option *gop;
		gop = find_opt_in_list(list, count, var);
		assert(gop != NULL);
		assert(gop->type == GOP_BOOL);
		if (validate_one(gop, s->val) != 0)
			return -1;
	}
	return string_to_bool_val(s->val);
}

int server_conf_uint_wvalid(const char *var, uint64_t *resultp,
			    const struct gitcmd_option *list,
			    unsigned int count, uint64_t defval)
{
	const struct config_setting *s = find_config_setting(&gitfsconf, var);

	if (s == NULL) {
		*resultp = defval;
		return 0;
	}
	if (list != NULL) {
		const struct gitcmd_option *gop;
		gop = find_opt_in_list(list, count, var);
		assert(gop != NULL);
		assert(gop->type == GOP_UINT);
		if (validate_one(gop, s->val) != 0)
			return -1;
	}
	return convert_uint64(s->val, resultp);
}

int server_conf_str_wvalid(const char *var, char *buf, size_t buflen,
			   const struct gitcmd_option *list,
			   unsigned int count, const char *defval)
{
	const struct config_setting *s = find_config_setting(&gitfsconf, var);
	size_t copylen;

	if (s == NULL) {
		copylen = 1 + strlen(defval);
		assert(copylen <= buflen);
		memcpy(buf, defval, copylen);
		return 0;
	}
	if (list != NULL) {
		const struct gitcmd_option *gop;
		gop = find_opt_in_list(list, count, var);
		assert(gop != NULL);
		assert(gop->type == GOP_STRING);
		if (validate_one(gop, s->val) != 0)
			return -1;
	}
	copylen = 1 + strlen(s->val);
	if (copylen > buflen)
		return -1;
	memcpy(buf, s->val, copylen);
	return 0;
}

/*
 * Functions callable from the clients to check configuration.  We first
 * check our command-line options and then query the server
 */

int gs_conf_bool_wvalid(struct gitfs_server_connection *gsc,
			const char *var,
			const struct gitcmd_option *list, unsigned int count,
			int defval)
{
	const struct config_setting *s;
	char buf[64];
	int rv;

	s = find_config_setting(&from_cmd_line, var);
	if (s != NULL) /* No need to verify; we already checked it */
		return string_to_bool_val(s->val);
	/* Next, query the server and see if IT has a value */
	rv = gs_conf_raw_fetch(gsc, var, buf, sizeof(buf));
	if (rv != 0) {
		assert(rv < 0);
		return (rv == -ENOENT) ? defval : -1;
	}
	if (list != NULL) {
		const struct gitcmd_option *gop;
		gop = find_opt_in_list(list, count, var);
		assert(gop != NULL);
		assert(gop->type == GOP_BOOL);
		if (validate_one(gop, buf) != 0)
			return -1;
	}
	return string_to_bool_val(buf);
}

int gs_conf_uint_wvalid(struct gitfs_server_connection *gsc,
			const char *var, uint64_t *resultp,
			const struct gitcmd_option *list, unsigned int count,
			uint64_t defval)
{
	const struct config_setting *s;
	char buf[64];
	int rv;

	s = find_config_setting(&from_cmd_line, var);
	if (s != NULL) /* No need to verify; we already checked it */
		return convert_uint64(s->val, resultp);
	/* Next, query the server and see if IT has a value */
	rv = gs_conf_raw_fetch(gsc, var, buf, sizeof(buf));
	if (rv != 0) {
		assert(rv < 0);
		*resultp = defval;
		return (rv == -ENOENT) ? 0 : -1;
	}
	if (list != NULL) {
		const struct gitcmd_option *gop;
		gop = find_opt_in_list(list, count, var);
		assert(gop != NULL);
		assert(gop->type == GOP_UINT);
		if (validate_one(gop, buf) != 0)
			return -1;
	}
	return convert_uint64(buf, resultp);
}

int gs_conf_str_wvalid(struct gitfs_server_connection *gsc,
		       const char *var, char *buf, size_t buflen,
		       const struct gitcmd_option *list, unsigned int count,
		       const char *defval)
{
	const struct config_setting *s;
	size_t copylen;

	s = find_config_setting(&from_cmd_line, var);
	if (s != NULL) {
		copylen = 1 + strlen(s->val);
		if (copylen > buflen)
			return -1;
		defval = s->val;
		goto do_memcpy;
	}
	switch (gs_conf_raw_fetch(gsc, var, buf, buflen)) {
	case -ENOENT:
		copylen = 1 + strlen(defval);
	    do_memcpy:
		assert(copylen <= buflen);
		memcpy(buf, defval, copylen);
		break;
	case 0:
		if (list != NULL) {
			const struct gitcmd_option *gop;
			gop = find_opt_in_list(list, count, var);
			assert(gop != NULL);
			assert(gop->type == GOP_STRING);
			if (validate_one(gop, buf) != 0)
				return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}
