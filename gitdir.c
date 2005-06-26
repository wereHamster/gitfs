/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

/*
 * TODO - maybe hold onto original allocated space and point all the names
 * into there?
 */
void gitdir_free(struct gitdir *gdir)
{
	unsigned int i;

	for (i = 0; i < gdir->nentries; i++)
		free(gdir->entries[i].name);
	free(gdir->entries);
	free(gdir);
}

#include <stdio.h>
/*
 * fills in "r" with the data based on the tree data at "data".  "*datalenp"
 * is left updated
 */
static int gitdir_parse_one(struct gitdir_entry *r,
			    const unsigned char *data, size_t *datalenp)
{
	const unsigned char *d, *end;
	const char *name;

	assert(*datalenp > 0);
	memset(r, 0, sizeof(*r));
	/*
	 * Entries in a git "tree" object are:
	 *   1. An octal "mode" value
	 *   2. ASCII space
	 *   3. name of file
	 *   4. ASCII '\0'
	 *   5. 20 byte sha1 value
	 */
	d = data;
fprintf(stderr, "parsing '%s'\n", d);
	end = d + *datalenp;
	assert(end > d);
	r->perm = 0;
	do {
		if (*d < '0' || *d > '7')
			return -EIO;
		r->perm = (r->perm * 8) + (*d - '0');
		if (++d >= end)
			return -EIO;
	} while (*d != ' ');
	if (++d >= end || *d == '\0')
		return -EIO;
	name = (const char *) d;
	do {
		if (++d >= end)
			return -EIO;
	} while  (*d != '\0');
	d++;
	if (&d[sizeof(r->ptr.sha1)] > end)
		return -EIO;
	memcpy(&r->ptr.sha1[0], d, sizeof(r->ptr.sha1));
	d += sizeof(r->ptr.sha1);
	assert(d <= end);
	assert(d > data);
	assert((d - data) <= (int) *datalenp);
	if (S_ISREG(r->perm))
		r->type = GFN_FILE;
	else if (S_ISDIR(r->perm))
		r->type = GFN_DIR;
	else if (S_ISLNK(r->perm))
		r->type = GFN_SYMLINK;
	else
		return -ENXIO;
	r->perm &= 0777;
	/* Not every object (notably directories) carry file permissions */
	if (r->perm == 0)
		r->perm = (mode_t) -1;
	r->name = strdup(name);
	if (r->name == NULL)
		return -ENOMEM;
	*datalenp -= (d - data);
	return 0;
}

static int gitdir_entry_compare(const void *v1, const void *v2)
{
	return strcmp(((const struct gitdir_entry *) v1)->name,
		      ((const struct gitdir_entry *) v2)->name);
}

/*
 * Given the number of bytes left in the tree object to parse, returns the
 * number of additional directory entries to allocate
 */
static unsigned int to_add(size_t bytes_left)
{
	unsigned int result = bytes_left / 28;	/* wild guess */

	/*
	 * To mitigate cases where we always underestimate (and to avoid
	 * the special case where a tiny entry at the end causes us to
	 * add zero entries) we always
	 * allocate at least a few
	 */
	return (result < 6) ? 6 : result;
}

int gitdir_parse(struct gitdir **resultp,
		 const unsigned char *data, size_t datalen)
{
	struct gitdir *gdir;
	struct gitdir_entry *ent;
	unsigned int nalloced = 0;
	int ret;

	gdir = calloc(1, sizeof(*gdir));
	if (gdir == NULL)
		return -ENOMEM;
	data += datalen;
	while (datalen > 0) {
		if (gdir->nentries >= nalloced) {
			struct gitdir_entry *ne;
			assert(gdir->nentries == nalloced);
			nalloced += to_add(datalen);
			ne = realloc(gdir->entries,
				     nalloced * sizeof(gdir->entries[0]));
			if (ne == NULL) {
				gitdir_free(gdir);
				return -ENOMEM;
			}
			gdir->entries = ne;
		}
		assert(gdir->nentries < nalloced);
		ent = &gdir->entries[gdir->nentries];
		ret = gitdir_parse_one(ent, data - datalen, &datalen);
		if (ret != 0) {
			assert(ret < 0);
			gitdir_free(gdir);
			return ret;
		}
		gdir->nentries++;
		if (ent->type == GFN_DIR)
			gdir->nsubdirs++;
	}
	assert(gdir->nsubdirs <= gdir->nentries);
	/* We do binary searches in this table so the names must be sorted */
	qsort(gdir->entries, gdir->nentries, sizeof(gdir->entries[0]),
	      gitdir_entry_compare);
	(void) time(&gdir->atime);
	*resultp = gdir;
	return 0;
}

struct gitdir_entry *gitdir_find(struct gitdir *gdir, const char *name)
{
	struct gitdir_entry *es;
	int l, r, i, cr;

	/*
	 * TODO - cache last successful lookup and check for LRU and
	 * directory scanning
	 */
	assert(gdir != NULL);
	(void) time(&gdir->atime);
	if (gdir->nentries == 0)
		return NULL;
	es = gdir->entries;
	assert(es != NULL);
	l = 0;
	r = gdir->nentries - 1;
	do {
		assert(l >= 0);
		assert(r < (int) gdir->nentries);
		i = (l + r) / 2;
		cr = strcmp(name, es[i].name);
		/* TEMPORARY DEBUGGING: */
		if (gitfs_debug != 0)
			fprintf(stderr, "Seaching for '%s', %d/%d%d, "
				"got '%s', result=%d\n", name, l, i, r,
				es[i].name, cr);
		if (cr == 0)
			return &es[i];
		if (cr < 0)	/* name < current element */
			r = i - 1;
		else		/* name > current element */
			l = i + 1;
	} while (r >= l);
	/* TEMPORARY DEBUGGING: */
	if (gitfs_debug != 0) {
		fprintf(stderr, "NOT FOUND\n");
		for (i = 0; i < (int) gdir->nentries; i++)
			if (0==strcmp(es[i].name, name))
				fprintf(stderr, "WAS AT %d!!!!\n", i);
	}
	return NULL;
}

void gitdir_readdir(struct gitdir *gdir, struct api_readdir_state *ars)
{
	unsigned int i;

	assert(gdir != NULL);
	(void) time(&gdir->atime);
	for (i = 0; i < gdir->nentries; i++) {
		struct gitdir_entry *e = &gdir->entries[i];
		if (api_add_dir_contents(ars, e->name, e->type) != 0)
			break;
	}
}
