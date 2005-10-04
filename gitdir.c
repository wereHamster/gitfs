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

void gitdir_free(struct gitdir *gdir)
{
	free(gdir->entries);
	free(gdir->backing_file);
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
	r->name = (const char *) d;
	do {
		if (++d >= end)
			return -EIO;
	} while  (*d != '\0');
	d++;
	if (&d[sizeof(r->ptr->sha1)] > end)
		return -EIO;
	r->ptr = (const struct gitobj_ptr *) d;
	d += sizeof(r->ptr->sha1);
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
	 * add zero entries) we always allocate at least a few
	 */
	return (result < 6) ? 6 : result;
}

int gitdir_parse(struct gitdir *gdir, unsigned char *data, size_t datalen)
{
	struct gitdir_entry *ent;
	unsigned int nalloced = 0;
	int out_of_order = -1;
	const char *last_parsed_name = "";
	int ret;

	assert(gdir->nentries == 0);
	assert(gdir->nsubdirs == 0);
	assert(gdir->entries == NULL);
	gdir->backing_file = data;
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
		/*
		 * We do binary searches on the table so the names must be
		 * sorted.  As far as I can tell git directories always are
		 * so this is just a redundant check, but for now I want to
		 * be safe
		 */
		if (out_of_order <= 0) {
			out_of_order = strcmp(last_parsed_name, ent->name);
			last_parsed_name = ent->name;
		}
	}
	assert(gdir->nsubdirs <= gdir->nentries);
	if (out_of_order != 0)
		qsort(gdir->entries, gdir->nentries, sizeof(gdir->entries[0]),
		      gitdir_entry_compare);
	(void) time(&gdir->atime);
	gdir->last_find = 0;
	return 0;
}

struct gitdir_entry *gitdir_find(struct gitdir *gdir, const char *name)
{
	struct gitdir_entry *es;
	unsigned int i;
	int l, r, cr;

	assert(gdir != NULL);
	(void) time(&gdir->atime);
	if (gdir->nentries == 0)
		return NULL;
	assert(gdir->entries != NULL);
	l = 0;
	r = gdir->nentries - 1;
	/*
	 * Two common cases are that we're looking up the same thing as
	 * last time OR we're scanning the directory linearly and just want
	 * the next entry
	 */
	i = gdir->last_find;
	assert(i < gdir->nentries);
	es = &gdir->entries[i];
	cr = strcmp(name, es->name);
	if (cr >= 0) {
		if (cr == 0)
			return es;
		if (++i > (unsigned int) r) {
			assert(i == gdir->nentries);
			return NULL;
		}
		cr = strcmp(name, (++es)->name);
		if (cr == 0) {
			gdir->last_find = i;
			return es;
		}
		if (cr < 0)
			return NULL;
		l = i + 1;
	} else {
		if (i == 0)
			return NULL;
		r = i - 1;
	}
	/* OK, we'll have to resort to a binary search */
	es = gdir->entries;
	do {
		assert(l >= 0);
		assert(r < (int) gdir->nentries);
		i = (l + r) / 2;
		cr = strcmp(name, es[i].name);
		if (cr == 0) {
			gdir->last_find = i;
			return &es[i];
		}
		if (cr < 0)	/* name < current element */
			r = i - 1;
		else		/* name > current element */
			l = i + 1;
	} while (r >= l);
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
