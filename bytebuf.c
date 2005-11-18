/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  bytebuf.c -- Simple overflow-safe byte buffer
 */

#include "gitfs.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static size_t bb_roundsize(size_t sz)
{
	if (sz != 0) {
		size_t nsz = 128;
		while (nsz < sz)
			nsz <<= 1;
		sz = nsz;
	}
	return sz;
}

void bytebuf_init(struct bytebuf *bb, size_t space_before, size_t space_after)
{
	bb->error = 0;
	if (space_before + space_after == 0)
		space_after = 1;
	space_before = bb_roundsize(space_before);
	space_after = bb_roundsize(space_after);
	bb->alloc.start = malloc(space_before + space_after);
	if (bb->alloc.start == NULL) {
		bb->error = ENOMEM;
		return;
	}
	bb->alloc.end = &bb->alloc.start[space_before + space_after];
	bb->stored.end = bb->stored.start = &bb->alloc.start[space_before];
	bb->spoint = bb->stored.start;
}

void bytebuf_destroy(struct bytebuf *bb)
{
	free(bb->alloc.start);
	memset(bb, 0, sizeof(*bb));
}

static inline size_t bb_space_before(const struct bytebuf *bb)
{
	assert(bb->stored.start >= bb->alloc.start);
	return bb->stored.start - bb->alloc.start;
}

static inline size_t bb_space_after(const struct bytebuf *bb)
{
	assert(bb->alloc.end >= bb->stored.end);
	return bb->alloc.end - bb->stored.end;
}

/*
 * Add at least "before" bytes to the beginning and "after" bytes to the
 * end of bytebuf
 */
static void bb_realloc(struct bytebuf *bb, size_t before, size_t after)
{
	char *n, *nstart;

	assert(unlikely(bb->error == 0));
	assert(before == 0 || after == 0);
	before = bb_roundsize(before + (bb->spoint - bb->alloc.start));
	after = bb_roundsize(after + (bb->alloc.end - bb->spoint));
	if (before == 0) {
		n = realloc(bb->alloc.start, before + after);
		if (n == bb->alloc.start) {
			bb->alloc.end = &n[before + after];
			return;
		}
	} else
		n = malloc(before + after);
	if (n == NULL) {
		free(bb->alloc.start);
		bb->alloc.start = NULL;
		bb->error = ENOMEM;
		return;
	}
	/*
	 * Since "n + before" is our new "spoint", we can use that to
	 * determine where to copy into
	 */
	nstart = (n + before) - (bb->spoint - bb->stored.start);
	bb->spoint = n + before;
	memcpy(nstart, bb->stored.start, bytebuf_len(bb));
	free(bb->alloc.start);
	bb->alloc.start = n;
	bb->alloc.end = n + (before + after);
	bb->stored.end = nstart + bytebuf_len(bb);
	bb->stored.start = nstart;
}

void bytebuf_prepend(struct bytebuf *bb, const char *src, size_t srclen)
{
	size_t space_before;

    again:
	if (unlikely(bb->error != 0))
		return;
	space_before = bb_space_before(bb);
	if (unlikely(space_before < srclen)) {
		size_t to_add = bb->spoint - bb->alloc.start;
		if (to_add == 0)
			to_add = 128;
		bb_realloc(bb, to_add, 0);
		goto again;
	}
	bb->stored.start -= srclen;
	assert(bb->stored.start >= bb->alloc.start);
	memcpy(bb->stored.start, src, srclen);
}

void bytebuf_append(struct bytebuf *bb, const char *src, size_t srclen)
{
	size_t space_after;

    again:
	if (unlikely(bb->error != 0))
		return;
	space_after = bb_space_after(bb);
	if (unlikely(space_after < srclen)) {
		size_t to_add = bb->alloc.end - bb->spoint;
		if (to_add == 0)
			to_add = 128;
		bb_realloc(bb, 0, to_add);
		goto again;
	}
	memcpy(bb->stored.end, src, srclen);
	bb->stored.end += srclen;
	assert(bb->stored.end <= bb->alloc.end);
}

char *bytebuf_asptr(struct bytebuf *bb)
{
	if (unlikely(bb->error != 0)) {
		errno = bb->error;
		return NULL;
	}
	return bb->stored.start;
}
