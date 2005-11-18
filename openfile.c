/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */
#include "gitfs.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

/*
 * For readonly objects we might want to keep a lot of them open at once,
 * but there's little advantage to exploding the size of our own file
 * descriptor table -- therefore we keep them on an LRU and close them
 * if they haven't been used in awhile.  Since we do all access via pread()
 * we can always reopen them later if needed
 */

static struct openfile_lrulinks of_lru = {
	.next = (struct openfile *) &of_lru,
	.prev = (struct openfile *) &of_lru,
};
static unsigned int of_count = 0;
#define OPENFILE_MAX		(50)	// TODO -- make this configurable

static inline void lru_remove(struct openfile *of)
{
	of->lru.prev->lru.next = of->lru.next;
	of->lru.next->lru.prev = of->lru.prev;
}

static inline void lru_add_to_front(struct openfile *of)
{
	of->lru.prev = (struct openfile *) &of_lru;
	of->lru.next = of_lru.next;
	of_lru.next->lru.prev = of;
	of_lru.next = of;
}

int openfile_fd(struct openfile *of)
{
	assert(of != NULL);
	if (of->backing_fd >= 0 && of_lru.next != of) {
		lru_remove(of);
		lru_add_to_front(of);
	}
	return of->backing_fd;
}

void openfile_close(struct openfile *of)
{
	if (of->backing_fd >= 0) {
		lru_remove(of);
		(void) close(of->backing_fd);
		of->backing_fd = -1;
		of_count--;
	}
}

int openfile_open(struct openfile *of, const char *path)
{
	assert(of != NULL);
	assert(of->backing_fd < 0);
	if (of_count >= OPENFILE_MAX) {
		assert(of_count == OPENFILE_MAX);
		openfile_close(of_lru.prev);
		assert(of_count < OPENFILE_MAX);
	}
	of->backing_fd = open(path, O_RDONLY);
	if (of->backing_fd >= 0) {
		lru_add_to_front(of);
		of_count++;
		return of->backing_fd;
	}
	return neg_errno();
}

int openfile_stat(const struct openfile *of, struct stat *st)
{
	if (of->backing_fd < 0)
		return -EBADF;
	return (fstat(of->backing_fd, st) == 0) ? 0 : neg_errno();
}
