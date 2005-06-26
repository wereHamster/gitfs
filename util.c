/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mman.h>
#include "cache.h"	/* from git core */

int neg_errno(void)
{
	if (errno > 0)
		return -errno;
	/*
	 * Like in the linux kernel we often indicate failure by returning
	 * -errno.  Of couse errno should always be positive after any
	 * syscall failure, but just in case we use this function for the
	 * negation.  I just picked EADDRNOTAVAIL since it is unlikely
	 * to be returned by a normal filesystem call
	 */
	return -EADDRNOTAVAIL;
}

/* Write "dir/fn" into buf, with robust size checking */
int create_fullpath(char *buf, size_t bufsiz, const char *dir, const char *fn)
{
	size_t x;

	assert(fn != NULL);
	if (dir != NULL) {
		x = strlen(dir);
		if (x >= bufsiz)
			return -ENAMETOOLONG;
		memcpy(buf, dir, x);
		buf += x;
		bufsiz -= x;
		if (x > 0 && buf[-1] != '/') {
			if (bufsiz < 1)
				return -ENAMETOOLONG;
			*buf++ = '/';
			bufsiz--;
		}
	}
	x = strlen(fn) + 1;	/* Include '\0' in final memcpy */
	if (x > bufsiz)
		return -ENAMETOOLONG;
	memcpy(buf, fn, x);
	return 0;
}


/* returns modification time of inode or 0 on error */
time_t mtime_of(const char *path)
{
	struct stat st;

	return (stat(path, &st) == 0) ? st.st_mtime : 0;
}

size_t basename_offset(const char *path)
{
	size_t result = 0, i = 0;

	while (*path != '\0') {
		if (*path == '/' && path[1] != '/' && path[1] != '\0')
			result = i + 1;
		path++;
		i++;
	}
	return result;
}

void strdup_if_needed(char **destp, const char *src)
{
	assert(destp != NULL);
	assert(src != NULL);
	if (*destp == NULL || 0 != strcmp(*destp, src)) {
		free(*destp);
		*destp = strdup(src);
	}
}

/* Set *ptr based on hex string in file; returns non-zero on error */
int read_ptr(int fd, struct gitobj_ptr *ptr)
{
	/* we allow for two whitespace characters ("\r\n") at end... */
	char buf[(sizeof(ptr->sha1) * 2) + 3];
	int count;
	const char *p;

	count = read(fd, buf, sizeof(buf));
	if (count < 0) {
		// TODO - print error
		return count;
	}
	if ((unsigned int) count >= sizeof(buf)) {
		assert(count == sizeof(buf));
		// TODO - print error
		return -ENAMETOOLONG;
	}
	buf[count] = '\0';
	p = buf;
	if (get_sha1_hex(p, &ptr->sha1[0]) != 0) {
		// TODO - print error
		return -EINVAL;
	}
	for (p += HEX_PTR_LEN; *p != '\0'; p++)
		if (*p != '\r' && *p != '\n') {
			// TODO - print error
			return -EINVAL;
		}
	return 0;
}
// TODO - might be better for above to take filename argument instead of fd

int symlink_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISLNK(st.st_mode);
}

/* Make a directory and all of its parents as needed */
int recursive_mkdir(const char *path, int strip_basename)
{
	char pbuf[PATH_MAX];
	int ret;

	if (strip_basename != 0) {
		size_t boff = basename_offset(path);
		if (boff >= sizeof(pbuf))
			return -ENAMETOOLONG;
		memcpy(pbuf, path, boff);
		while (boff > 0 && pbuf[boff - 1] == '/')
			boff--;
		if (boff == 0)
			return -ERANGE;	/* something went really wrong! */
		pbuf[boff] = '\0';
		path = pbuf;
	}
	if (mkdir(path, 0755) == 0 || errno == EEXIST)
		return 0;
	if (errno != ENOENT)
		return neg_errno();
	ret = recursive_mkdir(path, 1);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	if (mkdir(path, 0755) != 0 && errno != EEXIST)
		return neg_errno();
	return 0;
}

int write_safe(int wfd, void *data, size_t datalen)
{
	size_t off = 0;
	ssize_t progress;

	while (off < datalen) {
		progress = write(wfd, data + off, datalen - off);
		if (progress <= 0) {
			if (progress < 0 && errno == EAGAIN)
				continue;
			return (progress < 0) ? neg_errno() : -ENOSPC;
		}
		off += progress;
	}
	return 0;
}

int copy_fd_to_fname(int rfd, const char *dst)
{
	unsigned char *p;
	struct stat st;
	int wfd, ret;

	if (fstat(rfd, &st) != 0)
		return neg_errno();
	p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, rfd, 0);
	if (p == MAP_FAILED)
		return neg_errno();
	wfd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (wfd < 0) {
		int ret = neg_errno();
		(void) munmap(p, st.st_size);
		return ret;
	}
	ret = write_safe(wfd, p, st.st_size);
	if (ret != 0) {
		assert(ret < 0);
		(void) munmap(p, st.st_size);
		(void) unlink(dst);
		return ret;
	}
	return 0;
}

int move_file(const char *src, const char *dst)
{
	int fd, ret;

	/* First, try to rename if they're on the same fs */
	if (rename(src, dst) == 0)
		return 0;
	if (errno != EXDEV)
		return neg_errno();
	fd = open(src, O_RDONLY);
	if (fd < 0)
		return neg_errno();
	ret = copy_fd_to_fname(fd, dst);
	if (ret != 0) {
		assert(ret < 0);
		return ret;
	}
	if (close(fd) == 0 && (unlink(src) == 0 || errno == ENOENT))
		return 0;
	/* Final unlink() failed; try to roll back copy if possible */
	ret = neg_errno();
	(void) unlink(dst);
	return ret;
}
