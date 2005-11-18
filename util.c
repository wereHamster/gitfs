/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#define _GNU_SOURCE	/* for clock_gettime() */
#include "gitfs.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "cache.h"	/* for get_sha1_hex() */

int
#ifdef __GNUC__
    __attribute__ ((warn_unused_result))
#endif /* __GNUC__ */
neg_errno(void)
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

void timespec(struct timespec *now)
{
	int rv = clock_gettime(CLOCK_REALTIME, now);

	if (unlikely(rv != 0)) {
		perror("clock_gettime");
		abort();
	}
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

    read_again:
	count = read(fd, buf, sizeof(buf));
	if (count < 0) {
		if (errno == EINTR)
			goto read_again;
		gdbg("error reading git ptr from file: %s", strerror(errno));
		return count;
	}
	if ((unsigned int) count >= sizeof(buf)) {
		assert(count == sizeof(buf));
		gdbg("git ptr in file was too long");
		return -ENAMETOOLONG;
	}
	buf[count] = '\0';
	p = buf;
	if (get_sha1_hex(p, &ptr->sha1[0]) != 0) {
		gdbg("git ptr in file was invalid SHA1");
		return -EINVAL;
	}
	for (p += HEX_PTR_LEN; *p != '\0'; p++)
		if (*p != '\r' && *p != '\n') {
			gdbg("git ptr in file had extra characters after");
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

int write_safe(int wfd, const void *data, size_t datalen)
{
	size_t off = 0;
	ssize_t progress;

	while (off < datalen) {
		progress = write(wfd, data + off, datalen - off);
		if (progress <= 0) {
			int rv;
			if (progress < 0) {
				rv = neg_errno();
				if (rv == -EINTR || errno == -EAGAIN)
					continue;
			} else
				rv = -ENOSPC;
			return rv;
		}
		off += progress;
	}
	return 0;
}

int read_safe(int rfd, void *data, size_t datalen)
{
	size_t off = 0;
	ssize_t progress;

	while (off < datalen) {
		progress = read(rfd, data + off, datalen - off);
		if (progress <= 0) {
			int rv;
			if (progress < 0) {
				rv = neg_errno();
				if (rv == -EINTR || errno == -EAGAIN)
					continue;
			} else
				rv = -ENOMSG;
			return rv;
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

int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0) {
		perror("fcntl(F_GETFL)");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl(F_SETFL)");
		return -1;
	}
	return 0;
}

void gitptr_ascii(struct gitobj_ptr_ascii *o, const struct gitobj_ptr *gp)
{
	const unsigned char *b = &gp->sha1[0];
	char *r = &o->ascii[0];
	unsigned int i = 0;

	do {
		*r++ = xdigit_lc[(*b >> 4) & 0xF];
		*r++ = xdigit_lc[(*b >> 0) & 0xF];
		b++;
	} while (++i < sizeof(gp->sha1));
	*r = '\0';
}

int gitptr_to_fname(char *buf, size_t bufsiz, const char *dir,
		    const struct gitobj_ptr *gp)
{
	const unsigned char *b;
	unsigned int i;

	if (dir != NULL && *dir != '\0') {
		size_t dlen = strlen(dir);
		if (bufsiz <= dlen)
			return -ENAMETOOLONG;
		memcpy(buf, dir, dlen);
		buf += dlen;
		bufsiz -= dlen;
		if (buf[-1] != '/') {
			if (bufsiz < 1)
				return -ENAMETOOLONG;
			*buf++ = '/';
			bufsiz--;
		}
	}
	if (bufsiz < 2 + HEX_PTR_LEN)
		return -ENAMETOOLONG;
	b = &gp->sha1[0];
	for (i = 0; i < sizeof(gp->sha1); i++) {
		*buf++ = xdigit_lc[(*b >> 4) & 0xF];
		*buf++ = xdigit_lc[(*b >> 0) & 0xF];
		b++;
		if (i == 0)
			*buf++ = '/';
	}
	*buf = '\0';
	return 0;
}

/*
 * Convert a string into an unsigned integer.  This is a very strict
 * implementation: no leading zeros, overflow is prevented
 */
int convert_uint64(const char *str, uint64_t *res)
{
	if (str[0] == '\0')
		return -1;
	if (str[0] == '0' && str[1] != '\0')
		return -1;
	*res = 0;
	do {
		if (*str < '0' || *str > '9')
			return -1;
		if (*res > ((~(uint64_t) 0) - 9) / 10)
			return -1;	/* overflow risk */
		*res = ((*res) * 10) + (*str - '0');
	} while (*++str != '\0');
	return 0;
}
