/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  pcbuf.c -- Simple producer/consumer buffer with an overflow-safe API
 */

#define _GNU_SOURCE		/* for strnlen() */
#include "gitfs.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct pcbuf_elem {
	char *wptr;
	const char *bufend;
	const char *rptr;
	struct pcbuf_elem *next;
	char buf[0];
};

#define PCB_FLAGS_KEEP	(0x0001)	/* Don't free after read */

/*
 * Normally, after data is read from the pcbuf it is freed immediately.
 * However, if you turn "keep" on it will be retained and you can later
 * call pcbuf_rewind() to get back to the beginning
 */
void pcbuf_keep(struct pcbuf *pc)
{
	pc->flags |= PCB_FLAGS_KEEP;
}
void pcbuf_nokeep(struct pcbuf *pc)
{
	pc->flags &= ~PCB_FLAGS_KEEP;
}

static inline size_t pcbuf_alloc_size(size_t need)
{
	size_t result = 4096;	/* always alloc at least this much */

	need += sizeof(struct pcbuf_elem);
	while (result < need)
		result <<= 1;
	return result;
}

static char *pcbuf_space(struct pcbuf *pc, size_t need)
{
	struct pcbuf_elem *pe, **linkp;
	size_t asize;

	if (unlikely(pc->error != 0))
		return NULL;
	pe = pc->active.tail;
	if (likely(pe != NULL && (pe->wptr + need) <= pe->bufend)) {
	    done:
		return pe->wptr;
	}
	linkp = (pe == NULL) ? &pc->active.head : &pe->next;
	/* OK, we have no space left in this element... allocate a new one */
	assert(*linkp == NULL);
	asize = pcbuf_alloc_size(need);
	pe = malloc(asize);
	if (pe == NULL) {
		pc->error = ENOMEM;
		return NULL;
	}
	*linkp = pe;
	pe->rptr = pe->wptr = &pe->buf[0];
	pe->bufend = asize + (const char *) pe;
	pe->next = NULL;
	pc->active.tail = pe;
	goto done;
}

/* write()-like interface to put data into a pcbuf */
void pcbuf_write(struct pcbuf *pc, const void *bytes, size_t len)
{
	char *w = pcbuf_space(pc, len);

	if (w != NULL) {
		memcpy(w, bytes, len);
		pc->active.tail->wptr += len;
		pc->cur_size += len;
		pc->total_written += len;
	}
}

/* Add "count" occurances of a character into a pcbuf */
void pcbuf_multichar(struct pcbuf *pc, char c, size_t count)
{
	char *w = pcbuf_space(pc, count);

	if (w != NULL) {
		memset(w, c, count);
		pc->active.tail->wptr += count;
		pc->cur_size += count;
		pc->total_written += count;
	}
}

/* We export xdigit_lc[] for util.c to share */
const char xdigit_lc[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};
static const char xdigit_uc[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
};

struct pcfmt_spec {
	unsigned int width;
	unsigned int limit;	/* i.e. %.30s */
	int base;	/* negatve for upper case letters */
	char prewidth;	/* ' ', '-', '0' */
	char type;	/* '\0', 'h', 'l', 'L', 'z' */
};

static void pcfmt_unsigned(struct pcbuf *pc, unsigned long long val,
			   const struct pcfmt_spec *spec)
{
	char rfmt[(sizeof(val) * 8 + 2) / 3];	/* length in octal */
	unsigned int rlen = 0;
	unsigned int base;
	const char *dgts;

	assert(spec->limit == 0);	/* we don't support precision */
	base = spec->base;
	dgts = xdigit_lc;
	if (unlikely(spec->base == -16)) {
		base = 16;
		dgts = xdigit_uc;
	}
	assert(base == 8 || base == 10 || base == 16);
	do {
		assert(rlen < sizeof(rfmt));
		rfmt[rlen++] = dgts[val % base];
		val /= base;
	} while (val != 0);
	if (rlen < spec->width && spec->prewidth != '-')
		pcbuf_multichar(pc, spec->prewidth, spec->width - rlen);
	pcbuf_write(pc, rfmt, rlen);
	if (rlen < spec->width && spec->prewidth == '-')
		pcbuf_multichar(pc, ' ', spec->width - rlen);
}

static void pcfmt_signed(struct pcbuf *pc, long long val,
			 const struct pcfmt_spec *spec)
{
	static const char minus = '-';
	unsigned long long uval = val;
	char rfmt[1 + ((sizeof(val) * 8 + 2) / 3)];
	unsigned int rlen = 0;
	int need_minus = 0;

	assert(spec->base == 10);
	assert(spec->limit == 0);	/* we don't support precision */
	if (unlikely(val < 0)) {
		uval = -val;
		need_minus = 1;
	}
	do {
		assert(rlen < sizeof(rfmt));
		rfmt[rlen++] = xdigit_lc[uval % 10];
		uval /= 10;
	} while (val != 0);
	if ((rlen + need_minus) < spec->width && spec->prewidth != '-') {
		unsigned int plen = spec->width - (rlen + need_minus);
		if (spec->prewidth == '0' && need_minus != 0) {
			pcbuf_write_obj(pc, minus);
			need_minus = 0;
		}
		pcbuf_multichar(pc, spec->prewidth, plen);
	}
	if (need_minus != 0)
		pcbuf_write_obj(pc, minus);
	pcbuf_write(pc, rfmt, rlen);
	if ((rlen + need_minus) < spec->width && spec->prewidth == '-')
		pcbuf_multichar(pc, ' ', spec->width - (rlen + need_minus));
}

static void pcfmt_string(struct pcbuf *pc, const char *str,
			 const struct pcfmt_spec *spec)
{
	size_t slen;

	assert(spec->prewidth != '0');
	slen = (spec->limit == 0) ? strlen(str) : strnlen(str, spec->width);
	assert(spec->limit == 0 || slen <= spec->width);
	if (slen < spec->width && spec->prewidth != '-')
		pcbuf_multichar(pc, ' ', spec->width - slen);
	pcbuf_write(pc, str, slen);
	if (slen < spec->width && spec->prewidth == '-')
		pcbuf_multichar(pc, ' ', spec->width - slen);
}

/*
 * printf()-like formatter to write to pcbuf's.  We don't support all the
 * formats that printf() does (notably we have no floating-point support) but
 * the basic string/integer stuff is here
 */
void pcbuf_vfmt(struct pcbuf *pc, const char *fmt, va_list ap)
{
	const char *sfmt;
	struct pcfmt_spec fspec;

    start:
	sfmt = fmt;
	while (*fmt != '\0' && *fmt != '%')
		fmt++;
	if (sfmt != fmt)
		pcbuf_write(pc, sfmt, sfmt - fmt);
	if (*fmt == '\0')
		return;
	assert(*fmt == '%');
	fspec.width = 0;
	fspec.base = 10;
	fspec.prewidth = ' ';
	fspec.type = '\0';
    next_fmt:
	switch (*++fmt) {
	case 's':
		assert(fspec.type == '\0');
		pcfmt_string(pc, va_arg(ap, const char *), &fspec);
		break;
	case 'c':
		assert(fspec.width <= 1);
		assert(fspec.prewidth == ' ');
		assert(fspec.type == '\0');
		{
			char c = va_arg(ap, int);
			pcbuf_write_obj(pc, c);
		}
		break;
	case 'l':
		if (fspec.type == 'l') {
			fspec.type = 'L';
			goto next_fmt;
		}
		/* FALLTHROUGH */
	case 'h':
	case 'z':
		assert(fspec.type == '\0');
		fspec.type = *fmt;
		goto next_fmt;
	case 'd':
	case 'i':
		{
			long long val;
			switch (fspec.type) {
			case '\0':
			case 'h':
				val = va_arg(ap, int);
				break;
			case 'z':
				val = va_arg(ap, ssize_t);
				break;
			case 'l':
				val = va_arg(ap, long);
				break;
			case 'L':
				val = va_arg(ap, long long);
				break;
			default:
				assert(0);
			}
			pcfmt_signed(pc, val, &fspec);
		}
		break;
	case 'x':
		fspec.base = 16;
		goto do_unsigned;
	case 'X':
		fspec.base = -16;
		goto do_unsigned;
	case 'o':
		fspec.base = 8;
		/* FALLTHROUGH */
	case 'u':
	    do_unsigned:
		{
			unsigned long long val;
			switch (fspec.type) {
			case '\0':
			case 'h':
				val = va_arg(ap, unsigned int);
				break;
			case 'z':
				val = va_arg(ap, size_t);
				break;
			case 'l':
				val = va_arg(ap, unsigned long);
				break;
			case 'L':
				val = va_arg(ap, unsigned long long);
				break;
			default:
				assert(0);
			}
			pcfmt_unsigned(pc, val, &fspec);
		}
		break;
	case 'p':
		assert(fmt[-1] == '%');
		{
			static const char zerox[2] = { '0', 'x' };
			static const struct pcfmt_spec ptrspec = {
				.base = 16,
				.width = sizeof(void *) * strlen_const("AA"),
				.prewidth = '0',
			};
			const void *ptr = va_arg(ap, const void *);
			pcbuf_write_obj(pc, zerox);
			pcfmt_unsigned(pc,
				(unsigned long long) (unsigned long) ptr,
				&ptrspec);
		}
		break;
	case '0':
		if (fspec.width == 0)
			goto set_prewidth;
		/* FALLTHROUGH */
	case '1' ... '9':
		fspec.width = (fspec.width * 10) + (*fmt - '0');
		goto next_fmt;
	case '-':
		assert(fspec.width == 0);
	   set_prewidth:
		assert(fspec.prewidth == ' ');
		fspec.prewidth = *fmt;
		goto next_fmt;
	case '.':
		assert(fspec.width == 0);
		assert(fspec.limit == 0);
		fspec.limit = 1;
		goto next_fmt;
	case '%':
		assert(fmt[-1] == '%');
		pcbuf_write(pc, fmt, 1);
		break;
	default:
		assert(0);
	}
	fmt++;
	goto start;
}

void pcbuf_fmt(struct pcbuf *pc, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	pcbuf_vfmt(pc, fmt, ap);
	va_end(ap);
}

static int consume_fd(int fd)
{
	char buf[4096];
	int res;

	for (;;) {
		res = read(fd, buf, sizeof(buf));
		assert(res <= (int) sizeof(buf));
		if (res <= 0) {
			if (res < 0) {
				res = neg_errno();
				if (res == -EINTR)
					continue;
			}
			break;
		}
	}
	return res;
}

/* Add the contents of file descriptor "fd" to a pcbuf */
int pcbuf_fromfd(struct pcbuf *pc, int fd)
{
	for (;;) {
		int res;
		char *wptr = pcbuf_space(pc, 1);
		if (wptr == NULL)
			return consume_fd(fd);
	    again:
		res = read(fd, wptr, pc->active.tail->bufend - wptr);
		if (res <= 0) {
			if (res == 0)
				return -ECHILD;	/* errno abuse */
			res = neg_errno();
			if (res == -EINTR)
				goto again;
			return res;
		}
		pc->active.tail->wptr += res;
		pc->cur_size += res;
		pc->total_written += res;
	}
	return 0;
}

static void pcbuf_free_head(struct pcbuf *pc)
{
	struct pcbuf_elem *pe = pc->active.head;

	assert(pe->rptr == pe->wptr);
	pc->active.head = pe->next;
	if (pc->active.head == NULL)
		pc->active.tail = NULL;
	if ((pc->flags & PCB_FLAGS_KEEP) != 0) {
		pe->next = NULL;
		if (pc->kept.tail != NULL) {
			assert(pc->kept.head != NULL);
			pc->kept.tail->next = pe;
		} else {
			assert(pc->kept.head == NULL);
			pc->kept.head = pe;
		}
		pc->kept.tail = pe;
	} else
		free(pe);
}

/* read()-like interface for pulling data from a pcbuf */
ssize_t pcbuf_read(struct pcbuf *pc, void *result, size_t len)
{
	size_t old_len = len;

	if (unlikely(pc->error != 0)) {
		errno = pc->error;
		return -1;
	}
	while (len > 0) {
		struct pcbuf_elem *pe = pc->active.head;
		size_t to_copy;
		if (pe == NULL)
			break;		/* Nothing more to read! */
		to_copy = len;
		if (&pe->rptr[to_copy] > pe->wptr)
			to_copy = pe->wptr - pe->rptr;
		memcpy(result, pe->rptr, to_copy);
		result += to_copy;
		assert(to_copy <= len);
		len -= to_copy;
		pe->rptr += to_copy;
		assert(pc->cur_size >= to_copy);
		pc->cur_size -= to_copy;
		if (pe->rptr >= pe->wptr)
			pcbuf_free_head(pc);
	}
	assert(len <= old_len);
	return old_len - len;
}

/*
 * Reads from a pcbuf into memory at "buf" until a delimiter character is
 * reached.  Returns zero if the delimiter was found, >0 if we hit EOF
 * first, <0 on error.
 *
 * On entry *buflenp should be the number of bytes available at "buf".  On
 * exit it will contain the number of bytes that WOULD have been written.
 * Therefore if it has a larger value at exit than at entry the result was
 * truncated
 */
int pcbuf_read_todelim(struct pcbuf *pc, char *buf,
		       size_t *buflenp, char delim)
{
	struct pcbuf_elem *pe;
	size_t buflen = *buflenp;

	*buflenp = 0;
	if (unlikely(pc->error != 0)) {
		errno = pc->error;
		return -1;
	}
    next_elem:
	pe = pc->active.head;
	if (pe == NULL)
		return 1;
	for (;;) {
		char c;
		if (pe->rptr >= pe->wptr) {
			pcbuf_free_head(pc);
			goto next_elem;
		}
		assert(pc->cur_size > 0);
		pc->cur_size--;
		c = *pe->rptr++;
		if (c == delim)
			break;
		if (++(*buflenp) <= buflen)
			*buf++ = c;
	}
	return 0;
}

/* copy all data in pcbuf to a file descriptor */
int pcbuf_tofd(struct pcbuf *pc, int fd)
{
	for (;;) {
		int res;
		struct pcbuf_elem *pe = pc->active.head;
		if (pe == NULL)
			break;
	    again:
		res = write(fd, pe->rptr, pe->wptr - pe->rptr);
		if (res <= 0) {
			res = (res == 0) ? -ENOSPC : neg_errno();
			assert(res < 0);
			if (res == -EINTR)
				goto again;
			return res;
		}
		assert(res <= pe->wptr - pe->rptr);
		assert((unsigned int) res <= pc->cur_size);
		pc->cur_size -= res;
		pe->rptr += res;
		assert(pe->rptr <= pe->wptr);
		if (likely(pe->rptr == pe->wptr))
			pcbuf_free_head(pc);
	}
	return 0;
}

static inline void pcelem_rewind(struct pcbuf_elem *e)
{
	e->rptr = &e->buf[0];
}

static inline void pcbuf_rewind_chain(struct pcbuf_elem *e)
{
	assert(e != NULL);
	do {
		pcelem_rewind(e);
		e = e->next;
	} while (e != NULL);
}

void pcbuf_rewind(struct pcbuf *pc)
{
	assert((pc->flags & PCB_FLAGS_KEEP) != 0);
	if (pc->active.head != NULL) {
		assert(pc->active.tail != NULL);
		pcelem_rewind(pc->active.head);
	}
	if (pc->kept.head != NULL) {
		assert(pc->kept.tail != NULL);
		assert(pc->kept.tail->next == NULL);
		pcbuf_rewind_chain(pc->kept.head);
		pc->kept.tail->next = pc->active.head;
		pc->active.head = pc->kept.head;
		pc->kept.head = pc->kept.tail = NULL;
	}
	pc->cur_size = pc->total_written;
}

void pcbuf_init(struct pcbuf *pc)
{
	memset(pc, 0, sizeof(*pc));
}

static void pcbuf_destroy_chain(struct pcbuf_elem *e)
{
	while (e != NULL) {
		struct pcbuf_elem *next = e->next;
		free(e);
		e = next;
	}
}

void pcbuf_destroy(struct pcbuf *pc)
{
	pcbuf_destroy_chain(pc->active.head);
	pcbuf_destroy_chain(pc->kept.head);
	pcbuf_init(pc);
}
