/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  This file implements a "gitworker" thread responsible for all work done
 *  via the git library -- this allows other filesystem operations to complete
 *  asynchronously.  Ideally we'd start one thread for each CPU (to allow
 *  expensive operations like uncompression to scale nicely on SMP), however
 *  unfortunately libgit.a is *NOT* MT-safe (for example it keeps internal
 *  state like "packed_git")
 *
 *  As a side-effect of this, *ALL* libgit work (even fast operations) must
 *  be done via this worker thread to avoid race conditions
 */

#include "gitfs.h"
#include <pthread.h>
#include "cache.h"

static void gitwork_find_packname(struct gitwork_cmd *cmd)
{
	struct packed_git *pg = find_sha1_pack(cmd->gptr->sha1, packed_git);

	if (pg == NULL)
		cmd->error = -ENOENT;
	else {
		/*
		 * Since git never removes packs from the "packed_git" list
		 * it should be safe to return the "->pack_name" pointer --
		 * it won't ever be free()'ed
		 */
		cmd->answer.pack_filename = pg->pack_name;
		cmd->error = 0;
	}
}

/*
 * We follow the same rules as git's "cat-file" command - we'll automatically
 * consider a "commit" the same as a "tree"
 */
static int raw_resolve_reference(const unsigned char *obuf,
				 unsigned char **nbufp, unsigned long *sizep,
				 const char *ref_str, size_t reflen,
				 char *type)
{
	struct gitobj_ptr nptr;

	if (*sizep < reflen + HEX_PTR_LEN ||
	    0 != memcmp(obuf, ref_str, reflen) ||
	    get_sha1_hex((const char *) &obuf[reflen], &nptr.sha1[0]) != 0)
		return -ENOLINK;
	*nbufp = read_sha1_file(&nptr.sha1[0], type, sizep);
	if (*nbufp == NULL)
		return -ENOENT;
	return 0;
}
#define resolve_reference(obuf, nbufp, sizep, rtype, type)		\
		raw_resolve_reference(obuf, nbufp, sizep,		\
			rtype " ", strlen_const(rtype " "), type)

/*
 * Read the git object "ptr" into memory; put results (including type/size)
 * into "ores"
 */
static int git_read(const struct gitobj_ptr *ptr,
		    struct gitwork_open_result *ores)
{
	char type[20];
	unsigned char *buf;
	int res;

	buf = read_sha1_file(&ptr->sha1[0], type, &ores->size);
	if (buf == NULL)
		return -ENOENT;
	ores->buf = buf;
	if (0 == strcmp(type, "tag")) {
		res = resolve_reference(ores->buf, &buf,
					&ores->size, "object", type);
		free(ores->buf);
		if (res != 0) {
			assert(res < 0);
			return res;
		}
		ores->buf = buf;
	}
	if (0 == strcmp(type, "commit")) {
		res = resolve_reference(ores->buf, &buf,
					&ores->size, "tree", type);
		free(ores->buf);
		if (res != 0) {
			assert(res < 0);
			return res;
		}
		ores->buf = buf;
	}
	if (0 == strcmp(type, "tree")) {
		ores->type = GFN_DIR;
	} else if (0 == strcmp(type, "blob")) {
		ores->type = GFN_FILE;
		/* Note: this could actually turn out to be a symlink */
	} else {
		free(buf);		/* Unknown type */
		return -EIO;
	}
	return 0;
}

static void gitwork_object_info(struct gitwork_cmd *cmd)
{
	/*
	 * If we're expecting it to be a file or symlink, just start with
	 * calling sha1_object_info() on it since we might not need the
	 * actual file contents yet
	 */
	if (cmd->answer.open.type == GFN_FILE ||
	    cmd->answer.open.type == GFN_SYMLINK) {
		char type[20];
		if (sha1_object_info(&cmd->gptr->sha1[0], type,
				     &cmd->answer.open.size) == 0 &&
		    0 == strcmp(type, "blob")) {
			cmd->error = 0;
			cmd->answer.open.type = GFN_FILE;
			cmd->answer.open.buf = NULL;
			return;
		}
	}
	/* Otherwise, just read the file as normal */
	cmd->error = git_read(cmd->gptr, &cmd->answer.open);
}

static void gitwork_add_to_ocache(struct gitwork_cmd *cmd)
{
	char fname[PATH_MAX], tfile[PATH_MAX];
	int fd, ret;

	cmd->error = gitptr_to_fname(fname, sizeof(fname),
				     ocache_dir, cmd->gptr);
	if (cmd->error != 0) {
		assert(cmd->error < 0);
		return;
	}
	fd = open(fname, O_RDONLY);
	if (fd >= 0) {
		/* Hmmm... looks like someone beat us to it */
		cmd->error = -EAGAIN;
		(void) close(fd);
		return;
	}
	ret = snprintf(tfile, sizeof(tfile), "%s%s", fname, instance_str);
	if (ret <= 0 || ret >= (int) sizeof(tfile)) {
		cmd->error = -ENAMETOOLONG;
		return;
	}
	fd = open(tfile, O_WRONLY | O_CREAT | O_EXCL, 0444);
	if (fd < 0) {
		cmd->error = neg_errno();
		switch (cmd->error) {
		case -EEXIST:
			/* Weird; I guess its left over from a previous run */
			(void) unlink(tfile);
			break;
		case -ENOENT:
			/* A parent directory is probaly missing */
			cmd->error = recursive_mkdir(tfile, 1);
			if (cmd->error != 0) {
				assert(cmd->error < 0);
				return;
			}
			break;
		default:
			return;
		}
		fd = open(tfile, O_WRONLY | O_CREAT | O_EXCL, 0444);
		if (fd < 0) {
			cmd->error = neg_errno();
			return;
		}
	}
	cmd->error = git_read(cmd->gptr, &cmd->answer.open);
	if (cmd->error != 0) {
		cmd->answer.open.buf = NULL;
		goto close_and_fail;
	}
	if (cmd->answer.open.type != GFN_FILE) {
		assert(cmd->answer.open.type == GFN_DIR);
		cmd->error = -EISDIR;
		free(cmd->answer.open.buf);
		cmd->answer.open.buf = NULL;
		goto close_and_fail;
	}
	cmd->error = write_safe(fd, cmd->answer.open.buf,
				cmd->answer.open.size);
	free(cmd->answer.open.buf);
	cmd->answer.open.buf = NULL;	/* just for safety */
	if (cmd->error != 0) {
	    close_and_fail:
		(void) close(fd);
		goto unlink_and_fail;
	}
	if (close(fd) != 0 || rename(tfile, fname) != 0) {
		cmd->error = neg_errno();
	    unlink_and_fail:
		(void) unlink(tfile);
		assert(cmd->error < 0);
	}
}

static void gitwork_docmd(struct gitwork_cmd *cmd)
{
	switch (cmd->opcode) {
	case GITWORKER_OBJECT_INFO:
		gitwork_object_info(cmd);
		break;
	case GITWORKER_ADD_TO_OCACHE:
		gitwork_add_to_ocache(cmd);
		break;
	case GITWORKER_FIND_PACKNAME:
		gitwork_find_packname(cmd);
		break;
	default:
		assert(0);
	}
}

struct gitwork_queue {
	struct gitwork_cmd *head, **endp;
};

static inline void gitwork_queue_add(struct gitwork_queue *q,
				     struct gitwork_cmd *cmd)
{
	cmd->queue_next = NULL;
	*(q->endp) = cmd;
	q->endp = &cmd->queue_next;
}

static inline int gitwork_queue_empty(const struct gitwork_queue *q)
{
	return q->head == NULL;
}

static inline struct gitwork_cmd *gitwork_queue_get(struct gitwork_queue *q)
{
	struct gitwork_cmd *cmd;

	assert(!gitwork_queue_empty(q));
	cmd = q->head;
	q->head = cmd->queue_next;
	if (q->head == NULL) {
		assert(q->endp == &cmd->queue_next);
		q->endp = &q->head;
	}
	return cmd;
}

static struct gitwork_queue gitwork_out = {
	.head = NULL,
	.endp = &gitwork_out.head,
};

static pthread_mutex_t gitwork_queue_lock = PTHREAD_MUTEX_INITIALIZER;

void gitwork_service_replies(void)
{
	struct gitwork_cmd *head, *gw;

	pthread_mutex_lock(&gitwork_queue_lock);
	head = gitwork_out.head;
	if (head == NULL) {
		pthread_mutex_unlock(&gitwork_queue_lock);
		return;
	}
	gitwork_out.head = NULL;
	gitwork_out.endp = &gitwork_out.head;
	pthread_mutex_unlock(&gitwork_queue_lock);

	do {
		gw = head;
		head = head->queue_next;
		gitwork_finish(gw);
	} while (head != NULL);
}

static struct gitwork_queue gitwork_in = {
	.head = NULL,
	.endp = &gitwork_in.head,
};

static pthread_cond_t gitwork_in_notempty = PTHREAD_COND_INITIALIZER;

static void *gitworker_run(UNUSED_ARG(void *dummy))
{
	pthread_mutex_lock(&gitwork_queue_lock);
	for (;;) {
		struct gitwork_cmd *cmd;
		int need_wakeup;
		while (gitwork_queue_empty(&gitwork_in))
			pthread_cond_wait(&gitwork_in_notempty,
					  &gitwork_queue_lock);
		cmd = gitwork_queue_get(&gitwork_in);
		pthread_mutex_unlock(&gitwork_queue_lock);
		if (cmd->opcode == GITWORKER_QUIT)
			break;
		gitwork_docmd(cmd);
		pthread_mutex_lock(&gitwork_queue_lock);
		need_wakeup = gitwork_queue_empty(&gitwork_out);
		gitwork_queue_add(&gitwork_out, cmd);
		if (need_wakeup != 0) {
			pthread_mutex_unlock(&gitwork_queue_lock);
			selfpipe_ping();
			pthread_mutex_lock(&gitwork_queue_lock);
		}
	}
	return NULL;
}

void gitwork_add(struct gitwork_cmd *cmd)
{
	pthread_mutex_lock(&gitwork_queue_lock);
	gitwork_queue_add(&gitwork_in, cmd);
	if (gitwork_in.head == cmd)	/* only item in the queue? */
		pthread_cond_signal(&gitwork_in_notempty);
	pthread_mutex_unlock(&gitwork_queue_lock);
}

static pthread_t gitworker_thread;

int gitwork_init(void)
{
	int rv = pthread_create(&gitworker_thread, NULL, gitworker_run, NULL);

	if (rv != 0) {
		errno = rv;
		perror("pthread_create");
		return -1;
	}
	return 0;
}

void gitwork_fini(void)
{
	struct gitwork_cmd quit_cmd;
	int ret;

	/* just cheat and put the quit command at the head of the line */
	quit_cmd.opcode = GITWORKER_QUIT;
	quit_cmd.queue_next = NULL;
	pthread_mutex_lock(&gitwork_queue_lock);
	gitwork_in.head = &quit_cmd;
	gitwork_in.endp = &quit_cmd.queue_next;
	pthread_cond_signal(&gitwork_in_notempty);
	pthread_mutex_unlock(&gitwork_queue_lock);
	ret = pthread_join(gitworker_thread, NULL);
	if (ret != 0) {
		errno = ret;
		perror("pthread_join");
	}
}
