/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */

#include "gitfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

void gn_save_node(struct gitfs_saved_node *sn, struct gitfs_node *gn)
{
	sn->gn = gn;
	if (gn != NULL) {
		gn_assert_held(gn);
		gn_hold(gn);
		sn->prevp = &gn->saved_node_root;
		sn->next = gn->saved_node_root;
		if (sn->next != NULL) {
			assert(sn->next->gn == gn);
			assert(sn->next->prevp == &gn->saved_node_root);
			sn->next->prevp = &sn->next;
		}
		gn->saved_node_root = sn;
	}
}

void gn_unsave_node(struct gitfs_saved_node *sn)
{
	if (sn->gn != NULL) {
		*(sn->prevp) = sn->next;
		if (sn->next != NULL) {
			assert(sn->next->gn == sn->gn);
			assert(sn->next->prevp == &sn->next);
			sn->next->prevp = sn->prevp;
		}
		gn_release(sn->gn);
	}
}

static struct rb_tree active_inums = EMPTY_RBTREE;

static inline void inum_hash_remove(struct gitfs_node *gn)
{
	rbtree_delete(&gn->inum_tree);
}

static inline struct gitfs_node *rbtree_to_inum_gn(struct rb_node *rb)
{
	char *ptr = (char *) rb;

	ptr -= (size_t) &((struct gitfs_node *) 0)->inum_tree;
	return (struct gitfs_node *) ptr;
}

static inline uint32_t inum32(const struct gitfs_node *gn)
{
	return gn->inum & 0xFFFFFFFF;
}

static struct rb_node **inum_walk(uint32_t i32)
{
	struct rb_node **rp;

	rbtree_walk(&active_inums, rp) {
		uint32_t tinum = inum32(rbtree_to_inum_gn(*rp));
		if (tinum == i32)
			break;
		rp = &(*rp)->child[i32 > tinum];
	}
	return rp;
}

/*
 * NOTE: the root gitfs_node isn't in the active_inums tree so it won't
 * be found by this function
 */
struct gitfs_node *gn_lookup_inum(gitfs_inum_t inum)
{
	struct rb_node *rb;
	struct gitfs_node *gn;

	rb = *inum_walk(inum & 0xFFFFFFFF);
	if (unlikely(RB_IS_NIL(rb)))
		return NULL;
	gn = rbtree_to_inum_gn(rb);
	if (unlikely(gn->type == GFN_INCOMPLETE || gn->inum != inum))
		return NULL;
	gn_hold(gn);
	return gn;
}

#define RESERVED_INODES		(256)

static void gn_assign_inum(struct gitfs_node *gn)
{
	static gitfs_inum_t next_inum = RESERVED_INODES;
	uint32_t i32;
	struct rb_node **rp;

    calc_32:
	i32 = next_inum & 0xFFFFFFFF;
	if (unlikely(i32 < RESERVED_INODES)) {
	    wraparound:
		assert(i32 == 0);
		next_inum += RESERVED_INODES;
		goto calc_32;
	}
    find_place:
	if (unlikely(next_inum == GITFS_NO_INUM)) {
		assert(i32 == 0xFFFFFFFF);
		next_inum++;
		goto calc_32;
	}
	rp = inum_walk(i32);
	if (unlikely(!RB_IS_NIL(*rp))) {
		struct rb_node *rb = *rp;
		/* Collision in the low 32 bits! */
		assert(inum32(rbtree_to_inum_gn(*rp)) == i32);
		do {
			i32++;
			next_inum++;
			if (unlikely(i32 == 0))
				goto wraparound;
			rb = rbtree_next(rb);
		} while (rb != NULL && inum32(rbtree_to_inum_gn(rb)) == i32);
		goto find_place;
	}
	gn->inum = next_inum++;
	rbtree_insert(rp, &gn->inum_tree);
}

static inline struct gitfs_node *rbtree_to_named_gn(struct rb_node *rb)
{
	char *ptr = (char *) rb;

	ptr -= (size_t) &((struct gitfs_node *) 0)->name_tree;
	return (struct gitfs_node *) ptr;
}

static struct rb_node **childlist_walk(struct gitfs_node *parent,
				       const char *name)
{
	struct rb_node **rp;

	assert(parent->type == GFN_DIR);
	rbtree_walk(&parent->t.d.children, rp) {
		int cmp = strcmp(name, rbtree_to_named_gn(*rp)->name);
		if (cmp == 0)
			break;
		rp = &(*rp)->child[cmp < 0];
	}
	return rp;
}

static inline struct gitfs_node *childlist_lookup(struct gitfs_node *gn,
						  const char *name)
{
	struct rb_node **rp = childlist_walk(gn, name);

	if (RB_IS_NIL(*rp))
		return NULL;
	gn = rbtree_to_named_gn(*rp);
	gn_hold(gn);
	return gn;
}

static inline void childlist_add(struct gitfs_node *parent,
				 struct gitfs_node *child)
{
	struct rb_node **rp;

	child->parent = parent;
	rp = childlist_walk(parent, child->name);
	assert(RB_IS_NIL(*rp));
	rbtree_insert(rp, &child->name_tree);
}

static inline void childlist_del(struct gitfs_node *child)
{
	rbtree_delete(&child->name_tree);
}

struct gitfs_node *gn_alloc(struct gitfs_node *parent, const char *name)
{
	size_t namelenz = strlen(name) + 1;
	struct gitfs_node *gn = calloc(1, sizeof(*gn) + namelenz);

	if (gn != NULL) {
		gn->type = GFN_INCOMPLETE;
		gn->hold_count = 1;
		gn_assign_inum(gn);
		memcpy(&gn[1], name, namelenz);
		childlist_add(parent, gn);
		gn->tree = parent->tree;
		openfile_init(&gn->backing.file.of);
		gn_hold(parent);
	}
	return gn;
}

void gn_set_type(struct gitfs_node *gn, enum gitfs_node_type ntype)
{
	assert(gn->type == GFN_INCOMPLETE);
	assert(ntype != GFN_INCOMPLETE);
	gn->type = ntype;
	if (ntype == GFN_DIR)
		gn->t.d.children = empty_rbtree;
}

static void gtree_free(struct gitfs_tree *gtree)
{
	free(gtree->symbolic_name);
	free(gtree->backing_path);
	free(gtree);
}

static void fsback_free(struct gitfs_fs_backing *fsb)
{
	free(fsb->path);
	openfile_close(&fsb->of);
}

void gn_release_nref(struct gitfs_node *gn, unsigned int refcnt)
{
	for (;;) {
		struct gitfs_node *ogn;
		assert(gn->hold_count >= refcnt);
		gn->hold_count -= refcnt;
		if (gn->hold_count != 0)
			break;		/* We're still held by someone */
		assert(gn->parent != gn);
		assert(gn->saved_node_root == NULL);
		assert(gn->type != GFN_DIR ||
		       rbtree_first(&gn->t.d.children) == NULL);
		if (gn->op.c != NULL && gn->op.c->destroy != NULL)
			gn->op.c->destroy(gn);
		if (gn->backing.gobj != NULL)
			gobj_release(gn->backing.gobj);
		fsback_free(&gn->backing.file);
		if (gn_is_treeroot(gn))
			gtree_free(gn->tree);
		inum_hash_remove(gn);
		ogn = gn;
		gn = gn->parent;
		assert(gn != NULL);
		/*
		 * We should never hit the root of the tree here, because
		 * "gitfs_node_root" should always be held
		 */
		assert(gn != ogn);
		childlist_del(ogn);
		free(ogn);
		/*
		 * Now we recurse up the tree releaseing the hold we had on
		 * our parent
		 */
		refcnt = 1;
	}
}

struct gn_defered_incomplete_lookup {
	struct api_request *req;
	struct gn_defered_incomplete_lookup *next;
	char name[0];
};

/*
 * When we do a lookup and find that we already have a child but it's in
 * the GFN_INCOMPLETE state we must defer this request and retry it after
 * we're done with
 */
static int defer_incomplete_lookup(struct gitfs_node *parent,
				   const char *elem)
{
	size_t namelenz = strlen(elem) + 1;
	struct gn_defered_incomplete_lookup *dil;

	dil = malloc(sizeof(*dil) + namelenz);
	if (dil == NULL)
		return -ENOMEM;
	dil->req = api_save_request(NULL);
	if (dil->req == NULL) {
		free(dil);
		return -ENOMEM;
	}
	memcpy(&dil[1], elem, namelenz);
	dil->next = parent->t.d.first_defered;
	parent->t.d.first_defered = dil;
	return -EINPROGRESS;
}

int gn_lookup_in(struct gitfs_node *parent, const char *elem,
		 struct gitfs_node **resultp)
{
	gn_assert_held(parent);
	if (parent->type != GFN_DIR)
		return -ENOTDIR;
	*resultp = childlist_lookup(parent, elem);
	if (*resultp != NULL) {
		if (unlikely((*resultp)->type == GFN_INCOMPLETE)) {
			gn_release(*resultp);
			return defer_incomplete_lookup(parent, elem);
		}
		return 0;
	}
	if (unlikely(0 == strcmp(elem, CSIPC_DISCOVERY_FILE)))
		return csipc_discovery_node(parent, resultp);
	return parent->op.d->lookup(parent, resultp, elem);
}

/*
 * For ->lookup()'s methods that defered themselves, we need to also wake
 * up any gn_lookup_in() requests that stalled due to finding an incomplete
 * inode
 */
void gn_finish_defered_lookups(struct gitfs_node *parent,
			       struct api_request *req, int error)
{
	struct gn_defered_incomplete_lookup *next;

	assert(error <= 0);
	gn_hold(parent);
	next = parent->t.d.first_defered;
	parent->t.d.first_defered = NULL;
	api_complete_saved_request(req, error, NULL, 0);
	while (next != NULL) {
		struct gitfs_node *gn;
		struct gn_defered_incomplete_lookup *dil = next;
		next = next->next;
		gn = childlist_lookup(parent, dil->name);
		if (gn == NULL) {
			/*
			 * OK, at this point we know that the last time
			 * we looked this node was GFN_INCOMPLETE state
			 * and now its simply missing.  This implies that
			 * we just returned an error for this same file
			 * at the top of this function
			 */
			assert(error < 0);
			api_complete_saved_request(dil->req, error, NULL, 0);
			free(dil);
		} else if (gn->type == GFN_INCOMPLETE) {
			/* Still incomplete, requeue */
			gn_release(gn);
			dil->next = parent->t.d.first_defered;
			parent->t.d.first_defered = dil;
		} else {
			/* No longer incomplete; just return it now */
			api_saved_request_set_gnode(dil->req, gn);
			api_complete_saved_request(dil->req, 0, NULL, 0);
			free(dil);
		}
	}
	gn_release(parent);
}

/*
 * For ->readdir() implementors -- return the inode # of a child or -1
 * if one hasn't been assigned yet
 */
gitfs_inum_t gn_child_inum(struct gitfs_node *gn, const char *elem)
{
	gitfs_inum_t result = GITFS_NO_INUM;

	gn_assert_held(gn);
	gn = childlist_lookup(gn, elem);
	if (gn != NULL) {
		result = gn->inum;
		gn_release(gn);
	}
	return result;
}

int gn_change_name(struct gitfs_node **gnp, const char *newname)
{
	struct gitfs_node *oldgn, *newgn;
	size_t namelenz;

	if ((*gnp)->open_count > 0) {
		/*
		 * We don't allow renames of items which are currently
		 * open.  There are a bunch of reasons for this, but the
		 * big one is that we pass the "gn" value directly to the
		 * kernel as the file handle, so if it moves we'd be in
		 * big trouble
		 */
		return -EBUSY;
	}
	oldgn = *gnp;
	namelenz = strlen(newname) + 1;
	newgn = realloc(oldgn, sizeof(*oldgn) + namelenz);
	if (newgn == NULL)
		return -ENOMEM;
	memcpy(newgn->name, newname, namelenz);
	if (oldgn != newgn) {
		/*
		 * If we moved the gnode in memory we need to fix all of
		 * the pointers in "gitfs_saved_node" structures
		 */
		struct gitfs_saved_node *sn = newgn->saved_node_root;
		while (sn != NULL) {
			assert(sn->gn == oldgn);
			sn->gn = newgn;
			sn = sn->next;
		}
	}
	*gnp = newgn;
	return 0;
}

/* IMPLEMENTATION OF "gitfs pwd" COMMAND: */

static int cmd_pwd(UNUSED_ARG(int argn), char * const *argv)
{
	static const char newline = '\n';
	struct gitfs_server_connection *gsc;
	struct bytebuf bb;
	char elem[PATH_MAX + 1], *r;

	if (argv[1] != NULL) {
		print_usage();
		return 4;
	}
	bytebuf_init(&bb, 128, 0);
	bytebuf_prepend(&bb, &newline, 1);
	gsc = gs_connection_open();
	if (gsc == NULL)
		return 8;
	elem[0] = '/';
	do {
		if (gs_getname(gsc, 0, elem + 1, sizeof(elem) - 1) != 0 ||
		    elem[1] == '\0')
			break;
		bytebuf_prepend(&bb, elem, strlen(elem));
	} while (gs_cdup(gsc, 0) == 0);
	gs_connection_close(gsc);
	r = bytebuf_asptr(&bb);
	if (r == NULL) {
		perror("bytebuf_asptr");
		return 8;
	} else {
		size_t len = bytebuf_len(&bb);
		while (len > 1 && *r == '/')
			r++, len--;
		fwrite(r, sizeof(*r), len, stdout);
	}
	bytebuf_destroy(&bb);
	return 0;
}
const struct gitfs_subcommand scmd_pwd = {
	.cmd = "pwd",
	.handler = &cmd_pwd,
	.usage = "& [-d] pwd",
};

/* IMPLEMENTATION OF "gitfs _dump_ino" DEBUGGING COMMAND: */

struct ino_dump_result {
	/* inum is GITFS_NO_INUM for the end of a list */
	gitfs_inum_t inum, parent_inum;
	enum gitfs_node_type type;
	unsigned long hold_count, open_count;
	mode_t mode;
	unsigned int backing;
	struct gitobj_ptr gptr;
	/* Note: name follows this structure */
};

void ino_dump_single_answer(struct pcbuf *out, const struct gitfs_node *gn)
{
	struct ino_dump_result dr;

	memset(&dr, 0, sizeof(dr));
	if (gn == NULL) {
		dr.inum = GITFS_NO_INUM;
		return;
	}
	dr.inum = gn->inum;
	dr.parent_inum = gn->parent->inum;
	dr.type = gn->type;
	dr.hold_count = gn->hold_count;
	dr.open_count = gn->open_count;
	dr.mode = gn->stat.perm;
	if (gn->backing.gobj != NULL) {
		dr.backing = 1;
		memcpy(&dr.gptr, &gn->backing.gobj->hash.sha1[0],
		       sizeof(gn->backing.gobj->hash.sha1));
	}
	pcbuf_write_obj(out, dr);
	pcbuf_write(out, gn->name, strlen(gn->name) + 1);
}

void ino_dump_answer(struct pcbuf *out)
{
	static const struct __attribute__ ((packed)) {
		struct ino_dump_result dr;
		char name[1];
	} ino_dump_eof = {
		.dr = {
			.inum = GITFS_NO_INUM,
		},
		.name = { '\0' },
	};
	struct rb_node *rb;

	for (rb = rbtree_first(&active_inums);
	     rb != NULL;
	     rb = rbtree_next(rb))
		ino_dump_single_answer(out, rbtree_to_inum_gn(rb));
	pcbuf_write_obj(out, ino_dump_eof);
}

struct dcmd_ino_dump_state {
	int first;
};

static enum service_result dcmd_ino_dump_worker(const void *data,
						const char *name, void *state)
{
	const struct ino_dump_result *dr = data;
	struct dcmd_ino_dump_state *dst = state;
	const char *stype = "???";

	if (dr->inum == GITFS_NO_INUM)
		return SERVICED_EOF;
	if (dst->first == 0)
		putchar('\n');
	else
		dst->first = 0;
	switch (dr->type) {
	case GFN_FILE:
		stype = "file";
		break;
	case GFN_DIR:
		stype = "directory";
		break;
	case GFN_SYMLINK:
		stype = "symlink";
		break;
	case GFN_INCOMPLETE:
		stype = "incomplete lookup";
		break;
	}
	printf("inode %llu (%s \"%s\" %04o) holds: %lu",
	       (unsigned long long) dr->inum, stype, name, dr->mode & 0777,
	       dr->hold_count);
	if (dr->open_count != 0)
		printf(", opens: %lu", dr->open_count);
	printf("\n\tparent: %llu\n", (unsigned long long) dr->parent_inum);
	if (dr->backing != 0) {
		struct gitobj_ptr_ascii pa;
		gitptr_ascii(&pa, &dr->gptr);
		printf("\tbacking git object: %s\n", pa.ascii);
	}
	return SERVICED_OK;
}

static int dcmd_dump_ino(UNUSED_ARG(int argn), char * const *argv)
{
	struct gitfs_server_connection *gsc;
	struct ino_dump_result resbuf;
	struct dcmd_ino_dump_state dstate;
	gitfs_inum_t inum;
	int have_inum = 0;

	if (argv[1] != NULL) {
		have_inum = 1;
		if (argv[2] != NULL || convert_uint64(argv[1], &inum) != 0) {
			print_usage();
			return 4;
		}
	}
	dstate.first = 1;

	gsc = gs_connection_open();
	if (gsc == NULL)
		return 8;
	if (have_inum != 0) {
		csipc_fh_t fh = gs_open_inode(gsc, inum);
		if (fh < 0) {
			errno = -fh;
			perror("open gitfs inode");
			gs_connection_close(gsc);
			return 1;
		}
		if (gs_dump_ino_single(gsc, fh, &resbuf, sizeof(resbuf),
				       dcmd_ino_dump_worker, &dstate) != 0) {
			gs_connection_close(gsc);
			return 8;
		}
	} else if (gs_dump_ino(gsc, &resbuf, sizeof(resbuf),
			       dcmd_ino_dump_worker, &dstate) != 0) {
		gs_connection_close(gsc);
		return 8;
	}
	gs_connection_close(gsc);

	return 0;
}
const struct gitfs_subcommand debug_cmd_dump_ino = {
	.cmd = "_dump_ino",
	.handler = &dcmd_dump_ino,
	.usage = "& [-d] _dump_ino [inum]",
};
