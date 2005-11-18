/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 */
#ifndef GOT_GITFS_H
#define GOT_GITFS_H

#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>	/* for "struct timespec" */

#ifdef __GNUC__
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define UNUSED_ARG(x)	x __attribute__ ((unused))
#else /* !__GNUC__ */
#define likely(x)	(x)
#define unlikely(x)	(x)
#define UNUSED_ARG(x)	x
#endif /* __GNUC__ */

/* length of a constant string */
#define strlen_const(cs)	(sizeof("" cs) - sizeof(""))

/* Forwawrd declarations */
struct stat;
struct gitfs_node;
struct api_readdir_state;	/* opaque outside api-*.c */
struct api_request;		/* opaque outside api-*.c */

enum gitfs_node_type {
	GFN_INCOMPLETE,
	GFN_FILE,
	GFN_DIR,
	GFN_SYMLINK,
};

struct gitobj_ptr {
	unsigned char sha1[160 / 8]
			__attribute__ ((aligned (sizeof(unsigned long))));
};
extern struct gitobj_ptr dummy_ptr; /* doesn't exist; only for sizeof() */
#define HEX_PTR_LEN	(strlen_const("AA") * sizeof(dummy_ptr.sha1))

struct gitobj_ptr_ascii {
	char ascii[HEX_PTR_LEN + 1];
};

struct gitfs_subcommand {
	const char *cmd;
	const char * const *aliases;
	int (*handler)(int argn, char * const *argv);
	const char *usage;
};

enum service_result {
	SERVICED_OK,
	SERVICED_EOF,
	SERVICED_ERROR,
};

typedef uint64_t gitfs_inum_t;
#define GITFS_NO_INUM	((gitfs_inum_t) -1)

/****************
 * For rbtree.c *
 ****************/

/*
 * In order to facilitate some ugly (but very efficient) pointer tricks we
 * need to make sure our "node->child[]" array is aligned
 */
#define RBNODE_ALIGN	(2 * sizeof(struct rb_node *))

struct rb_node;			/* Forward declaration */

/* Private state -- should only be touched inside rbtree.c */
struct rb_node_priv {
	/*
	 * ->priv.plink is a pointer to where we're linked into our parent.
	 * In other words, it'll either be &parent->child[0] or
	 * &parent->child[1] depending if we're our parent's left or right
	 * child
	 */
	struct rb_node **plink;
	unsigned int is_red;
};

/* Per-node rbtree state */
struct rb_node {
	/*
	 * It is very important that child[] be kept first since we do evil
	 * pointer math on things pointing into the child array
	 */
	struct rb_node *child[2]	/* left, right child */
			__attribute__ ((aligned (RBNODE_ALIGN)));
	struct rb_node_priv priv;
};

/* Sentinel node -- we use this instead of NULL to indicate a leaf */
extern struct rb_node rb_NilNode;
#define RBNIL	(&rb_NilNode)
/*
 * This is equivelant to "node == RBNIL" except it generates significantly
 * shorter code than comparing a pointer against a full-word constant.
 * Since "node" is probably cache-hot this comparison is very cheap
 */
#define RB_IS_NIL(node)	((node) == (node)->child[0])

/* Head of rbtree */
struct rb_tree {
	struct rb_node aroot; /* node above root (.aroot.child[0] is root) */
};
#define EMPTY_RBTREE {							\
	.aroot = {							\
		.child = { RBNIL, RBNIL },				\
		.priv = {						\
			.plink = NULL,					\
			.is_red = 0,					\
		},							\
	},								\
}
extern const struct rb_tree empty_rbtree;

extern void rbtree_insert(struct rb_node **link, struct rb_node *node);
extern void rbtree_delete(struct rb_node *node);

/*
 * Macro to help implement tree lookups.  Basically you do:
 *
 *	struct rb_tree **linkp;
 *	rbtree_walk(&my_tree, linkp) {
 *		if (TREE_VAL(*linkp) == what_im_looking_for) {
 *			yep_i_found_it();
 *			return;
 *		}
 *		if (what_im_looking_for < TREE_VAL(*linkp))
 *			linkp = &(*linkp)->child[0];
 *		else
 *			linkp = &(*linkp)->child[1];
 *	}
 *	no_i_didnt_find_it();
 *
 * If we end up not finding a match, "linkp" will be left with a value
 * suitable for passing to rbtree_insert()
 */
#define rbtree_walk(tree, lp)					\
		for ((lp) = &(tree)->aroot.child[0];		\
		     !RB_IS_NIL(*(lp));)			\

extern struct rb_node *rbtree_first(struct rb_tree *tree);
extern struct rb_node *rbtree_next(struct rb_node *node);

/*****************
 * For bytebuf.c *
 *****************/

struct bytebuf {
	struct {
		char *start;
		char *end;
	} stored, alloc;
	const char *spoint;
	int error;
};

#define bytebuf_len(bb)		((bb)->stored.end - (bb)->stored.start)
extern void bytebuf_init(struct bytebuf *bb,
			 size_t space_before, size_t space_after);
extern void bytebuf_destroy(struct bytebuf *bb);
extern void bytebuf_prepend(struct bytebuf *bb,
			    const char *src, size_t srclen);
extern void bytebuf_append(struct bytebuf *bb,
			   const char *src, size_t srclen);
extern char *bytebuf_asptr(struct bytebuf *bb);

/***************
 * For pcbuf.c *
 ***************/

struct pcbuf_elem;

struct pcbuf {
	struct {
		struct pcbuf_elem *head, *tail;
	} active, kept;
	size_t cur_size;
	size_t total_written;
	int error;
	unsigned int flags;
};

extern void pcbuf_keep(struct pcbuf *pc);
extern void pcbuf_nokeep(struct pcbuf *pc);
extern void pcbuf_write(struct pcbuf *pc, const void *bytes, size_t len);
#define pcbuf_write_obj(pc, obj)  pcbuf_write((pc), &(obj), sizeof(obj))
extern void pcbuf_multichar(struct pcbuf *pc, char c, size_t count);

extern const char xdigit_lc[16];

extern void pcbuf_vfmt(struct pcbuf *pc, const char *fmt, va_list ap);
extern
#ifdef __GNUC__
	__attribute__ ((format (printf, 2, 3)))
#endif /* __GNUC__ */
	void pcbuf_fmt(struct pcbuf *pc, const char *fmt, ...);
extern int pcbuf_fromfd(struct pcbuf *pc, int fd);
extern ssize_t pcbuf_read(struct pcbuf *pc, void *result, size_t len);
extern int pcbuf_read_todelim(struct pcbuf *pc, char *buf,
			      size_t *buflenp, char delim);
extern int pcbuf_tofd(struct pcbuf *pc, int fd);
extern void pcbuf_rewind(struct pcbuf *pc);
extern void pcbuf_init(struct pcbuf *pc);
extern void pcbuf_destroy(struct pcbuf *pc);

/******************
 * For openfile.c *
 ******************/

struct openfile_lrulinks {
	struct openfile *next, *prev;
};

struct openfile {
	struct openfile_lrulinks lru;	/* keep this first! */
	int backing_fd;
};

#define openfile_init(of)	do { (of)->backing_fd = -1; } while (0)
extern int openfile_fd(struct openfile *of);
extern void openfile_close(struct openfile *of);
extern int openfile_open(struct openfile *of, const char *path);
extern int openfile_stat(const struct openfile *of, struct stat *st);

/*******************
 * For gitworker.c *
 *******************/

/*
 * This structure is used to hold the results of both the GITWORKER_OPEN
 * and GITWORKER_ADD_TO_OCACHE opcodes, although in the latter case ->buf
 * will be NULL
 */
struct gitwork_open_result {
	void *buf;
	unsigned long size;
	enum gitfs_node_type type;
};

struct gitwork_cmd {
	struct gitwork_cmd *queue_next;
	enum {
		GITWORKER_OBJECT_INFO,
		GITWORKER_ADD_TO_OCACHE,
		GITWORKER_FIND_PACKNAME,
		GITWORKER_QUIT,
	} opcode;
	const struct gitobj_ptr *gptr;
	enum gitfs_node_type type;
	union {
		struct gitwork_open_result open;
		char *pack_filename;		/* GITWORKER_FIND_PACKNAME */
	} answer;
	int error;
};

extern int gitwork_init(void);
extern void gitwork_add(struct gitwork_cmd *cmd);
extern void gitwork_service_replies(void);
extern void gitwork_fini(void);

/****************
 * For gitdir.c *
 ****************/

struct gitdir_entry {
	const char *name;
	const struct gitobj_ptr *ptr;
	enum gitfs_node_type type;
	mode_t perm;
};

struct gitdir {
	/* entries are stored in order so we can binary search them */
	struct gitdir_entry *entries;
	unsigned char *backing_buf;
	unsigned int nentries;
	unsigned int nsubdirs;
};

extern int gitdir_parse(struct gitdir *gdir, unsigned char *data,
			size_t datalen);
extern void gitdir_free(struct gitdir *gdir);
extern struct gitdir_entry *gitdir_find(struct gitdir *gdir, const char *name,
					unsigned int *last_findp);
extern void gitdir_readdir(struct gitdir *gdir, struct gitfs_node *gn,
			   struct api_readdir_state *ars);

extern void gitdir_ls_answer(struct pcbuf *out, const struct gitfs_node *gn);
extern const struct gitfs_subcommand scmd_gls;

/****************
 * For gitobj.c *
 ****************/

struct gitobj_pending_request;		/* opaque to gitobj.c */

struct gitobj {
	unsigned long hold_count;
	unsigned long open_count;
	enum gitfs_node_type type;
	union {
		struct gitdir dir;
		struct {		/* also used for symlinks */
			struct openfile of;
			off_t size;
		} file;
	} d;
	struct gitobj_pending_request *pending;
	struct rb_node rb_active;	/* red-black tree */
	struct gitobj_ptr hash;
};

#define gobj_hold(gn)	do { (gobj)->hold_count++; } while (0)
extern void gobj_release(struct gitobj *gobj);
extern int gitobj_lookup_byptr(const struct gitobj_ptr *ptr,
			       struct gitfs_node *gn,
			       enum gitfs_node_type de_type, mode_t de_mode,
			       int (*finish)(int error,
					     struct gitfs_node *gn));
extern void gitwork_finish(struct gitwork_cmd *gwcmd);

struct gobj_dump_filter {
	uint32_t ptrbytes;
	uint32_t last_nibble;
	struct gitobj_ptr ptr;
};
extern void gobj_dump_answer(struct pcbuf *out,
			     const struct gobj_dump_filter *filt);
extern const struct gitfs_subcommand debug_cmd_dump_gobj;

/**************
 * For util.c *
 **************/
// TODO - prune this file as possible

extern
#ifdef __GNUC__
    __attribute__ ((warn_unused_result))
#endif /* __GNUC__ */
	int neg_errno(void);
extern void timespec(struct timespec *now);
extern int create_fullpath(char *buf, size_t bufsiz,
			   const char *dir, const char *fn);

/*
 * Defining basename() this way has the advantage that you can pass in
 * either a "char *" or a "const char *" and it'll return the right type
 */
extern size_t basename_offset(const char *path);
#define basename(path)	(&path[basename_offset(path)])

extern void strdup_if_needed(char **destp, const char *src);
extern int read_ptr(int fd, struct gitobj_ptr *ptr);
extern int symlink_exists(const char *path);

extern int recursive_mkdir(const char *path, int strip_basename);
extern int write_safe(int wfd, const void *data, size_t datalen);
extern int read_safe(int rfd, void *data, size_t datalen);
extern int copy_fd_to_fname(int fd, const char *dst);
extern int move_file(const char *src, const char *dst);
extern int set_nonblock(int fd);
extern void gitptr_ascii(struct gitobj_ptr_ascii *o,
			 const struct gitobj_ptr *gp);
extern int gitptr_to_fname(char *buf, size_t bufsiz, const char *dir,
			   const struct gitobj_ptr *gp);
extern int convert_uint64(const char *str, uint64_t *res);

/*****************
 * For opencmd.c *
 *****************/

/*
 * Note: these functions are NOT reentrant; threaded users must ensure
 * serialization themselves
 */
extern int open_fromcmd(const char *cmd, char * const argv[], int stdin_fd,
			int close_stderr);
extern int open_tocmd(const char *cmd, char * const argv[], int stdout_fd,
		      int close_stderr);
extern int close_cmd(int fd);

/***************
 * For gnode.c *
 ***************/

/*
 * Some places need to remember the location of a gnode long-term.  As long
 * as you hold a reference to it, this is basically fine -- it won't go
 * away.  However, in some corner cases (renaming to a longer name) we need
 * to move the gnode in memory.  In those cases the holder should use this
 * structure and the gn_{,un}save_node() API.
 */
struct gitfs_saved_node {
	struct gitfs_node *gn;
	struct gitfs_saved_node **prevp, *next;
};

extern void gn_save_node(struct gitfs_saved_node *sn, struct gitfs_node *gn);
extern void gn_unsave_node(struct gitfs_saved_node *sn);

struct gitfs_common_ops {
	int (*stat)(struct gitfs_node *gn, struct stat *sbuf);
	void (*destroy)(struct gitfs_node *gn);
};

struct gitfs_file_ops {
	struct gitfs_common_ops common;		/* must be first! */
	int (*open)(struct gitfs_node *gn, unsigned int flags);
	void (*close)(struct gitfs_node *gn);
	int (*pread)(struct gitfs_node *gn,
		     void *buf, size_t size, off_t offset);
	int (*pwrite)(struct gitfs_node *gn,
		      const void *buf, size_t size, off_t offset);
	int (*is_sticky)(struct gitfs_node *gn);
	int (*set_sticky)(struct gitfs_node *gn, int flag);
};

/*
 * "lookup" and "readdir" are required for all directory nodes
 * "count_subdirs" is optional (it's just to compute st_nlinks correctly)
 */
struct gitfs_dir_ops {
	struct gitfs_common_ops common;		/* must be first! */
	/* typically ->lookup() should reteurn 0 or -ENOENT */
	int (*lookup)(struct gitfs_node *parent, struct gitfs_node **resultp,
		      const char *name);
	int (*readdir)(struct gitfs_node *gn, struct api_readdir_state *ars);
	unsigned int (*count_subdirs)(struct gitfs_node *gn);
};

/*
 * "readlink" is required for all symlinks
 * "link_len" is optional; it's just used to compute the file length for stat
 */
struct gitfs_symlink_ops {
	struct gitfs_common_ops common;		/* must be first! */
	int (*readlink)(struct gitfs_node *gn, char *result, size_t *rlen);
	size_t (*link_len)(struct gitfs_node *gn);
};

/* Forward declarations for things that can go in gn->priv: */
struct git_tag;
struct git_tag_dir;
struct gn_defered_incomplete_lookup;	/* private to gnode.c */

/*
 * Note: this structure doesn't need to be refcounted -- we only free it when
 * we're freeing it's "root" node in gn_release_nref().
 */
struct gitfs_tree {
	struct gitfs_saved_node root;
	char *symbolic_name;
	char *backing_path;
};

struct gitfs_fs_backing {
	struct openfile of;
	char *path;
};

/*
 * Our internal idea of what a node in our filesystem looks like.  Holds
 * all the info about a file or directory
 */
struct gitfs_node {
	unsigned long hold_count;
	unsigned long open_count;
	enum gitfs_node_type type;
	struct gitfs_tree *tree;
	union {
		const struct gitfs_common_ops *c;
		const struct gitfs_file_ops *f;
		const struct gitfs_dir_ops *d;
		const struct gitfs_symlink_ops *sl;
	} op;
	/*
	 * Inode # (or zero for the root node)  For non-root nodes we
	 * garauntee that the low 32-bits will be >= 256 and unique within
	 * the tree.  We don't try too hard for long-term inode # persistance
	 * However, nodes tend to stay in the tree for a fairly long time so
	 * it shouldn't cause problems for most software
	 */
	struct rb_node inum_tree;
	gitfs_inum_t inum;
	/*
	 * Linkage within the tree -- a link to our parent (who
	 * we keep a gn_hold() on)
	 */
	struct gitfs_node *parent;
	union {			/* per-filetype data... */
		struct {	/* ...GIT_DIR */
			struct rb_tree children;
			unsigned int last_lookup_offset;
			struct gn_defered_incomplete_lookup *first_defered;
		} d;
		struct {	/* ...GIT_FILE */
			int direct_io;	/* OS can't cache data */
		} f;
	} t;
	struct {
		mode_t perm;
		struct timespec atime;
	} stat;
	/*
	 * Backing object(s).  For something in the git tree there will
	 * only be a corresponding git object.  A file gnode in a worktree
	 * can be either an unmodified git object OR a file.  A directory
	 * in a worktree can have both if it contains some files that are
	 * modified
	 */
	struct {
		struct gitobj *gobj;	/* backing git object, if any */
		struct gitfs_fs_backing file;
	} backing;
	/* private data used by some lower levels */
	union {
		struct git_tag *gt;
		struct git_tag_dir *gtd;
	} priv;
	struct gitfs_saved_node *saved_node_root;
	/* rbtree for holding all of our parent's active children by name */
	struct rb_node name_tree;
	char name[0];		/* must be last! */
};

#define gn_is_treeroot(ggn) ((ggn)->tree != NULL &&			\
			     (ggn)->tree->root.gn == ggn)

#define gn_hold(gn)	do { (gn)->hold_count++; } while (0)
extern void gn_release_nref(struct gitfs_node *gn, unsigned int refcnt);
#define gn_release(gn)	gn_release_nref((gn), 1)
#define gn_release_notlast(gn)						\
do {									\
	assert((gn)->hold_count > 1);					\
	(gn)->hold_count--;						\
} while (0)
#define gn_assert_held(gn)						\
do {									\
	assert((gn)->hold_count > 0);					\
	assert((gn)->backing.gobj == NULL ||				\
	       (gn)->backing.gobj->hold_count > 0);			\
} while (0)

extern struct gitfs_node *gn_lookup_inum(gitfs_inum_t inum);
extern struct gitfs_node *gn_alloc(struct gitfs_node *parent,
				   const char *name);
extern void gn_set_type(struct gitfs_node *gn, enum gitfs_node_type ntype);
extern int gn_lookup_in(struct gitfs_node *parent, const char *elem,
			struct gitfs_node **resultp);
extern void gn_finish_defered_lookups(struct gitfs_node *parent,
				      struct api_request *req, int error);
extern gitfs_inum_t gn_child_inum(struct gitfs_node *gn, const char *elem);
extern int gn_change_name(struct gitfs_node **gnp, const char *newname);
extern const struct gitfs_subcommand scmd_pwd;
extern void ino_dump_single_answer(struct pcbuf *out,
				   const struct gitfs_node *gn);
extern void ino_dump_answer(struct pcbuf *out);
extern const struct gitfs_subcommand debug_cmd_dump_ino;

/****************
 * For topdir.c *
 ****************/

extern struct gitfs_node gitfs_node_root;

/****************
 * For tagdir.c *
 ****************/

extern int tagroot_lookup(struct gitfs_node **resultp, const char *name);
extern void tagroot_readdir(struct api_readdir_state *ars);
extern unsigned int tagroot_count_subdirs(void);

/******************
 * For autotree.c *
 ******************/

extern unsigned int autotree_count_subdirs(void);
extern void autotree_readdir(struct api_readdir_state *ars);
extern int autotree_lookup(struct gitfs_node **resultp, const char *name);

/******************
 * For worktree.c *
 ******************/

extern unsigned int worktree_count_subdirs(void);
extern void worktree_readdir(struct api_readdir_state *ars);
extern int worktree_lookup(struct gitfs_node **resultp, const char *name);

/******************
 * For api-fuse.c *
 ******************/

extern int api_add_dir_contents(struct api_readdir_state *ars,
				const char *name, enum gitfs_node_type type,
				gitfs_inum_t inum);
extern int api_open_mount(const char *path, int rdonly);
extern int api_umount_and_exit(const char *path);
extern void api_umount(void);
extern enum service_result api_service_poll(void);

/*
 * If a low-level function wants to defer answering a request (in order
 * to allow another thread to help out, for instance) this is the API to
 * use
 *
 * Calling api_save_request() will "freeze" the current request and return
 * an opaque pointer.  Note that this operation can fail (and return NULL)
 * if we're at low memory -- callers must be prepared for this.  After a
 * successful call the low-level function can just return zero to end
 * processing on the request.
 *
 * After the request is completed (one way or another) you MUST call
 * api_complete_saved_request() to close the request out.  If its a call
 * like "read" or "readlink" that returns a buffer then you must pass in
 * your own buffer -- the one originally offered to you will have been
 * reused
 *
 * Finally, for some "lookup" requests the lower levels may need to save
 * the request before we know its proper gnode -- in that case it can be
 * passed in as NULL and set later via api_saved_request_set_gnode()
 */
extern struct api_request *api_save_request(struct gitfs_node *gn);
extern void api_complete_saved_request(struct api_request *ipc, int error,
				       char *buf, size_t buflen);
extern void api_saved_request_set_gnode(struct api_request *ipc,
					struct gitfs_node *gn);

/*******************
 * For cmd-mount.c *
 *******************/

extern int gitfs_read_only;
extern const char *ocache_dir;
extern char instance_str[];
extern void selfpipe_ping(void);
extern int epoll_add(int fd, void *token);
extern int epoll_mod(int fd, void *token, int newmode);
extern int epoll_del(int fd);
extern const struct gitfs_subcommand scmd_mount;
extern const struct gitfs_subcommand scmd_umount;

/**************
 * For main.c *
 **************/

extern int gitfs_debug;
#define gdbg(gdbg_fmt, ...)						\
do {									\
	if (unlikely(gitfs_debug != 0))					\
		fprintf(stderr, gdbg_fmt "\n", ## __VA_ARGS__);		\
} while (0)

extern void print_usage(void);

/***************
 * For csipc.c *
 ***************/

extern int csipc_init(void);
extern void csipc_fini(void);
#define CSIPC_DISCOVERY_FILE ".__gitfs__ipcdisc"
extern int csipc_discovery_node(struct gitfs_node *parent,
				struct gitfs_node **resultp);
extern enum service_result csipc_service(void *token);

/* Functions for client-side IPC access: */
struct gitfs_server_connection;		/* opaque outside csipc.c */
typedef int32_t csipc_fh_t;
extern struct gitfs_server_connection *gs_connection_open(void);
extern void gs_connection_close(struct gitfs_server_connection *gsc);
extern csipc_fh_t gs_open_inode(struct gitfs_server_connection *gsc,
				gitfs_inum_t inum);
extern int gs_close(struct gitfs_server_connection *gsc, csipc_fh_t fh);
extern csipc_fh_t gs_dupfd(struct gitfs_server_connection *gsc,
			   csipc_fh_t fh);
extern int gs_getname(struct gitfs_server_connection *gsc, csipc_fh_t fh,
		      char *buf, size_t buflen);
extern int gs_cdup(const struct gitfs_server_connection *gsc, csipc_fh_t fh);
extern int gs_dump_gobj(struct gitfs_server_connection *gsc,
			const struct gobj_dump_filter *filt,
			void *buf, size_t buflen,
			enum service_result (*work)(const void *data,
						    void *state),
			void *state);
extern int gs_gls(struct gitfs_server_connection *gsc, csipc_fh_t fh,
		  enum service_result (*work)(enum gitfs_node_type type,
					      mode_t perm,
					      const struct gitobj_ptr *ptr,
					      const char *name));
extern int gs_dump_ino_single(struct gitfs_server_connection *gsc,
			      csipc_fh_t fh, void *buf, size_t buflen,
			      enum service_result (*work)(const void *data,
							  const char *name,
							  void *state),
			      void *state);
extern int gs_dump_ino(struct gitfs_server_connection *gsc,
		       void *buf, size_t buflen,
		       enum service_result (*work)(const void *data,
						   const char *name,
						   void *state),
		       void *state);
extern int gs_is_treeroot(struct gitfs_server_connection *gsc, csipc_fh_t fh);

#endif /* !GOT_GITFS_H */
