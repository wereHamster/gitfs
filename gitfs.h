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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* length of a constant string */
#define strlen_const(cs)	(sizeof("" cs) - sizeof(""))

/* Forwawrd declarations */
struct gitfs_node;
struct api_readdir_state;	/* opaque outside fuseapi.c */

/* TODO -- errmsg.c */

/****************
 * For gitdir.c *
 ****************/

enum gitfs_node_type {
	GFN_FILE,
	GFN_DIR,
	GFN_SYMLINK,
};

struct gitobj_ptr {
	unsigned char sha1[160 / 8];
};
extern struct gitobj_ptr dummy_ptr; /* doesn't exist; only for sizeof() */
#define HEX_PTR_LEN	(strlen_const("AA") * sizeof(dummy_ptr.sha1))

struct gitdir_entry {
	const char *name;
	const struct gitobj_ptr *ptr;
	enum gitfs_node_type type;
	mode_t perm;
};

struct gitdir {
	/* entries are stored in order so we can binary search them */
	struct gitdir_entry *entries;
	char *backing_file;
	unsigned int nentries;
	unsigned int nsubdirs;
	time_t atime;
	unsigned int last_find;
};

extern int gitdir_parse(struct gitdir *gdir, unsigned char *data,
			size_t datalen);
extern void gitdir_free(struct gitdir *gdir);
extern struct gitdir_entry *gitdir_find(struct gitdir *gdir, const char *name);
extern void gitdir_readdir(struct gitdir *gdir, struct api_readdir_state *ars);

/****************
 * For gitobj.c *
 ****************/

struct gitobj {
	struct gitobj_ptr hash;
	enum gitfs_node_type type;
	union {
		struct gitdir dir;
		struct {		/* also used for symlinks */
			int backing_fd;
			off_t size;
		} file;
	} d;
	mode_t perm;
	unsigned long hold_count;
	struct gitobj *lru_prev, *lru_next;
};

#define gobj_hold(gn)	do { (gobj)->hold_count++; } while (0)
extern void gobj_release(struct gitobj *gobj);
extern int gitobj_lookup_byptr(const struct gitobj_ptr *ptr,
			       struct gitfs_node **resultp,
			       const struct gitdir_entry *dire);

/**************
 * For util.c *
 **************/
// TODO - prune this file as possible

extern int neg_errno(void);
extern time_t mtime_of(const char *path);
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
extern int write_safe(int wfd, void *data, size_t datalen);
extern int copy_fd_to_fname(int fd, const char *dst);
extern int move_file(const char *src, const char *dst);

/***************
 * For gnode.c *
 ***************/

/*
 * "stat" is optional for all nodes
 * "destroy" is required EXCEPT for nodes which are not dynamically created
 */
struct gitfs_common_ops {
	int (*stat)(struct gitfs_node *gn, struct stat *sbuf);
	void (*destroy)(struct gitfs_node *gn);
};

struct gitfs_file_ops {
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
	int (*readlink)(struct gitfs_node *gn, char *result, size_t *rlen);
	size_t (*link_len)(struct gitfs_node *gn);
};

/* Forward declarations for things that can go in gn->priv: */
struct git_tag;
struct git_tag_dir;

/*
 * Our internal idea of what a node in our filesystem looks like.  Holds
 * all the info about a file or directory
 */
struct gitfs_node {
	enum gitfs_node_type type;
	const struct gitfs_common_ops *opc;
	union {
		const struct gitfs_file_ops *f;
		const struct gitfs_dir_ops *d;
		const struct gitfs_symlink_ops *sl;
	} op;
	unsigned long hold_count;
	struct gitobj *gitobj;		/* backing git object, if any */
	union {
		struct git_tag *gt;
		struct git_tag_dir *gtd;
	} priv;
};

#define gn_hold(gn)	do { (gn)->hold_count++; } while (0)
extern struct gitfs_node *gn_alloc(enum gitfs_node_type type);
extern void gn_release(struct gitfs_node *gn);
extern int gn_lookup_from(struct gitfs_node *gn, const char *path,
			  struct gitfs_node **resultp);
#define gn_lookup(path, rp) gn_lookup_from(&gitfs_node_root, path, rp)
/*
 * gn_lookup_type() is like gn_lookup() but also verifies the expected node
 * type
 */
extern int gn_lookup_type(const char *path, struct gitfs_node **resultp,
			  enum gitfs_node_type type);
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

/*****************
 * For fuseapi.c *
 *****************/

extern int api_add_dir_contents(struct api_readdir_state *ars,
				const char *name, enum gitfs_node_type type);
extern int api_prepare_mount(const char *path);
extern void api_abandon_mount(void);
extern int api_run_mount(void);
extern int api_umount(const char *path);

/**************
 * For main.c *
 **************/

extern int gitfs_debug;
extern int gitfs_please_exit;
extern const char *ocache_dir;

#endif /* !GOT_GITFS_H */
