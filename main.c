/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#define FUSE_USE_VERSION 27

#include <fuse.h>

#include <cache.h>
#include <object.h>
#include <tree.h>
#include <commit.h>
#include <tag.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *__gitfs_str = "__Gitfs World!\n";
static const char *__gitfs_path = "/__gitfs";

struct object *__object(const char *path)
{
	char *ref = xstrdup("HEAD");
	char *sub = xstrdup(path + 1);

	if (strncmp(path, "/.refs/", 7) == 0) {
		const char *end = strchr(path + 7, '/');
		if (end == NULL) {
			ref = xstrdup(path + 7);
			sub = xstrdup("");
		} else {
			ref = xstrndup(path + 7, end - path - 7);
			sub = xstrdup(end + 1);
		}
	}

	char tmp[1000];
	sprintf(tmp, "%s:%s", ref, sub);

	free(ref);
	free(sub);

	unsigned char sha1[20];
	int ret = get_sha1(tmp, sha1);
	printf("path %s resolved to %s\n", path, tmp);

	if (ret)
		return NULL;

	struct object *obj = parse_object(sha1);
        do {
                if (!obj)
                        return NULL;
                if (obj->type == OBJ_TREE || obj->type == OBJ_BLOB)
                        return obj;
                else if (obj->type == OBJ_COMMIT)
                        obj = &(((struct commit *) obj)->tree->object);
                else if (obj->type == OBJ_TAG)
                        obj = ((struct tag *) obj)->tagged;
                else
                        return NULL;

                if (!obj->parsed)
                        parse_object(obj->sha1);
        } while (1);
}

static int __gitfs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));

	struct object *obj = __object(path);
	if (obj == NULL) {
		if (strncmp(path, "/.refs", 6))
			return -ENOENT;

		if (strcmp(path, "/.refs") == 0) {
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		} else {
			const char *ref = path + 7;

			unsigned char sha1[20];
			if (get_sha1(ref, sha1))
				return -ENOENT;

			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
		}

		return 0;
	}

	printf("object type: %d\n", obj->type);

	if (obj->type == OBJ_TREE) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (obj->type == OBJ_BLOB) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(__gitfs_str);
	} else {
		res = -ENOENT;
	}

	return res;
}

struct __gitfs_readdir_ctx {
	void *buf;
	fuse_fill_dir_t filler;
};

static int show_tree(const unsigned char *sha1, const char *base, int baselen,
		     const char *pathname, unsigned mode, int stage, void *context)
{
        struct __gitfs_readdir_ctx *ctx = context;

	(*ctx->filler) (ctx->buf, pathname, NULL, 0);

	return 0;
}

static int show_ref(const char *refname, const unsigned char *sha1, int flag, void *context)
{
	struct __gitfs_readdir_ctx *ctx = context;

        (*ctx->filler) (ctx->buf, strrchr(refname, '/') + 1, NULL, 0);

        return 0;
}

static int __gitfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	struct __gitfs_readdir_ctx ctx = { buf, filler };

	if (strcmp(path, "/.refs") == 0) {
		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);

		for_each_ref(show_ref, &ctx);
		return 0;
	}

	struct object *obj = __object(path);
	if (!obj || obj->type != OBJ_TREE)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

        struct tree *tree = (struct tree *) obj;

        read_tree_recursive(tree, "", 0, 0, NULL, show_tree, &ctx);
	
//	filler(buf, __gitfs_path + 1, NULL, 0);

	return 0;
}

static int __gitfs_open(const char *path, struct fuse_file_info *fi)
{
	struct object *obj = __object(path);
	if (!obj || obj->type != OBJ_BLOB)
		return -ENOENT;

	if((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int __gitfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	size_t len;

	struct object *obj = __object(path);
	if (!obj || obj->type != OBJ_BLOB)
		return -ENOENT;

	len = strlen(__gitfs_str);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, __gitfs_str + offset, size);
	} else
		size = 0;

	return size;
}

static struct fuse_operations ops = {
	.getattr = __gitfs_getattr,
	.readdir = __gitfs_readdir,
	.open = __gitfs_open,
	.read = __gitfs_read,
};

int main(int argc, char *argv[])
{
	git_config(git_default_config, NULL);

	return fuse_main(argc, argv, &ops, NULL);
}
