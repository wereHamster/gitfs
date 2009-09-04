
#include <assert.h>

#define FUSE_USE_VERSION 27
#include <fuse.h>

#include <cache.h>
#include <object.h>
#include <tree.h>
#include <commit.h>
#include <tag.h>
#include <diff.h>
#include <revision.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

struct __gitfs_object {
	unsigned char rev[20];
	struct object *obj;
	unsigned mode;
};

static const char *parse(const char *path, unsigned char sha1[20])
{
	const char *ref = "HEAD", *end = ref + 4;

	if (strncmp(path, "/.refs", 6) == 0) {
		if (path[6] == '\0')
			return NULL;

		if (path[6] == '/') {
			path += 7;
			ref = path;

			end = strchr(ref, '/');
			if (end == NULL)
				end = path + strlen(path);

			path = end[0] == '/' ? end + 1 : end;
		}
	} else {
		path += 1;
	}

	if (get_sha1_1(ref, end - ref, sha1))
		return NULL;
	
	return path;
}

struct object *gitobj(unsigned char sha1[20])
{
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

struct __gitfs_object *__gitfs(const char *path)
{
	unsigned char sha1[20];
	const char *dir = parse(path, sha1);
	if (!dir)
		return NULL;

	struct object *obj = gitobj(sha1);
	if (!obj)
		return NULL;

	unsigned mode = 0644;
	if (obj->type == OBJ_TREE) {
		unsigned char blob[20];
		if (get_tree_entry(sha1, dir, blob, &mode))
			return NULL;

		obj = gitobj(blob);
	}

	struct __gitfs_object *gfsobj = malloc(sizeof(struct __gitfs_object));
	if (gfsobj) {
		hashcpy(gfsobj->rev, sha1);
		gfsobj->obj = obj;
		gfsobj->mode = mode;
	}

	return gfsobj;
}

static int __gitfs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/.refs") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;

		return 0;
	}

	struct __gitfs_object *obj = __gitfs(path);
	if (obj == NULL)
		return -ENOENT;

	if (obj->obj->type == OBJ_TREE) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (obj->obj->type == OBJ_BLOB) {
		stbuf->st_mode = S_IFREG | obj->mode;
		stbuf->st_nlink = 1;

		sha1_object_info(obj->obj->sha1, &stbuf->st_size);
	} else {
		res = -ENOENT;
	}

	free(obj);

	return res;
}

static int __gitfs_readlink(const char *path, char *buf, size_t size)
{
	unsigned long len;

	struct __gitfs_object *obj = __gitfs(path);
	if (!obj)
		return -ENOENT;
	
	enum object_type type;
	void *data = read_sha1_file(obj->obj->sha1, &type, &len);

	assert(type == obj->obj->type);
	free(obj);

	if (len > size)
		len = size;

	memcpy(buf, data, len);
	free(data);

	return 0;
}

static int __gitfs_open(const char *path, struct fuse_file_info *fi)
{
	struct __gitfs_object *obj = __gitfs(path);
	if (!obj)
		return -ENOENT;

	if (obj->obj->type == OBJ_TREE)
		return -EISDIR;

	assert(obj->obj->type == OBJ_BLOB);

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	fi->fh = (uint64_t) obj;

	return 0;
}

static int __gitfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	unsigned long len;

	struct __gitfs_object *obj = (struct __gitfs_object *) fi->fh;
	assert(obj);

	if (obj->obj->type != OBJ_BLOB)
		return -ENOENT;
	
	enum object_type type;
	void *data = read_sha1_file(obj->obj->sha1, &type, &len);

	assert(type == obj->obj->type);

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, data + offset, size);
	} else {
		size = 0;
	}

	free(data);

	return size;
}

static int __gitfs_release(const char *path, struct fuse_file_info *fi)
{
	struct __gitfs_object *obj = (struct __gitfs_object *) fi->fh;
	assert(obj);

	free(obj);

	return 0;
}

static int __gitfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	struct __gitfs_object *obj = __gitfs(path);
	if (!obj)
		return -ENOENT;

	if (strcmp(name, "__gitfs.hash") == 0) {
		strncpy(value, sha1_to_hex(obj->obj->sha1), size);
	}

	return 0;
}

static int __gitfs_opendir(const char *path, struct fuse_file_info *fi)
{
	return -ENOENT;
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

        (*ctx->filler) (ctx->buf, refname, NULL, 0);

        return 0;
}

static int __gitfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	struct __gitfs_readdir_ctx ctx = { buf, filler };

	if (strcmp(path, "/.refs") == 0) {
		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);

		for_each_tag_ref(show_ref, &ctx);
		return 0;
	}

	struct __gitfs_object *obj = __gitfs(path);
	if (!obj || obj->obj->type != OBJ_TREE)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

        struct tree *tree = (struct tree *) obj->obj;

        read_tree_recursive(tree, "", 0, 0, NULL, show_tree, &ctx);

	free(obj);
	
	return 0;
}

static int __gitfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	return -ENOENT;
}

static int __gitfs_access(const char *path, int mode)
{
	return -ENOENT;
}

static int __gitfs_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *fi)
{
	return -ENOENT;
}

static struct fuse_operations __gitfs_ops = {
	.getattr    = __gitfs_getattr,
	.readlink   = __gitfs_readlink,
	.open       = __gitfs_open,
	.read       = __gitfs_read,
	.release    = __gitfs_release,
//	.getxattr   = __gitfs_getxattr,
//	.opendir    = __gitfs_opendir,
	.readdir    = __gitfs_readdir,
//	.releasedir = __gitfs_releasedir,
//	.access     = __gitfs_access,
//	.fgetattr   = __gitfs_fgetattr,
};

int main(int argc, char *argv[])
{
	const char *retval = setup_git_directory();
	git_config(git_default_config, NULL);

	return fuse_main(argc, argv, &__gitfs_ops, NULL);
}
