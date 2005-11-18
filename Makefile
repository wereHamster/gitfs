# Set to where your git source tree is, and what flags are required to build
# against it
GITDIR = ../git/git-core-0.99.9g
GITCFLAGS = '-DSHA1_HEADER=<openssl/sha.h>' -I$(GITDIR)
GITLDFLAGS = $(GITDIR)/libgit.a -lcrypto

# What flags are required to build against FUSE
FUSECFLAGS = '-DFUSE_HEADER="../git/linux-2.6/include/linux/fuse.h"'

OBJS = gitobj.o api-fuse.o gnode.o topdir.o util.o tagdir.o autotree.o \
       gitdir.o main.o worktree.o openfile.o gitworker.o rbtree.o pcbuf.o \
       opencmd.o cmd-mount.o csipc.o bytebuf.o

gitfs: $(OBJS)
	gcc -Wall -W -g -O2 -o $@ $+ $(GITLDFLAGS) -lpthread -lrt

rbtree_unittest: rbtree.c
	gcc -Wall -W -g -O2 -DRBTREE_UNITTEST -o $@ $<
%.s: %.c
	gcc -Wall -W -O3 -DNDEBUG -S $<

%.o: %.c
	gcc -D_FILE_OFFSET_BITS=64 -D_REENTRANT $(GITCFLAGS) $(FUSECFLAGS) \
		-Wall -W -g -O2 -c $<

clean:
	rm -f gitfs $(OBJS) rbtree_unittest

$(OBJS): gitfs.h
cmd-mount.o: defaults.h
