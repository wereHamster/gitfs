# Set to where your git source tree is, and what flags are required to build
# against it
GITDIR = ../git/git-core-0.99.8
GITCFLAGS = '-DSHA1_HEADER=<openssl/sha.h>' -I$(GITDIR)
GITLDFLAGS = $(GITDIR)/libgit.a -lcrypto

# What flags are required to build against FUSE
FUSECFLAGS = -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=22
FUSELDFLAGS = -lfuse -lpthread -Wl,--rpath -Wl,/usr/local/lib

OBJS = gitobj.o fuseapi.o gnode.o topdir.o util.o tagdir.o autotree.o \
       gitdir.o main.o worktree.o

gitfs: $(OBJS)
	gcc -Wall -W -g -O2 -o $@ $+ $(GITLDFLAGS) $(FUSELDFLAGS)

%.o: %.c
	gcc $(GITCFLAGS) $(FUSECFLAGS) -Wall -W -g -O2 -c $<

clean:
	rm -f gitfs $(OBJS)

$(OBJS): gitfs.h
main.o: defaults.h
