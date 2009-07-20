# Run with "V=1" to see all the gory details
prefix_func=@echo $(1);
ifdef V
	prefix_func=
endif

# Set to where your git source tree is, and what flags are required to build
# against it
GITDIR = ../git
GITCFLAGS = '-DSHA1_HEADER=<openssl/sha.h>' -I$(GITDIR)
GITLDFLAGS = $(GITDIR)/libgit.a $(GITDIR)/xdiff/lib.a -lcrypto -lz

DEFINEFLAGS = -D_FILE_OFFSET_BITS=64 -D_REENTRANT $(GITCFLAGS) $(FUSECFLAGS)

OBJS = gitobj.o api-fuse.o gnode.o topdir.o util.o tagdir.o autotree.o \
       gitdir.o main.o worktree.o openfile.o gitworker.o rbtree.o pcbuf.o \
       opencmd.o cmd-mount.o csipc.o bytebuf.o view.o conf.o

# I'm a big fan of compiler warnings:
WARNFLAGS = -Wall -Wextra -Wwrite-strings -Wshadow -Wbad-function-cast \
	    -Wcast-qual -Wcast-align -Wsign-compare -Waggregate-return \
	    -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
	    -Wmissing-declarations -Wmissing-noreturn \
	    -Wmissing-format-attribute -Wredundant-decls -Wnested-externs \
	    -Wvolatile-register-var
# Warnings that I'd like to enable but can't:
#   -Wunreachable-code: triggers on every C label, strcmp(), assert(), ...
#   -Wc++-compat: implicit casts from "void *" are so useful...
#   -Wpointer-arith: ...and so is math on "void *" pointers
#   -Wundef: causes warnings in git's headers
#   -Wconversion: this is WAY too chatty (for instance if you have a function
#		that takes a "char" argument)  Sad because this also warns
#		about other things that are useful

OPTFLAGS=-ggdb -O2

gitfs: $(OBJS)
	$(call prefix_func,"LINK $@")gcc $(WARNFLAGS) $(OPTFLAGS) -o $@ $+ $(GITLDFLAGS) -lpthread -lrt

rbtree_unittest: rbtree.c gitfs.h
	$(call prefix_func,"LINK $@")gcc $(WARNFLAGS) $(OPTFLAGS) -DRBTREE_UNITTEST -o $@ $<

# Handy rule for compiling to assembly for inspection
# We turn up omtimization farther and turn off assert()'s for readability
%.s: %.c
	$(call prefix_func,"COMPILE-TO-ASSEMBLY $<")gcc $(DEFINEFLAGS) $(WARNFLAGS) -O3 -DNDEBUG -S $<

%.o: %.c
	$(call prefix_func,"COMPILE $<")gcc $(DEFINEFLAGS) $(WARNFLAGS) $(OPTFLAGS) -c $<

clean:
	rm -f gitfs $(OBJS) rbtree_unittest
.PHONY: clean

# Run the "sparse" syntax checker against the source files.  So far I haven't
# found this too useful, but here you go
#
# the `gcc -M ...` stuff is a gross hack to find out where all the C header
# files are coming from.  Without this sparse can't find header files that
# are gcc-private like stdarg.h
sparse:
	sparse `gcc -M $(GITCFLAGS) $(FUSECFLAGS) *.c | tr ' ' '\012' | sed -e '/^\/.*\/include\/[^/]*\.h$$/!d;s:/[^/]*\.h$$::;s/^/-I /' | sort | uniq` $(GITCFLAGS) $(FUSECFLAGS) *.c
.PHONY: sparse

# Dependencies go here:
$(OBJS): gitfs.h
cmd-mount.o: defaults.h
