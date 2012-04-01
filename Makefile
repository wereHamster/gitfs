
GITDIR = ../git

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CFLAGS  = `pkg-config --cflags fuse` -I$(GITDIR)/ '-DSHA1_HEADER=<openssl/sha.h>'
LDFLAGS = `pkg-config --libs fuse` $(GITDIR)/libgit.a $(GITDIR)/xdiff/lib.a -lcrypto -lz

ifeq ($(uname_S),Darwin)
	CFLAGS += -mmacosx-version-min=10.5
	LDFLAGS += -L/opt/local/lib
endif

all:
	gcc -O0 -g -ggdb -o gitfs $(CFLAGS) main.c $(LDFLAGS)
