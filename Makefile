
GITDIR = ../git

all:
	gcc -O0 -g -ggdb -o gitfs main.c `pkg-config --cflags --libs fuse` -I$(GITDIR)/ $(GITDIR)/libgit.a $(GITDIR)/xdiff/lib.a '-DSHA1_HEADER=<openssl/sha.h>' -lcrypto -lz
