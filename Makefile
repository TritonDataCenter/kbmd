#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2020 Joyent, Inc.
#

include		$(PWD)/../../../build.env

STRAP_AREA =	$(PWD)/../../../proto.strap
CC =		$(STRAP_AREA)/usr/bin/gcc
AR =		/usr/bin/ar
LIBCRYPTO =	$(DESTDIR)/lib/amd64/libsunw_crypto.a
PROTOINC =	$(DESTDIR)/usr/include
INSTALL =	/usr/sbin/install

PROGS =		kbmd kbmadm
PIVY_TARGETS =	pivy-tool pivy-box


CPPFLAGS =	-I$(PROTOINC) -I$(PROTOINC)/PCSC -Icommon -Ipivy
CFLAGS =	-g -msave-args -m64 -std=gnu99 -fstack-protector-all
LDFLAGS =	-L$(DESTDIR)/lib/amd64 -L$(DESTDIR)/usr/lib/amd64
LDLIBS =	-lumem -lssp -lcustr -lnvpair -lsocket

COMMON_SRCS =			\
	common/common.c		\
	common/ecustr.c		\
	common/envlist.c	\
	common/kspawn.c		\
	pivy/errf.c

COMMON_OBJS = $(COMMON_SRCS:%.c=%.o)

KBMADM_SRCS = \
	kbmadm/kbmadm.c

KBMADM_OBJS = $(KBMADM_SRCS:%.c=%.o)

KBMD_SRCS =		\
	door.c		\
	kbmd.c		\
	plugin.c	\
	zfs_box.c	\
	zfs_unlock.c	\
	zpool_create.c

KBMD_OBJS =	$(KBMD_SRCS:%.c=kbmd/%.o)
KBMD_LIBS =	-lsmbios -lzfs -lbunyan -luuid -lscf -lz -lpcsclite
out/kbmd :	LDLIBS += $(KBMD_LIBS)

LIBSSH_OBJS = 			\
	atomicio.o		\
	authfd.o		\
	base64.o		\
	bcrypt-pbkdf.o		\
	blowfish.o		\
	cipher.o		\
	digest-openssl.o	\
	hmac.o			\
	rsa.o			\
	ssh-ecdsa.o		\
	ssh-ed25519.o		\
	ssh-rsa.o		\
	sshbuf.o		\
	sshkey.o

SSS_OBJS =		\
	hazmat.o	\
	randombytes.o

CHAPOLY_OBJS =		\
	chacha.o	\
	poly1305.o

ED25519_OBJS =		\
	blocks.o	\
	ed25519.o	\
	fe25519.o	\
	ge25519.o	\
	hash.o		\
	sc25519.o

# NOTE: errf.c is included within the kbmd/kbmadm common objs
# The pivy sources are only included within kbmd
PIVY_OBJS =			\
	debug.o			\
	ebox.o			\
	piv.o			\
	tlv.o

PIVY_A_OBJS =					\
	$(PIVY_OBJS:%=pivy/%)			\
	$(SSS_OBJS:%=pivy/sss/%)		\
	$(LIBSSH_OBJS:%=pivy/libssh/%)		\
	$(CHAPOLY_SRCS:%=pivy/chapoly/%)	\
	$(ED25519_OBJS:%=pivy/ed25519/%)

#
# Build Targets
#

.PHONY: all world
world: all
all: pivy-stamp out/common.a out/pivy.a $(PROGS:%=out/%)

out:
	-mkdir out

$(PROGS:%=out/%) out/common.a out/pivy.a: out

out/common.a: $(COMMON_OBJS)
	$(AR) -cr $@ $(COMMON_OBJS)

out/pivy.a: pivy-stamp
	$(AR) -cr $@ $(PIVY_A_OBJS)

common/%.o: common/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
	$(CTFCONVERT) $@

kbmadm/%.o: kbmadm/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
	$(CTFCONVERT) $@

kbmd/%.o: kbmd/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
	$(CTFCONVERT) $@

out/kbmadm: $(KBMADM_OBJS) out/common.a
	$(CC) -o $@ $(CFLAGS) $(KBMADM_OBJS) out/common.a $(LDFLAGS) $(LDLIBS)
	$(CTFCONVERT) $@

out/kbmd: $(KBMD_OBJS) out/common.a out/pivy.a
	$(CC) -o $@ $(CFLAGS) $(KBMD_OBJS) out/common.a out/pivy.a $(LIBCRYPTO) $(LDFLAGS) $(LDLIBS)
	$(CTFCONVERT) $@

#
# Install Targets
#
.PHONY: install manifest
install: all
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-tool
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-box
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin out/kbmadm
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/lib out/kbmd

manifest:
	cp manifest $(DESTDIR)/$(DESTNAME)

mancheck_conf:

.PHONY: update
update:
	git pull --rebase

pivy-stamp:
	(cd pivy; $(MAKE) \
	    CC=$(CC) \
	    PROTO_AREA="$(DESTDIR)" \
	    PCSC_CFLAGS="-I$(DESTDIR)/usr/include/PCSC" \
	    PCSC_LIBS="-L$(DESTDIR)/usr/lib/amd64 -lpcsclite" \
	    CRYPTO_FLAGS="-I$(DESTDIR)/usr/include" \
	    CRYPTO_LIBS="$(LIBCRYPTO)" \
	    LIBRESSL_INC="$(DESTDIR)/usr/include" \
	    LIBCRYPTO="$(LIBCRYPTO)" \
	    $(PIVY_TARGETS) && \
	    touch ../pivy-stamp)

clean:
	rm -f $(COMMON_OBJS) $(KBMADM_OBJS) pivy-stamp out/*
	-rmdir out
	(cd pivy; $(MAKE) clean)
