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
# Copyright 2019, Joyent, Inc.
#

include		$(PWD)/../../../build.env

STRAP_AREA =	$(PWD)/../../../proto.strap
CC =		$(STRAP_AREA)/usr/bin/gcc
AR =		/usr/bin/ar
LIBCRYPTO =	$(DESTDIR)/lib/amd64/libsunw_crypto.a
PROTOINC =	$(DESTDIR)/usr/include
INSTALL =	/usr/sbin/install

_PROGS =	kbmd kbmadm
_STATIC_LIBS =	common.a pivy.a

PROGS =		$(_PROGS:%=out/%)
STATIC_LIBS =	$(_STATIC_LIBS:%=out/%)

PIVY_TARGETS =	pivy-tool pivy-box

CPPFLAGS =	-I$(PROTOINC) -I$(PROTOINC)/PCSC -Icommon -I.
CFLAGS =	-g -msave-args -m64 -std=gnu99 -fstack-protector-all
LDFLAGS =	-L$(DESTDIR)/lib/amd64 -L$(DESTDIR)/usr/lib/amd64
LDLIBS =	out/common.a -lumem -lssp -lcustr -lnvpair -lsocket

_COMMON_SRCS =		\
	common.c	\
	ecustr.c	\
	envlist.c	\
	kspawn.c

# Include errf here since it is shared between kbmd and kbmadm
COMMON_SRCS = $(_COMMON_SRCS:%=common/%) pivy/errf.c
COMMON_OBJS = $(COMMON_SRCS:%.c=%.o)

_KBMADM_SRCS = \
	kbmadm.c
KBMADM_SRCS = $(_KBMADM_SRCS:%=kbmadm/%)

KBMADM_OBJS = $(KBMADM_SRCS:%.c=%.o)

_KBMD_SRCS =		\
	door.c		\
	kbmd.c		\
	plugin.c	\
	zfs_box.c	\
	zfs_unlock.c	\
	zpool_create.c
KBMD_SRCS =	$(_KBMD_SRCS:%=kbmd/%)
KBMD_OBJS =	$(KBMD_SRCS:%.c=%.o)
KBMD_LIBS =		\
	out/pivy.a	\
	$(LIBCRYPTO)	\
	-lsmbios	\
	-lzfs		\
	-lbunyan	\
	-luuid		\
	-lscf		\
	-lz		\
	-lpcsclite
out/kbmd:	LDLIBS += $(KBMD_LIBS)

_LIBSSH_OBJS = 			\
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
LIBSSH_OBJS = $(_LIBSSH_OBJS:%=pivy/libssh/%)

_SSS_OBJS =		\
	hazmat.o	\
	randombytes.o
SSS_OBJS = $(_SSS_OBJS:%=pivy/sss/%)

_CHAPOLY_OBJS =		\
	chacha.o	\
	poly1305.o
CHAPOLY_OBJS = $(_CHAPOLY_OBJS:%=pivy/chapoly/%)

_ED25519_OBJS =		\
	blocks.o	\
	ed25519.o	\
	fe25519.o	\
	ge25519.o	\
	hash.o		\
	sc25519.o
ED25519_OBJS = $(_ED25519_OBJS:%=pivy/ed25519/%)

# NOTE: errf.c is included within the kbmd/kbmadm common objs
# The pivy sources are only included within kbmd
_PIVY_OBJS =			\
	debug.o			\
	ebox.o			\
	piv.o			\
	tlv.o
PIVY_OBJS = $(_PIVY_OBJS:%=pivy/%)

PIVY_A_OBJS =		\
	$(PIVY_OBJS)	\
	$(SSS_OBJS)	\
	$(LIBSSH_OBJS)	\
	$(CHAPOLY_OBJS)	\
	$(ED25519_OBJS)

#
# Build Targets
#

.PHONY: all world
world: all
all: pivy-stamp $(STATIC_LIBS) $(PROGS)

out:
	-mkdir out

$(PROGS) $(STATIC_LIBS): out

pivy-stamp:
	$(MAKE) -C pivy \
	    CC=$(CC) \
	    PROTO_AREA="$(DESTDIR)" \
	    PCSC_CFLAGS="-I$(DESTDIR)/usr/include/PCSC" \
	    PCSC_LIBS="-L$(DESTDIR)/usr/lib/amd64 -lpcsclite" \
	    CRYPTO_FLAGS="-I$(DESTDIR)/usr/include" \
	    CRYPTO_LIBS="$(LIBCRYPTO)" \
	    LIBRESSL_INC="$(DESTDIR)/usr/include" \
	    LIBCRYPTO="$(LIBCRYPTO)" \
	    $(PIVY_TARGETS)
	touch pivy-stamp

out/common.a: $(COMMON_OBJS)
	$(AR) -cr $@ $(COMMON_OBJS)

$(PIVY_A_OBJS): pivy-stamp
out/pivy.a: pivy-stamp $(PIVY_A_OBJS)
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
	$(CC) -o $@ $(CFLAGS) $(KBMADM_OBJS) $(LDFLAGS) $(LDLIBS)
	$(CTFCONVERT) $@

out/kbmd: $(KBMD_OBJS) $(STATIC_LIBS)
	$(CC) -o $@ $(CFLAGS) $(KBMD_OBJS) $(LDFLAGS) $(LDLIBS)
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

clean:
	rm -f $(COMMON_OBJS) $(KBMADM_OBJS) $(KBMD_OBJS) pivy-stamp out/*
	-rmdir out
	(cd pivy; $(MAKE) clean)
