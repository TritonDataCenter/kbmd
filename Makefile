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
INSTALL =	/usr/sbin/install

PROGS =		kbmd kbmadm
PIVY_TARGETS =	pivy-tool pivy-box

CPPFLAGS =	-I$(DESTDIR)/usr/include -Icommon
CFLAGS =	-g -msave-args -m64 -std=gnu99 -fstack-protector-all
LDFLAGS =	-L$(DESTDIR)/lib/amd64 -L$(DESTDIR)/usr/lib/amd64
LDLIBS =	-lumem -lssp -lcustr -lnvpair

COMMON_SRCS = \
	common/common.c \
	common/ecustr.c \
	common/envlist.c \
	common/kspawn.c \
	pivy/errf.c

COMMON_OBJS = $(COMMON_SRCS:%.c=%.o)

KBMADM_SRCS = \
	kbmadm/kbmadm.c

KBMADM_OBJS = $(KBMADM_SRCS:%.c=%.o)

#
# Build Targets
#

.PHONY: all world
world: all
all: pivy-stamp out/common.a $(PROGS:%=out/%)

out:
	-mkdir out

$(PROGS:%=out/%) out/common.a: out

out/common.a: $(COMMON_OBJS)
	$(AR) -r $@ $(COMMON_OBJS)

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

out/kbmd: $(KBMD_OBJS) out/common.a

#
# Install Targets
#
.PHONY: install manifest
install: all
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-tool
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-box
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin out/kbmadm

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
	    touch pivy-stamp)

clean:
	rm -f out $(COMMON_OBJS) $(KBMADM_OBJS) pivy-stamp
	(cd pivy; $(MAKE) clean)
