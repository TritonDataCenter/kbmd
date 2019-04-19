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
LIBCRYPTO =	$(DESTDIR)/lib/amd64/libsunw_crypto.a
INSTALL =	/usr/sbin/install

PROGS =		kbmd kbmadm
PIVY_TARGETS =	pivy-tool pivy-box

#
# Build Targets
#

.PHONY: all world
world: all
all: pivy-stamp


#
# Install Targets
#
.PHONY: install manifest
install: all
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-tool
	$(INSTALL) -m 0555 -f $(DESTDIR)/usr/sbin pivy/pivy-box

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
	rm -f $(PROGS) $(OBJS) pivy-stamp
	(cd pivy; $(MAKE) -f ../Makefile.pivy clean)
