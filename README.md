# kbmd

This repository contains the key backup and management daemon for use on
SmartOS.  As (eventually \*cough\* \*cough\*) described in [RFD77](https://github.com/joyent/rfd/tree/master/rfd/0077).

# Building

This is designed to be built as a local project as a part of [SmartOS](https://github.com/joyent/smartos-live).
Building kbmd standalone is not recommended as it requires several components
from both [illumos-joyent](https://github.com/joyent/illumos-joyent) as well as [illumos-extra](https://github.com/joyent/illumos-extra) to build.

However, there are a number of behaviors during the build process that are
worth pointing out for anyone updating this repository.  The biggest one is
that static linking is employed in a number of places.  This is deliberate--
until it is possible to tell the OS to unshare pages, we want to deliberately
avoid sharing any code pages containg crypto code.  This is to lessen the
ability to mount side-channel attacks against kbmd.  As a result, we statically
link libsunw_crypto.a (the SmartOS platform built OpenSSL library) into kbmd.

There is also a small amount of code that is shared between kbmd and kbmadm.
This is kept in the common/ subdirectory.  Given the rather small amount of
code there, it is compiled and then each object file is linked into kbmd and
kbmadm.  Since there is no crypto code present in common/, in the future, the
code in common/ could be turned into a shared library if needed, but is not
necessary at the present time.

## pivy

To minimize divergence with the pivy tools, it is added as a submodule.  This
allows the use of the same code for dealing with eboxes and boxes, as well as
build the pivy-box and pivy-tool tools as part of the SmartOS platform build.
However, since kbmd is 'cherry-picking' which files to use, not every file of
the pivy source is utilized.  For example, the custr and bunyan files in the
pivy repo are not utilized (while kbmd itself uses libcustr and libbunyan, the
illumos-joyent versions of those libraries are used instead of the pivy ones).
