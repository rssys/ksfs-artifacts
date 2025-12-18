#!/bin/bash
PKG_CONFIG_LIBDIR=../lib/lib/x86_64-linux-gnu/pkgconfig/ ./configure --with-fuse=external --enable-shared=no --disable-library --disable-ntfsprogs
