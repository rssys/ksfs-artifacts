#!/bin/bash
PKG_CONFIG_LIBDIR=../lib/lib/x86_64-linux-gnu/pkgconfig/ ./configure
make -C libexfat -j
make -C lowfuse -j
