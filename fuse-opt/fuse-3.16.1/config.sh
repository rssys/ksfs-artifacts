#!/bin/bash
meson setup build
meson configure -D default_library=static -D prefix=`realpath ../lib` build
