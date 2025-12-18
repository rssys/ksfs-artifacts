#!/bin/bash
cd fuse-3.16.1
rm -rf build
./config.sh
ninja -C build
ninja -C build install
cd ../ntfs
./config.sh
make -j
cp src/lowntfs-3g ../../drivers/bin/lowntfs-3g-opt
cd ../exfat
./build.sh
cp lowfuse/mount.exfat-lowfuse ../../drivers/bin/mount.exfat-lowfuse-opt
cd ..