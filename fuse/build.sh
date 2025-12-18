#!/bin/bash
cd ntfs
./config.sh
make -j
cp src/lowntfs-3g ../../drivers/bin/
cd ../exfat
./configure
make -j
cp lowfuse/mount.exfat-lowfuse ../../drivers/bin/
cd ..