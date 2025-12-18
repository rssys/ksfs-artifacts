#!/bin/bash
cd libfuse && make -j && cd ..
cd ntfs && make -j && cd ..
cd exfat && make -j && cd ..
cd fault-injection && make -j && cd ..
cp ntfs/ntfs.aot exfat/exfat.aot ../drivers
