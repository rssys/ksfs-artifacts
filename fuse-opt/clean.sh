#!/bin/bash
rm -rf lib/* fuse-3.16.1/build
cd ntfs; make distclean; cd ..
cd exfat; make distclean; cd ..
