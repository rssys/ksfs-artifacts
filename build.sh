#!/bin/bash
mkdir drivers/bin
cd ksfs && ./build.sh && cd ..
cd fuse && ./build.sh && cd ..
cd fuse-opt && ./build.sh && cd ..
cd drivers && make -j && cd ..
cd bento && ./build.sh && cd ..
