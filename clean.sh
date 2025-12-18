#!/bin/bash
cd ksfs && ./clean.sh && cd ..
cd fuse && ./clean.sh && cd ..
cd fuse-opt && ./clean.sh && cd ..
cd drivers && make clean && cd ..
cd bento && ./clean.sh && cd ..
