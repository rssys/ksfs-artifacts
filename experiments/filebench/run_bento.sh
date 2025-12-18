#!/bin/bash
source ../env.sh
mkdir -p ../results/filebench/
echo 0 |sudo tee  /proc/sys/kernel/randomize_va_space
for N in {1..10}
do
    ./run_one.sh bento exfat $KSFS_DEVICE $KSFS_MNT $N
done
