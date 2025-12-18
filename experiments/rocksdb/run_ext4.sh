#!/bin/bash
source ../env.sh
mkdir -p ../results/rocksdb/
for N in {1..10}
do
    ./run_one.sh native ext4 $KSFS_DEVICE $KSFS_MNT $N
done
sudo umount $KSFS_MNT
