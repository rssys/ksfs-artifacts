#!/bin/bash
source ../env.sh
mkdir -p ../results/rocksdb/
for N in {1..10}
do
    ./run_one.sh native ntfs $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh ksfs ntfs $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh fuse ntfs $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh fuse-opt ntfs $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh native exfat $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh ksfs exfat $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh fuse exfat $KSFS_DEVICE $KSFS_MNT $N
    ./run_one.sh fuse-opt exfat $KSFS_DEVICE $KSFS_MNT $N
done
sudo umount $KSFS_MNT
