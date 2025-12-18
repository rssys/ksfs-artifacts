#!/bin/bash
source ../env.sh
mkdir -p ../results/pjdfstest
./run_one.sh native ntfs $KSFS_DEVICE $KSFS_MNT $N
./run_one.sh ksfs ntfs $KSFS_DEVICE $KSFS_MNT $N
./run_one.sh fuse ntfs $KSFS_DEVICE $KSFS_MNT $N
sudo umount $KSFS_MNT
