#!/bin/bash
source ../env.sh
mkdir -p ../results/fio-sequential/
for FS in {ext4,}
do
    sudo ../../drivers/mount.sh native $FS $KSFS_DEVICE $KSFS_MNT --mkfs
    FILENAME=$KSFS_MNT/test_file
    sudo dd if=/dev/zero of=$FILENAME.0.0 bs=4M count=32768
    sync
    sudo umount $KSFS_MNT
    for N in {1..10}
    do
        ./run_one.sh native $FS $KSFS_DEVICE $KSFS_MNT $N
    done
done
