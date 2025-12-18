#!/bin/bash
source ../env.sh
mkdir -p ../results/fio-rand/
for FS in {ext4,}
do
    sudo ../../drivers/mount.sh native $FS $KSFS_DEVICE $KSFS_MNT --mkfs
    FILENAME=$KSFS_MNT/test_file
    for i in {0..195}
    do
        sudo dd if=/dev/zero of=$FILENAME.$i.0 bs=2M count=1024
    done
    sync
    sudo umount $KSFS_MNT
    for N in {0..10}
    do
        ./run_one.sh native $FS $KSFS_DEVICE $KSFS_MNT $N
    done
done
