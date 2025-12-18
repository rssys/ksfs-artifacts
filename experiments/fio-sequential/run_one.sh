#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
N=$5

FILENAME=$MNT/test_file
PREFIX=../results/fio-sequential/$N-$FS-$TYPE
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT
for blk in {4096,}
do
    sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
    sudo fio --name=$FILENAME --rw=write --bs=${blk}k --numjobs=1 --runtime=10 --time_based \
        --fsync=64 > $PREFIX-write-$blk.txt
done

for blk in {4096,}
do
    sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
    sudo fio --name=$FILENAME --rw=read --bs=${blk}k --numjobs=1 --runtime=10 --time_based > $PREFIX-read-$blk.txt
done

sudo umount $MNT
