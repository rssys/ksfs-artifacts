#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
N=$5

FILENAME=$MNT/test_file
PREFIX=../results/fio-rand/$N-$FS-$TYPE
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT
for T in {1,2,4,6,8,12,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128}
do
    sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
    sudo fio --name=$FILENAME --rw=randread --bs=4k --numjobs=$T --runtime=10 --time_based > $PREFIX-randread-$T.txt
done
for T in {1,2,4,6,8,10,12,14,16}
do
    sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
    sudo fio --name=$FILENAME --rw=randwrite --bs=4k --sync_file_range=write:1 --numjobs=$T --runtime=10 --time_based > $PREFIX-randwrite-$T.txt
done
sudo umount $MNT
