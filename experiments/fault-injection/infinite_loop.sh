#!/bin/bash
source ../env.sh
mkdir -p ../results/fault-injection
OUTPUT_FILE=../results/fault-injection/infinite_loop
sudo dmesg -C
$(sudo ../../drivers/bin/mount_ksfs_fault $KSFS_MNT ../../ksfs/fault-injection/infinite_loop.aot 5 &> $OUTPUT_FILE)
sudo dmesg >> $OUTPUT_FILE
if grep -qE "wasm exception: Exception: wasm instance killed" $OUTPUT_FILE; then
    echo "fault caught" | tee -a $OUTPUT_FILE
fi