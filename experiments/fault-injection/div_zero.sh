#!/bin/bash
source ../env.sh
mkdir -p ../results/fault-injection
OUTPUT_FILE=../results/fault-injection/div_zero
sudo dmesg -C
$(sudo ../../drivers/bin/mount_ksfs_fault $KSFS_MNT ../../ksfs/fault-injection/div_zero.aot -1 &> $OUTPUT_FILE)
sudo dmesg >> $OUTPUT_FILE
if grep -qE "wasm exception: Exception: integer divide by zero" $OUTPUT_FILE; then
    echo "fault caught" | tee -a $OUTPUT_FILE
fi