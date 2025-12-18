#!/bin/bash
echo 50|sudo tee /proc/sys/vm/dirty_ratio
cd fio-sequential && ./run.sh && cd ..
cd fio-rand && ./run.sh && cd ..
cd tar && ./run.sh && cd ..
cd filebench && ./run.sh && cd ..
cd rocksdb && ./run.sh && cd ..
cd fault-injection && ./run.sh && cd ..
./run_bento.sh
./run_ext4.sh

