#!/bin/bash
echo 50|sudo tee /proc/sys/vm/dirty_ratio
cd fio-sequential && ./run_bento.sh && cd ..
cd fio-rand && ./run_bento.sh && cd ..
cd tar && ./run_bento.sh && cd ..
cd filebench && ./run_bento.sh && cd ..
cd rocksdb && ./run_bento.sh && cd ..

