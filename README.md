# kSFS Artifacts
This repository contaisn the artifacts for the paper submission.

## Structure
The artifacts contain the following parts:
* `linux-6.1.38`: the Linux kernel with kSFS kernel driver.
* `ksfs`: Code and build toolchain for kSFS file systems.
* `fuse`: FUSE file systems.
* `fuse-opt`: FUSE file systems with zero-copy optimization.
* `bento`: Bento kernel driver and exFAT implementation.
* `experiments`: Experiment scripts and results.
* `drivers`: Built binaries for file systems and kernel drivers.

## Environment Setup
To run the experiments, one server with at least a 24-core CPU,
128 GiB RAM, and a NVMe SSD is required. We tested 
the artifacts on Debian 12 and Ubuntu 24.04.
Your user should have root permission without needing to input password.
**We strongly suggest using a new machine without important data
on it to avoid any data loss.**

Run the following command to install the modified kernel and software:

```shell
./install.sh
```

Alternatively, you can manually build the kernel and install required
software following the script. After installation, reboot the server
with the installed kernel, and then run the following command to build
file systems for kSFS and other comparison systems:

```shell
./build.sh
```

## Usage of kSFS exFAT and NTFS file systems
Run the following command to mount a disk with kSFS:
```shell
sudo ./drivers/mount.sh ksfs exfat/ntfs <disk> <mount point>
# Example:
# sudo ./drivers/mount.sh ksfs ntfs /dev/nvme0n1p1 /mnt
```

## Experiments

Edit `experiments/env.sh` to change the variable
`KSFS_DEVICE` to your SSD partition's device file
and `KSFS_MNT` to the mount point for the experiments.
Please note that the device and the mount point's data
will get lost.

Run the command `./run.sh` in `experiments` to automatically
run all the experiments. You can also run them manually
following its content. This repository contains
the raw data collected during the experiments in `results`.
If you need to run by yourself, please remove the `results`
directory to avoid conflicts.

To generate the table and figures, run the following commands
in `experiments/figures`:
```shell
sudo apt install -y msttcorefonts python3-pip # Install pip and fonts for figures
pip3 install pandas matplotlib --break-system-packages # Install libraries
python3 fio-sequential.py # Generating Tab.4
python3 fio-rand.py # Generating fig-fio-rand.pdf for Fig.3
python3 filebench.py # Generating fig-filebench.pdf for Fig.4
python3 tar.py # Generating fig-tar.pdf for Fig.5
python3 rocksdb.py # Generating fig-rocksdb.pdf for Fig.6
```

To check the fault isolation experiments, check the outputs with the following commands in `experiments/results/fault-injection`:
```shell
cat div_zero
cat infinite_loop
cat invalid_pointer
cat stack_overflow
```

All outputs should contain `fault caught`.
