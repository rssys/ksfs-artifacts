all: bin bin/mount_ksfs_ntfs bin/mount_ksfs_exfat bin/mount_ksfs_fault bin/kill
bin:
	mkdir -p bin
bin/mount_ksfs_exfat: src/mount_ksfs_exfat.cc src/mount.h bin
	g++ -O3 src/mount_ksfs_exfat.cc -o bin/mount_ksfs_exfat
bin/mount_ksfs_ntfs: src/mount_ksfs_ntfs.cc src/mount.h bin
	g++ -O3 src/mount_ksfs_ntfs.cc -o bin/mount_ksfs_ntfs
bin/mount_ksfs_fault: src/mount_ksfs_fault.cc src/mount.h bin
	g++ -O3 src/mount_ksfs_fault.cc -o bin/mount_ksfs_fault
bin/kill: src/kill.c bin
	gcc -O3 src/kill.c -o bin/kill
clean:
	rm -f bin/mount_ksfs_ntfs bin/mount_ksfs_exfat bin/kill exfat.aot ntfs.aot bin/lowntfs-3g \
	bin/lowntfs-3g-opt bin/mount.exfat-lowfuse bin/mount.exfat-lowfuse-opt bin/mount_ksfs_fault \
	bentofs.ko bento_exfat.ko
