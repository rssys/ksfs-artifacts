OBJS = libntfs-3g/acls.o libntfs-3g/attrib.o libntfs-3g/attrlist.o libntfs-3g/bitmap.o \
libntfs-3g/bootsect.o libntfs-3g/cache.o libntfs-3g/collate.o libntfs-3g/compat.o \
libntfs-3g/compress.o libntfs-3g/debug.o libntfs-3g/device.o libntfs-3g/dir.o \
libntfs-3g/ea.o libntfs-3g/efs.o libntfs-3g/index.o libntfs-3g/inode.o \
libntfs-3g/ioctl.o libntfs-3g/lcnalloc.o libntfs-3g/logfile.o libntfs-3g/logging.o \
libntfs-3g/mft.o libntfs-3g/misc.o libntfs-3g/mst.o libntfs-3g/object_id.o \
libntfs-3g/realpath.o libntfs-3g/reparse.o libntfs-3g/runlist.o libntfs-3g/security.o \
libntfs-3g/unistr.o libntfs-3g/unix_io.o libntfs-3g/volume.o libntfs-3g/xattrs.o \
src/lowntfs-3g.o src/ntfs-3g_common.o
CC=../toolchain/wasi-sdk/bin/clang
CFLAGS=-I../libfuse/include -I../libfuse/compat -I. -I./libntfs-3g -I./include/ntfs-3g -mbulk-memory -DHAVE_CONFIG_H -DFUSE_USE_VERSION=30 -D_FILE_OFFSET_BITS=64 -O3
WAMRC=../toolchain/wasm-micro-runtime/wamr-compiler/build/wamrc
MEMSIZE=33554432
MAXSIZE=33554432
ntfs.aot: ntfs.wasm
	$(WAMRC) -o ntfs.aot --enable-segue --stack-bounds-checks=1 --bounds-checks=0 --disable-simd --target=x86_64 --cpu=znver3 --cpu-features=+soft-float,-sse,-mmx,-avx ntfs.wasm
ntfs.wasm: $(OBJS) ../libfuse/libfuse.a
	$(CC) $(OBJS) ../libfuse/libfuse.a -z stack-size=1048576 \
		-Wl,--export=__heap_base,--export=__data_end \
		-Wl,--initial-memory=$(MEMSIZE) -Wl,--max-memory=$(MAXSIZE) \
		-Wl,--export=malloc -Wl,--export=free -o ntfs.wasm
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f $(OBJS) ntfs.wasm ntfs.aot