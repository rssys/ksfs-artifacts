OBJS = lowfuse/main.o libexfat/cluster.o libexfat/io.o libexfat/log.o libexfat/lookup.o \
	libexfat/mount.o libexfat/node.o libexfat/repair.o libexfat/time.o \
	libexfat/utf.o libexfat/utils.o
CC=../toolchain/wasi-sdk/bin/clang
CFLAGS=-I../libfuse/include -I../libfuse/compat -I./libexfat -mbulk-memory -DHAVE_CONFIG_H -DFUSE_USE_VERSION=30 -D_FILE_OFFSET_BITS=64 -O3
WAMRC=../toolchain/wasm-micro-runtime/wamr-compiler/build/wamrc
MEMSIZE=268435456
MAXSIZE=268435456
exfat.aot: exfat.wasm
	$(WAMRC) -o exfat.aot --enable-segue --stack-bounds-checks=1  --bounds-checks=0 --disable-simd  --target=x86_64 --cpu=znver3 --cpu-features=+soft-float,-sse,-mmx,-avx exfat.wasm
exfat.wasm: $(OBJS) ../libfuse/libfuse.a
	$(CC) $(OBJS) ../libfuse/libfuse.a -z stack-size=1048576 \
		-Wl,--export=__heap_base,--export=__data_end \
		-Wl,--initial-memory=$(MEMSIZE) -Wl,--max-memory=$(MAXSIZE) \
		-Wl,--export=malloc -Wl,--export=free -o exfat.wasm
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f $(OBJS) exfat.wasm exfat.aot