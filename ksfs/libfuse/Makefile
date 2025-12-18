OBJS = lib/fuse_lowlevel.o lib/buffer.o lib/fuse_log.o lib/fuse_opt.o lib/wasm.o lib/helper.o lib/fuse.o lib/modules/subdir.o lib/modules/iconv.o
CC=../toolchain/wasi-sdk/bin/clang
AR=../toolchain/wasi-sdk/bin/ar
CFLAGS=-Iinclude -Icompat -DFUSE_USE_VERSION=312 -mbulk-memory
libfuse.a: $(OBJS)
	$(AR) rcs libfuse.a $(OBJS)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f $(OBJS) libfuse.a