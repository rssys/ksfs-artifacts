CC=../toolchain/wasi-sdk/bin/clang
MEMSIZE=16777216
MAXSIZE=16777216
CFLAGS=../libfuse/libfuse.a -mbulk-memory -O0 -z stack-size=1048576 \
	-Wl,--export=__heap_base,--export=__data_end \
	-Wl,--initial-memory=$(MEMSIZE) -Wl,--max-memory=$(MAXSIZE) \
	-Wl,--export=malloc -Wl,--export=free
WAMRC=../toolchain/wasm-micro-runtime/wamr-compiler/build/wamrc
WAMRC_FLAGS=--enable-segue --stack-bounds-checks=1 --bounds-checks=0 --disable-simd --target=x86_64 --cpu=znver3 --cpu-features=+soft-float,-sse,-mmx,-avx

all: invalid_pointer.aot infinite_loop.aot div_zero.aot stack_overflow.aot
invalid_pointer.wasm: invalid_pointer.c
	$(CC) $(CFLAGS) -o $@ $< 
invalid_pointer.aot: invalid_pointer.wasm
	$(WAMRC) $(WAMRC_FLAGS) -o $@ $<
infinite_loop.wasm: infinite_loop.c
	$(CC) $(CFLAGS) -o $@ $< 
infinite_loop.aot: infinite_loop.wasm
	$(WAMRC) $(WAMRC_FLAGS) -o $@ $<
div_zero.wasm: div_zero.c
	$(CC) $(CFLAGS) -o $@ $< 
div_zero.aot: div_zero.wasm
	$(WAMRC) $(WAMRC_FLAGS) -o $@ $<
stack_overflow.wasm: stack_overflow.c
	$(CC) $(CFLAGS) -o $@ $< 
stack_overflow.aot: stack_overflow.wasm
	$(WAMRC) $(WAMRC_FLAGS) -o $@ $<
clean:
	rm -rf invalid_pointer.wasm invalid_pointer.aot infinite_loop.wasm infinite_loop.aot \
		div_zero.wasm div_zero.aot stack_overflow.wasm stack_overflow.aot
