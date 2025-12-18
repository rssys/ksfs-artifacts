#include <vector>
#include <string>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include "mount.h"

#define WASM_IOCTL_TYPE		0xE6
#define WASM_IOCTL_KILL		_IO(WASM_IOCTL_TYPE, 0x00)

int main(int argc, char **argv) {
    const char *mnt = argv[1];
    const char *wasm = argv[2];
    int timeout = atoi(argv[3]);
    std::vector<uint8_t> wasm_module;
    read_file(wasm, wasm_module);
    WasmModule mod(wasm_module);
    WasmInstance inst(mod, {"run"}, {}, {});
    std::string mo_option = "rootmode=0040000,user_id=0,group_id=0,allow_other,default_permissions,fd=";
    mo_option += std::to_string(inst.fd);
    std::unique_ptr<std::thread> th;
    std::mutex mutex;
    std::condition_variable cv;
    bool success = false;
    if (timeout != -1) {
        th.reset(new std::thread([&] {
            std::unique_lock<std::mutex> lock(mutex);
            if (!cv.wait_for(lock, std::chrono::seconds(timeout), [&] {
                return success;
            })) {
                ioctl(inst.fd, WASM_IOCTL_KILL);
            }
        }));
    }
    int res = mount(nullptr, mnt, "fuse", 0, mo_option.c_str());
    success = true;
    cv.notify_one();
    if (th) {
        th->join();
    }
    if (res == -1) {
        throw std::runtime_error("mount: " + std::string(strerror(errno)));
    }
    return 0;
}
