#include <vector>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include "mount.h"

int main(int argc, char **argv) {
    const char *dev = argv[1];
    const char *mnt = argv[2];
    const char *wasm = argv[3];
    Device device(dev, false);
    int new_fd = 0;
    device.dup(new_fd);
    std::vector<uint8_t> wasm_module;
    read_file(wasm, wasm_module);
    WasmModule mod(wasm_module);
    std::string option = "relatime,permissions,default_permissions,delay_mtime=1";
    if (device.is_ro) {
        option += ",ro";
    }
    WasmInstance inst(mod, {
        "run", "-o", option, std::to_string(new_fd), mnt
    }, {}, {});
    std::string mo_option = "rootmode=0040000,user_id=0,group_id=0,allow_other,default_permissions,fd=";
    mo_option += std::to_string(inst.fd);
    if (device.is_blk) {
        mo_option += ",blksize=4096";
    }
    int flags = MS_RELATIME;
    if (device.is_ro) {
        flags |= MS_RDONLY;
    }
    int res = mount(dev, mnt, device.is_blk ? "fuseblk" : "fuse", flags, mo_option.c_str());
    if (res == -1) {
        throw std::runtime_error("mount: " + std::string(strerror(errno)));
    }
    return 0;
}
