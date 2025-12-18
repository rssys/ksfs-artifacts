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
#include <sys/stat.h>

void read_file(const char *filename, std::vector<uint8_t> &data) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("open wasm moodule: " + std::string(strerror(errno)));
    }
    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        throw std::runtime_error("lseek: " + std::string(strerror(errno)));
    }
    data.resize(size);
    if (pread(fd, data.data(), size, 0) != size) {
        throw std::runtime_error("pread: " + std::string(strerror(errno)));
    }
    close(fd);
}

struct wasm_instantiate_args {
    const char **argv;
    const char **envp;
    const char **preopens;
};

struct WasmModule {
    WasmModule(const std::vector<uint8_t> &data) {
        mid = syscall(451, 0, data.data(), data.size());
        if (mid == -1) {
            throw std::runtime_error("wasm load: " + std::string(strerror(errno)));
        }
    }
    ~WasmModule() {
        if (mid == -1) {
            syscall(451, 1, mid);
        }
    }
    int mid = -1;
};

struct WasmInstance {
    WasmInstance(WasmModule &mod,
                 const std::vector<std::string> &argv,
                 const std::vector<std::string> &env,
                 const std::vector<std::string> &preopen) {
        std::vector<const char *> pargv, penv, ppreopen;
        for (const std::string &s: argv) {
            pargv.push_back(s.c_str());
        }
        pargv.push_back(nullptr);
        for (const std::string &s: env) {
            penv.push_back(s.c_str());
        }
        penv.push_back(nullptr);
        for (const std::string &s: preopen) {
            ppreopen.push_back(s.c_str());
        }
        ppreopen.push_back(nullptr);
        struct wasm_instantiate_args wargs = {
            pargv.data(), penv.data(), ppreopen.data()
        };
        fd = syscall(451, 3, mod.mid, &wargs);
        if (fd == -1) {
            throw std::runtime_error("wasm inst: " + std::string(strerror(errno)));
        }
    }
    ~WasmInstance() {
        if (fd != -1) {
            close(fd);
        }
    }
    int fd = -1;
};

struct Device {
    Device(const char *dev, bool ro) {
        fd = open(dev, ro ? O_RDONLY : O_RDWR);
        if (fd == -1) {
            throw std::runtime_error("failed to open device: " + std::string(strerror(errno)));
        }
        struct stat buf;
        if (fstat(fd, &buf) == -1) {
            throw std::runtime_error("fstat device: " + std::string(strerror(errno)));
        }
        is_blk = S_ISBLK(buf.st_mode);
        is_ro = ro;
    }
    void dup(int new_fd) {
        if (dup2(fd, new_fd) == -1) {
            throw std::runtime_error("dup: " + std::string(strerror(errno)));
        }
    }
    ~Device() {
        if (fd != -1) {
            close(fd);
        }
    }
    int fd = -1;
    bool is_blk = false;
    bool is_ro = false;
};
