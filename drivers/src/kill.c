#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/ioctl.h>
#define WASM_IOCTL_TYPE		0xE6
#define WASM_IOCTL_KILL		_IO(WASM_IOCTL_TYPE, 0x00)

int main(int argc, char **argv) {
    int pid = atoi(argv[1]);
    int fd = atoi(argv[2]);
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    assert(pidfd != -1);
    int pfd = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
    assert(pfd != -1);
    int res = ioctl(pfd, WASM_IOCTL_KILL);
    assert(res == 0);
    return 0;
}
