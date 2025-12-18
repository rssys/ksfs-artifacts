#pragma once
#include <fcntl.h>

#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7
inline static int getuid(void) {
	return 0;
}
inline static int getgid(void) {
	return 0;
}
#define S_BLKSIZE 512

#define LINUX_O_RDONLY		00000000
#define LINUX_O_WRONLY		00000001
#define LINUX_O_RDWR		00000002
#define LINUX_O_CREATE		00000100
#define LINUX_O_EXCL		00000200
#define LINUX_O_NOCTTY		00000400
#define LINUX_O_TRUNC		00001000
#define LINUX_O_APPEND		00002000
#define LINUX_O_NONBLOCK	00004000
#define LINUX_O_DSYNC		00010000
#define LINUX_O_DIRECTORY	00200000
#define LINUX_O_NOFOLLOW	00400000
#define LINUX_O_CLOEXEC		02000000
#define LINUX_O_SYNC		04000000

inline static int linux_flags_to_wasi_flags(int flags)
{
	int res = 0;
	switch (flags & 0x3) {
	case LINUX_O_RDONLY: res |= O_RDONLY; break;
	case LINUX_O_WRONLY: res |= O_WRONLY; break;
	case LINUX_O_RDWR: res |= O_RDWR; break;
	}
	if (flags & LINUX_O_CREATE)
		res |= O_CREAT;
	if (flags & LINUX_O_EXCL)
		res |= O_EXCL;
	if (flags & LINUX_O_NOCTTY)
		res |= O_NOCTTY;
	if (flags & LINUX_O_TRUNC)
		res |= O_TRUNC;
	if (flags & LINUX_O_APPEND)
		res |= O_APPEND;
	if (flags & LINUX_O_NONBLOCK)
		res |= O_NONBLOCK;
	if (flags & LINUX_O_DSYNC)
		res |= O_DSYNC;
	//if (flags & 00040000)
	//	res |= O_DIRECT;
	//if (flags & 00100000)
	//	res |= O_LARGEFILE;
	if (flags & LINUX_O_DIRECTORY)
		res |= O_DIRECTORY;
	if (flags & LINUX_O_NOFOLLOW)
		res |= O_NOFOLLOW;
	//if (flags & 01000000)
	//	res |= O_NOATIME;
	if (flags & LINUX_O_CLOEXEC)
		res |= O_CLOEXEC;
	if (flags & LINUX_O_SYNC)
		res |= O_SYNC;
	//if (flags & 010000000)
	//	res |= O_PATH;
	//if (flags & 020000000)
	//	res |= O_TMPFILE;
	return res;
}