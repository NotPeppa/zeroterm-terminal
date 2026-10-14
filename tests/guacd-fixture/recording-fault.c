/* Test-only LD_PRELOAD shim. No payload, filename or credentials are logged. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char root[] = "/var/lib/zeroterm-bastion/recordings";
static _Atomic unsigned long generation;
static _Atomic unsigned int calls;

static int scope(int fd, int directory) {
    char name[64], path[4096];
    snprintf(name, sizeof(name), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(name, path, sizeof(path) - 1);
    if (n < 0) return 0;
    path[n] = '\0';
    return directory ? strcmp(path, root) == 0
        : strncmp(path, root, sizeof(root) - 1) == 0
          && path[sizeof(root) - 1] == '/' && strstr(path, ".ztrec") != NULL;
}

static int mode(char *value) {
    char buffer[128];
    int fd = syscall(SYS_openat, AT_FDCWD, "/fault/control", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    ssize_t n = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buffer[n] = '\0';
    unsigned long next;
    if (sscanf(buffer, "%lu %31s", &next, value) != 2) return 0;
    if (atomic_exchange(&generation, next) != next) atomic_store(&calls, 0);
    return 1;
}

static void hit(const char *operation);
/* Indefinite stall: block until the controller selects another mode, then fail. */
static int stuck(const char *armed, const char *operation) {
    char selected[32];
    hit(operation);
    struct timespec poll = {0, 200000000};
    while (mode(selected) && strcmp(selected, armed) == 0)
        while (nanosleep(&poll, &poll) < 0 && errno == EINTR) {}
    errno = EIO; return -1;
}

static void hit(const char *operation) {
    int saved = errno;
    int fd = syscall(SYS_openat, AT_FDCWD, "/fault/hits", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        syscall(SYS_write, fd, operation, strlen(operation));
        syscall(SYS_write, fd, "\n", 1);
        syscall(SYS_close, fd);
    }
    errno = saved;
}

int openat(int fd, const char *path, int flags, ...) {
    mode_t permissions = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); permissions = va_arg(args, mode_t); va_end(args);
    }
    char selected[32];
    if ((flags & O_CREAT) && scope(fd, 1) && strstr(path, ".ztrec")
        && mode(selected) && strcmp(selected, "open") == 0) {
        hit("open EACCES"); errno = EACCES; return -1;
    }
    int (*next)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    return next(fd, path, flags, permissions);
}

ssize_t write(int fd, const void *bytes, size_t length) {
    ssize_t (*next)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    char selected[32];
    if (scope(fd, 0) && mode(selected)) {
        if (strcmp(selected, "write") == 0) {
            hit("write EIO"); errno = EIO; return -1;
        }
        if (strcmp(selected, "short-write") == 0) {
            if (atomic_fetch_add(&calls, 1) == 0 && length > 1) {
                hit("write partial"); return next(fd, bytes, 1);
            }
            hit("write EIO after partial"); errno = EIO; return -1;
        }
        if (strcmp(selected, "stuck-write") == 0) return stuck("stuck-write", "write stuck until released");
        if (strcmp(selected, "blocked-write") == 0 && atomic_fetch_add(&calls, 1) == 0) {
            hit("write blocked 8s");
            struct timespec delay = {8, 0}; while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        }
    }
    return next(fd, bytes, length);
}

int fsync(int fd) {
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    char selected[32];
    if ((scope(fd, 0) || scope(fd, 1)) && mode(selected)) {
        if ((strcmp(selected, "file-fsync") == 0 && scope(fd, 0))
            || (strcmp(selected, "dir-fsync") == 0 && scope(fd, 1))) {
            hit("fsync EIO"); errno = EIO; return -1;
        }
        if (strcmp(selected, "stuck-fsync") == 0 && scope(fd, 0)) return stuck("stuck-fsync", "fsync stuck until released");
        if (strcmp(selected, "blocked-fsync") == 0 && scope(fd, 0)
            && atomic_fetch_add(&calls, 1) == 0) {
            hit("fsync blocked 8s");
            struct timespec delay = {8, 0}; while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        }
    }
    return next(fd);
}
