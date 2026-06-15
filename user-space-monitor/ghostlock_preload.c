#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h> // For getpid and readlink
#include <limits.h> // For PATH_MAX
#include <time.h>   // For timestamp

// Original functions
typedef int (*orig_open_f_type)(const char *pathname, int flags, ...);
typedef int (*orig_openat_f_type)(int dirfd, const char *pathname, int flags, ...);
typedef int (*orig_flock_f_type)(int fd, int operation);
typedef int (*orig_fcntl_f_type)(int fd, int cmd, ...);
typedef ssize_t (*orig_read_f_type)(int fd, void *buf, size_t count);
typedef ssize_t (*orig_write_f_type)(int fd, const void *buf, size_t count);
typedef int (*orig_close_f_type)(int fd);

// Function pointers for original functions
static orig_open_f_type orig_open = NULL;
static orig_openat_f_type orig_openat = NULL;
static orig_flock_f_type orig_flock = NULL;
static orig_fcntl_f_type orig_fcntl = NULL;
static orig_read_f_type orig_read = NULL;
static orig_write_f_type orig_write = NULL;
static orig_close_f_type orig_close = NULL;

#define LOG_FILE "/tmp/ghostlock_detector.log"

// Function to log events
void log_event(const char *event_type, const char *file_path, pid_t pid) {
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t rawtime;
        struct tm *info;
        char timestamp[80];

        time(&rawtime);
        info = localtime(&rawtime);
        strftime(timestamp, 80, "%Y-%m-%d %H:%M:%S", info);

        fprintf(f, "%s | %s | %s | %d\n", timestamp, event_type, file_path, pid);
        fflush(f);
        fclose(f);
    }
}

// Helper to get path from fd
void get_path_from_fd(int fd, char *actual_path, size_t max_len) {
    char fd_path[PATH_MAX];
    ssize_t len = snprintf(fd_path, PATH_MAX, "/proc/self/fd/%d", fd);
    if (len > 0 && len < PATH_MAX) {
        len = readlink(fd_path, actual_path, max_len - 1);
        if (len != -1) {
            actual_path[len] = '\0';
            return;
        }
    }
    strncpy(actual_path, "unknown_path", max_len);
}

// Initialization function
static void __attribute__((constructor)) init(void) {
    orig_open = (orig_open_f_type) dlsym(RTLD_NEXT, "open");
    orig_openat = (orig_openat_f_type) dlsym(RTLD_NEXT, "openat");
    orig_flock = (orig_flock_f_type) dlsym(RTLD_NEXT, "flock");
    orig_fcntl = (orig_fcntl_f_type) dlsym(RTLD_NEXT, "fcntl");
    orig_read = (orig_read_f_type) dlsym(RTLD_NEXT, "read");
    orig_write = (orig_write_f_type) dlsym(RTLD_NEXT, "write");
    orig_close = (orig_close_f_type) dlsym(RTLD_NEXT, "close");

    if (!orig_open || !orig_openat || !orig_flock || !orig_fcntl || !orig_read || !orig_write || !orig_close) {
        fprintf(stderr, "LD_PRELOAD: Error in dlsym: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

// Intercepted open function
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (flags & O_EXCL) {
        log_event("O_EXCL_OPEN", pathname, getpid());
    }

    return orig_open(pathname, flags, mode);
}

// Intercepted openat function
int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (flags & O_EXCL) {
        log_event("O_EXCL_OPENAT", pathname, getpid());
    }

    return orig_openat(dirfd, pathname, flags, mode);
}

// Intercepted flock function
int flock(int fd, int operation) {
    if (operation & LOCK_EX) {
        char actual_path[PATH_MAX];
        get_path_from_fd(fd, actual_path, sizeof(actual_path));
        log_event("LOCK_EX_FLOCK", actual_path, getpid());
    }
    return orig_flock(fd, operation);
}

// Intercepted fcntl function
int fcntl(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    long arg = va_arg(args, long);
    va_end(args);

    if (cmd == F_SETLKW || cmd == F_SETLK) {
        struct flock *lk = (struct flock *)arg;
        if (lk && lk->l_type == F_WRLCK) {
            char actual_path[PATH_MAX];
            get_path_from_fd(fd, actual_path, sizeof(actual_path));
            log_event("F_WRLCK_FCNTL", actual_path, getpid());
        }
    }
    return orig_fcntl(fd, cmd, arg);
}

// Intercepted read function
ssize_t read(int fd, void *buf, size_t count) {
    ssize_t ret = orig_read(fd, buf, count);
    if (ret > 0) {
        char actual_path[PATH_MAX];
        get_path_from_fd(fd, actual_path, sizeof(actual_path));
        // Only log if it's not a standard stream to avoid log spam
        if (fd > 2) {
            log_event("READ", actual_path, getpid());
        }
    }
    return ret;
}

// Intercepted write function
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t ret = orig_write(fd, buf, count);
    if (ret > 0) {
        char actual_path[PATH_MAX];
        get_path_from_fd(fd, actual_path, sizeof(actual_path));
        // Only log if it's not a standard stream and not the log file itself
        if (fd > 2 && strstr(actual_path, "ghostlock_detector.log") == NULL) {
            log_event("WRITE", actual_path, getpid());
        }
    }
    return ret;
}

// Intercepted close function
int close(int fd) {
    if (fd > 2) {
        char actual_path[PATH_MAX];
        get_path_from_fd(fd, actual_path, sizeof(actual_path));
        if (strstr(actual_path, "ghostlock_detector.log") == NULL) {
            log_event("CLOSE", actual_path, getpid());
        }
    }
    return orig_close(fd);
}
