#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/lsm_hook_defs.h>
#include <linux/file.h>
#include <linux/dcache.h> // For dentry
#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct { 
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(size, 256 * 1024); 
} rb SEC(".maps");

struct event {
    pid_t pid;
    uid_t uid;
    int fd;
    int op_type; // 0: open, 1: flock, 2: fcntl
    int flags; // For open
    int cmd; // For fcntl
    char comm[TASK_COMM_LEN];

};



// Hook for file_open (O_EXCL detection)
SEC("lsm/file_open")
int BPF_PROG(ghostlock_file_open, struct file *file, int mask)
{
    struct event *event;
    int flags = file->f_flags;

    if (!(flags & O_EXCL)) {
        return 0; // Not an exclusive open
    }

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->fd = file->f_fd;
    event->op_type = 0; // open
    event->flags = flags;
    event->cmd = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));


    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook for file_lock (flock and fcntl locks)
SEC("lsm/file_lock")
int BPF_PROG(ghostlock_file_lock, struct file *file, int cmd)
{
    struct event *event;

    // Only interested in exclusive locks (LOCK_EX, F_SETLKW, F_SETLK)
    if (!((cmd & LOCK_EX) || (cmd == F_SETLKW) || (cmd == F_SETLK))) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->fd = file->f_fd;
    event->op_type = 1; // flock or fcntl
    event->flags = 0;
    event->cmd = cmd;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));


    bpf_ringbuf_submit(event, 0);
    return 0;
}
