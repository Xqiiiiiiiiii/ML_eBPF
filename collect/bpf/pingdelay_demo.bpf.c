// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct data_t {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
    int type;   // 0=execve, 1=openat, 2=read, 3=write, 4=close,
                // 5=unlink, 6=chmod, 7=chown
    int flags;  // openat 用
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

/// ---------------- execve ----------------
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data)
        return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename),
                            (void *)ctx->args[0]);
    data->type = 0;
    data->flags = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- openat ----------------
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    /* openat: args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode */
    bpf_probe_read_user_str(data->filename, sizeof(data->filename),
                            (const void *)ctx->args[1]);

    data->type = 1; /* openat */
    data->flags = (int)ctx->args[2];

    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- read ----------------
SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 2;
    data->filename[0] = '\0';
    data->flags = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- write ----------------
SEC("kprobe/__x64_sys_write")
int handle_write(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data)
        return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    data->type = 3;
    data->filename[0] = '\0'; // write 没有 filename
    data->flags = 0;

    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- close ----------------
SEC("kprobe/__x64_sys_close")
int handle_close(struct pt_regs *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data)
        return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    data->type = 4;
    data->filename[0] = '\0';
    data->flags = 0;

    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- unlink ----------------
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    /* unlinkat(dirfd, pathname, flags) -> pathname is args[1] */
    bpf_probe_read_user_str(data->filename, sizeof(data->filename),
                            (const void *)ctx->args[1]);

    data->type = 5; /* unlink */
    data->flags = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- chmod ----------------
SEC("tracepoint/syscalls/sys_enter_chmod")
int tp_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    /* chmod(pathname, mode) -> pathname args[0], mode args[1] */
    bpf_probe_read_user_str(data->filename, sizeof(data->filename),
                            (const void *)ctx->args[0]);
    data->type = 6;
    data->flags = (int)ctx->args[1]; /* mode */

    bpf_ringbuf_submit(data, 0);
    return 0;
}

/// ---------------- chown ----------------
SEC("tracepoint/syscalls/sys_enter_chown")
int tp_chown(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    /* chown(pathname, owner, group) -> pathname args[0] */
    bpf_probe_read_user_str(data->filename, sizeof(data->filename),
                            (const void *)ctx->args[0]);

    data->type = 7;
    data->flags = 0;
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
