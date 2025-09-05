// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <zmq.h>
#include "pingdelay_demo.skel.h"

typedef uint32_t u32;
static volatile bool exiting = false;

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    int type;   // 0=execve, 1=openat, 2=read, 3=write, 4=close, 5=unlink, 6=chmod, 7=chown
    int flags;  // 参数/模式
};

// 日志文件指针
static FILE *execve_fp = NULL;
static FILE *openat_fp = NULL;
static FILE *read_fp = NULL;
static FILE *write_fp = NULL;
static FILE *close_fp = NULL;
static FILE *unlink_fp = NULL;
static FILE *chmod_fp = NULL;
static FILE *chown_fp = NULL;

static void sig_handler(int sig) {
    exiting = true;
}

// 写日志的辅助函数
static void write_log(FILE *fp, struct data_t *e, int with_flags) {
    if (!fp) return;
    if (with_flags)
        fprintf(fp, "%ld,%u,%u,%s,%s,%d\n",
                time(NULL), e->pid, e->uid, e->comm, e->filename, e->flags);
    else
        fprintf(fp, "%ld,%u,%u,%s,%s\n",
                time(NULL), e->pid, e->uid, e->comm, e->filename);
    fflush(fp);
}

// 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct data_t *e = data;
    void **zmq_socket = ctx;

    // 打印到终端
    printf("[type=%d pid=%u uid=%u comm=%s filename=%s flags=%d]\n",
           e->type, e->pid, e->uid, e->comm, e->filename, e->flags);

    // 写入文件
    switch (e->type) {
        case 0: write_log(execve_fp, e, 0); break;
        case 1: write_log(openat_fp, e, 1); break;
        case 2: write_log(read_fp, e, 0); break;
        case 3: write_log(write_fp, e, 0); break;
        case 4: write_log(close_fp, e, 0); break;
        case 5: write_log(unlink_fp, e, 0); break;
        case 6: write_log(chmod_fp, e, 1); break;
        case 7: write_log(chown_fp, e, 0); break;
        default: break;
    }

    // 批处理发送 ZMQ
    static struct data_t batch[10];
    static int count = 0;
    batch[count++] = *e;
    if (count >= 10) {
        for (int i = 0; i < count; i++) {
            char msg[512];
            snprintf(msg, sizeof(msg),
                     "{\"type\":%d,\"pid\":%u,\"uid\":%u,"
                     "\"comm\":\"%s\",\"filename\":\"%s\",\"flags\":%d}",
                     batch[i].type, batch[i].pid, batch[i].uid,
                     batch[i].comm, batch[i].filename, batch[i].flags);
            zmq_send(*zmq_socket, msg, strlen(msg), ZMQ_DONTWAIT);
        }
        count = 0;
    }

    return 0;
}

int main() {
    struct ring_buffer *rb = NULL;
    struct pingdelay_demo_bpf *skel;
    int err;

    // 捕获信号
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 创建日志目录
    mkdir("../ebpf", 0755);

    // 打开文件（覆盖模式）
    execve_fp = fopen("../ebpf/execve_events.log", "w");
    openat_fp = fopen("../ebpf/openat_events.log", "w");
    read_fp   = fopen("../ebpf/read_events.log", "w");
    write_fp  = fopen("../ebpf/write_events.log", "w");
    close_fp  = fopen("../ebpf/close_events.log", "w");
    unlink_fp = fopen("../ebpf/unlink_events.log", "w");
    chmod_fp  = fopen("../ebpf/chmod_events.log", "w");
    chown_fp  = fopen("../ebpf/chown_events.log", "w");


    if (!execve_fp || !openat_fp || !read_fp || !write_fp ||
        !close_fp || !unlink_fp || !chmod_fp || !chown_fp) {
        fprintf(stderr, "Failed to open one or more log files\n");
        return 1;
    }

    // ZeroMQ 初始化
    void *context = zmq_ctx_new();
    void *socket = zmq_socket(context, ZMQ_PUSH);
    zmq_connect(socket, "ipc:///tmp/neurobpf-events");

    // 加载 eBPF skeleton
    skel = pingdelay_demo_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = pingdelay_demo_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skeleton: %d\n", err);
        goto cleanup;
    }

    err = pingdelay_demo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &socket, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Tracing syscalls... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    pingdelay_demo_bpf__destroy(skel);

    // 关闭文件
    if (execve_fp) fclose(execve_fp);
    if (openat_fp) fclose(openat_fp);
    if (read_fp) fclose(read_fp);
    if (write_fp) fclose(write_fp);
    if (close_fp) fclose(close_fp);
    if (unlink_fp) fclose(unlink_fp);
    if (chmod_fp) fclose(chmod_fp);
    if (chown_fp) fclose(chown_fp);

    zmq_close(socket);
    zmq_ctx_term(context);
    return 0;
}
