// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_PATH 256

enum event_type
{
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
};

struct event_hdr
{
    u32 type;
    u32 size;
};
struct proc_info
{
    struct event_hdr hdr;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 _pad; // padding for alignment
    char proc_path[MAX_PATH];
    u64 timestamp_ns;
};

struct openat_info
{
    struct event_hdr hdr;
    u32 pid;
    u32 _pad; // padding for alignment
    char filename[MAX_PATH];
    int64_t dirfd;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb_event SEC(".maps");

/*
/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
name: sys_enter_execve
ID: 786
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    field:const char * filename;	offset:16;	size:8;	signed:0;
    field:const char *const * argv;	offset:24;	size:8;	signed:0;
    field:const char *const * envp;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))

*/
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct proc_info *p_info;
    p_info = bpf_ringbuf_reserve(&rb_event, sizeof(struct proc_info), 0);
    if (!p_info)
    {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 1;
    }

    p_info->pid = (unsigned int)bpf_get_current_pid_tgid();
    p_info->uid = (unsigned int)bpf_get_current_uid_gid();
    p_info->ppid = BPF_CORE_READ(task, real_parent, pid);
    p_info->timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&p_info->proc_path, sizeof(p_info->proc_path), (const char *)ctx->args[0]);

    p_info->hdr.type = EVENT_EXECVE;
    p_info->hdr.size = sizeof(*p_info);

    bpf_ringbuf_submit(p_info, 0); // make it available to userspace
    return 0;
}
/*
 name: sys_enter_openat
ID: 706
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    field:int dfd;	offset:16;	size:8;	signed:0;
    field:const char * filename;	offset:24;	size:8;	signed:0;
    field:int flags;	offset:32;	size:8;	signed:0;
    field:umode_t mode;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))*/

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    struct openat_info *openat_info;

    openat_info = bpf_ringbuf_reserve(&rb_event, sizeof(struct openat_info), 0);
    if (!openat_info)
    {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 1;
    }

    openat_info->pid = (unsigned int)bpf_get_current_pid_tgid();

    bpf_probe_read_user_str(openat_info->filename, sizeof(openat_info->filename), (const char *)ctx->args[1]);
    openat_info->dirfd = (int)ctx->args[0];

    openat_info->hdr.type = EVENT_OPENAT;
    openat_info->hdr.size = sizeof(*openat_info);
    bpf_ringbuf_submit(openat_info, 0);

    return 0;
}