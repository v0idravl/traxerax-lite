/* SPDX-License-Identifier: GPL-2.0 */
/*
 * traxerax-lite kernel telemetry probe.
 *
 * Behavioral, non-signature-based monitoring for process execution, kernel
 * module loading, BPF program loading, credential changes, fileless
 * execution, log/file deletion, ptrace, mounts, namespace entry, and process
 * exit. Events are emitted to a ring buffer for userspace consumption.
 *
 * IMPORTANT: the EVENT_* constants below must stay in sync with
 * EVENT_TYPE_NAMES in src/traxerax_lite/ebpf_loader.py. When adding a new
 * event type, continue the numbering and update both sides.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

/* Keep in sync with EVENT_TYPE_NAMES in src/traxerax_lite/ebpf_loader.py. */
#define EVENT_EXECVE        1
#define EVENT_MODULE_LOAD   2
#define EVENT_BPF_LOAD      3
#define EVENT_COMMIT_CREDS  4
#define EVENT_MEMFD_CREATE  5
#define EVENT_UNLINK        6
#define EVENT_PTRACE        7
#define EVENT_MOUNT         8
#define EVENT_SETNS         9
#define EVENT_EXIT          10
#define EVENT_RENAME        11

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    struct task_struct *parent;
    parent = BPF_CORE_READ(task, real_parent);
    return parent;
}

static __always_inline void fill_event(struct event *e, __u32 type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = get_parent_task(task);

    e->type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (parent) {
        bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm),
                                  BPF_CORE_READ(parent, comm));
    } else {
        e->parent_comm[0] = '\0';
    }
    e->data[0] = '\0';
}

/* Emit an event whose data payload is a user-space string (syscall args). */
static __always_inline void emit_event(__u32 type, const char *data, __u64 data_len)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    fill_event(e, type);

    if (data && data_len > 0) {
        __u64 len = data_len;
        if (len > sizeof(e->data) - 1)
            len = sizeof(e->data) - 1;
        bpf_probe_read_user_str(&e->data, len, data);
    }

    bpf_ringbuf_submit(e, 0);
}

/* Emit an event whose data payload is a kernel-space string (scratch buffer
 * or __data_loc tracepoint field). Identical to emit_event() except for the
 * read variant.
 */
static __always_inline void emit_event_kdata(__u32 type, const char *data, __u64 data_len)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    fill_event(e, type);

    if (data && data_len > 0) {
        __u64 len = data_len;
        if (len > sizeof(e->data) - 1)
            len = sizeof(e->data) - 1;
        bpf_probe_read_kernel_str(&e->data, len, data);
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[0];
    emit_event(EVENT_EXECVE, filename, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    emit_event(EVENT_EXECVE, filename, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/module/module_load")
int trace_module_load(struct trace_event_raw_module_load *ctx)
{
    /* On recent kernels the module name is a __data_loc dynamic field:
     * the low 16 bits of __data_loc_name hold the offset from the start of
     * the tracepoint context to the NUL-terminated string.
     */
    __u32 offset = ctx->__data_loc_name & 0xFFFF;
    const char *name = (const char *)ctx + offset;
    emit_event_kdata(EVENT_MODULE_LOAD, name, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_bpf")
int trace_bpf_syscall(struct trace_event_raw_sys_enter *ctx)
{
    /* Only program loads are interesting; other bpf(2) commands (map
     * operations, obj pinning, ...) are far too noisy.
     */
    if ((int)ctx->args[0] != BPF_PROG_LOAD)
        return 0;
    emit_event(EVENT_BPF_LOAD, NULL, 0);
    return 0;
}

SEC("kprobe/commit_creds")
int trace_commit_creds(struct pt_regs *ctx)
{
    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
    char buf[EVENT_MAX_DATA];
    __u32 uid = BPF_CORE_READ(new, uid.val);
    __u32 euid = BPF_CORE_READ(new, euid.val);
    __u64 fmt_args[2] = { uid, euid };

    bpf_snprintf(buf, sizeof(buf), "%u,%u", fmt_args, sizeof(fmt_args));
    emit_event_kdata(EVENT_COMMIT_CREDS, buf, sizeof(buf));
    return 0;
}

SEC("tp/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    const char *name = (const char *)ctx->args[0];
    emit_event(EVENT_MEMFD_CREATE, name, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[0];
    emit_event(EVENT_UNLINK, pathname, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[1];
    emit_event(EVENT_UNLINK, pathname, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    char buf[EVENT_MAX_DATA];
    __u64 fmt_args[2] = { ctx->args[0], ctx->args[1] };

    bpf_snprintf(buf, sizeof(buf), "%ld,%ld", fmt_args, sizeof(fmt_args));
    emit_event_kdata(EVENT_PTRACE, buf, sizeof(buf));
    return 0;
}

SEC("tp/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    /* source, target and fstype are user string pointers; read each into
     * kernel scratch first, then compose "source->target fstype".
     * Truncation to the 128-byte data limit is acceptable.
     */
    char source[48];
    char target[48];
    char fstype[24];
    char buf[EVENT_MAX_DATA];

    source[0] = '\0';
    target[0] = '\0';
    fstype[0] = '\0';
    bpf_probe_read_user_str(source, sizeof(source), (const char *)ctx->args[0]);
    bpf_probe_read_user_str(target, sizeof(target), (const char *)ctx->args[1]);
    bpf_probe_read_user_str(fstype, sizeof(fstype), (const char *)ctx->args[2]);
    {
        __u64 fmt_args[3] = {
            (__u64)source,
            (__u64)target,
            (__u64)fstype,
        };
        bpf_snprintf(buf, sizeof(buf), "%s->%s %s", fmt_args, sizeof(fmt_args));
    }
    emit_event_kdata(EVENT_MOUNT, buf, sizeof(buf));
    return 0;
}

SEC("tp/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    char buf[EVENT_MAX_DATA];
    __u64 fmt_args[2] = { ctx->args[0], ctx->args[1] };

    bpf_snprintf(buf, sizeof(buf), "%ld,%ld", fmt_args, sizeof(fmt_args));
    emit_event_kdata(EVENT_SETNS, buf, sizeof(buf));
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
    /* The OLD path is the tamper signal: renaming /var/log/auth.log away
     * is the anti-forensics sibling of deleting it.
     */
    const char *oldpath = (const char *)ctx->args[0];
    emit_event(EVENT_RENAME, oldpath, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
    const char *oldpath = (const char *)ctx->args[1];
    emit_event(EVENT_RENAME, oldpath, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    const char *oldpath = (const char *)ctx->args[1];
    emit_event(EVENT_RENAME, oldpath, EVENT_MAX_DATA);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_process_exit(void *ctx)
{
    /* No context fields are read (some kernels' BTF lacks the raw exit
     * struct) and no data payload is needed: the pid/tgid/comm fields from
     * fill_event are all the detector needs to correlate exits with execve
     * events, so short-lived processes are not mistaken for hidden ones.
     */
    emit_event(EVENT_EXIT, NULL, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
