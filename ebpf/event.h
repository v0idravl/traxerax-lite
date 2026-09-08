/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared event layout between the rootwatch BPF probe (rootwatch.bpf.c) and
 * the userspace loader (loader.c). Both sides must include this header so
 * the ring buffer record format never drifts apart.
 */

#ifndef ROOTWATCH_EVENT_H
#define ROOTWATCH_EVENT_H

#define EVENT_MAX_DATA 128

struct event {
    __u32 type;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 ppid;
    char comm[16];
    char parent_comm[16];
    char data[EVENT_MAX_DATA];
};

#endif /* ROOTWATCH_EVENT_H */
