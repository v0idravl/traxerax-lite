/* SPDX-License-Identifier: GPL-2.0 */
/*
 * traxerax-lite eBPF loader.
 *
 * Loads the rootwatch probe, attaches tracepoints/kprobes, drains the ring
 * buffer, and prints JSON events to stdout. Designed to be invoked by the
 * Python orchestrator as a subprocess.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rootwatch.skel.h"
#include "event.h"

#ifndef PROGRAM_PIN_PATH
#define PROGRAM_PIN_PATH "/sys/fs/bpf/traxerax-lite"
#endif

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static void json_escape_string(const char *input, size_t len)
{
    for (size_t i = 0; i < len && input[i] != '\0'; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c == '\b') {
            printf("\\b");
        } else if (c == '\f') {
            printf("\\f");
        } else if (c == '\n') {
            printf("\\n");
        } else if (c == '\r') {
            printf("\\r");
        } else if (c == '\t') {
            printf("\\t");
        } else if (c < 0x20 || c > 0x7e) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    if (data_sz < sizeof(*e)) {
        return 0;
    }

    printf("{"
           "\"type\":%u,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"ppid\":%u,"
           "\"comm\":\"",
           e->type, e->pid, e->tgid, e->uid, e->ppid);
    json_escape_string(e->comm, sizeof(e->comm));
    printf("\",\"parent_comm\":\"");
    json_escape_string(e->parent_comm, sizeof(e->parent_comm));
    printf("\",\"data\":\"");
    json_escape_string(e->data, sizeof(e->data));
    printf("\"}\n");
    fflush(stdout);
    return 0;
}



int main(int argc, char **argv)
{
    struct rootwatch_bpf *skel;
    struct ring_buffer *rb = NULL;
    const char *pin_path = PROGRAM_PIN_PATH;
    int err;

    if (argc >= 2) {
        pin_path = argv[1];
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = rootwatch_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = rootwatch_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Pin programs and maps so the orchestrator can verify we are still
     * attached. Ignore EEXIST so restarts do not fail. The pin is the
     * declared health signal, so a pin failure is fatal. */
    err = bpf_object__pin_programs(skel->obj, pin_path);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to pin programs: %d\n", err);
        goto cleanup;
    }
    err = bpf_object__pin_maps(skel->obj, pin_path);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Warning: failed to pin maps: %d\n", err);
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup_pinned;
    }

    printf("{\"status\":\"attached\",\"pin_path\":\"");
    json_escape_string(pin_path, strlen(pin_path));
    printf("\"}\n");
    fflush(stdout);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup_pinned:
    bpf_object__unpin_programs(skel->obj, pin_path);
    bpf_object__unpin_maps(skel->obj, pin_path);
cleanup:
    ring_buffer__free(rb);
    rootwatch_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
