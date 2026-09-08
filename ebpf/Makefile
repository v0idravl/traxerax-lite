# SPDX-License-Identifier: GPL-2.0
#
# Build the traxerax-lite eBPF kernel probe and its userspace loader.
#
# Requirements:
#   - clang
#   - llvm-strip
#   - bpftool
#   - libbpf headers and library
#   - kernel BTF (for vmlinux.h) or kernel headers
#
# Run `make` from this directory. The output is `rootwatch-loader`.

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

LOADER := rootwatch-loader

.PHONY: all clean vmlinux

all: $(LOADER)

# FORCE keeps the rule running even when a (possibly empty) checked-in
# placeholder vmlinux.h exists; regeneration happens only when the file is
# missing or empty, so fresh checkouts always get real BTF.
FORCE:

vmlinux.h: FORCE
	@if [ ! -s $@ ]; then \
		if [ -f /sys/kernel/btf/vmlinux ]; then \
			$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp \
				&& mv $@.tmp $@ \
				|| { rm -f $@.tmp; exit 1; }; \
		else \
			echo "error: kernel BTF not available. Install a kernel with CONFIG_DEBUG_INFO_BTF=y or provide kernel headers." >&2; \
			exit 1; \
		fi; \
	fi

rootwatch.bpf.o: rootwatch.bpf.c event.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -I/usr/include \
		-c $< -o $@
	$(LLVM_STRIP) -g $@

rootwatch.skel.h: rootwatch.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

loader.o: loader.c event.h rootwatch.skel.h
	$(CLANG) -g -O2 -Wall -I. -c $< -o $@

$(LOADER): loader.o
	$(CLANG) $< -lbpf -lelf -lz -o $@

clean:
	rm -f *.o *.skel.h $(LOADER) vmlinux.h
