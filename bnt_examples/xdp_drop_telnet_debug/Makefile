CLANG ?= $(shell command -v clang 2>/dev/null || printf clang)
HOST_CC ?= $(CLANG)
ARCH ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types \
	-target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) -I../../src -I$(SYSINC)
USER_CFLAGS := -O2 -g -Wall -Wextra -I../../src -I$(SYSINC)
USER_LDLIBS := -lbpf -lelf -lz

BPF_SOURCES := \
	xdp_drop_telnet_debug_printk.bpf.c \
	xdp_drop_telnet_debug_ringbuf.bpf.c \
	xdp_drop_telnet_debug_map.bpf.c

USER_SOURCES := \
	xdp_drop_telnet_debug_printk.c \
	xdp_drop_telnet_debug_ringbuf.c \
	xdp_drop_telnet_debug_map.c

BPF_OBJECTS := $(BPF_SOURCES:.bpf.c=.bpf.o)
USER_PROGRAMS := $(USER_SOURCES:.c=)

.PHONY: all clean

all: $(USER_PROGRAMS)

%.bpf.o: %.bpf.c ../../src/bnt_xdp.h ../../src/bnt_core.h ../../src/bnt_debug.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_PROGRAMS): %: %.c %.bpf.o ../../src/bnt_debug.h
	$(HOST_CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -f $(BPF_OBJECTS) $(USER_PROGRAMS)
