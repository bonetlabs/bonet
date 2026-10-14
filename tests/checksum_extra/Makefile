CLANG  ?= $(shell command -v clang 2>/dev/null || command -v clang-15 2>/dev/null || printf clang)
ARCH   ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
ROOT   ?= ../..

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types \
              -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) \
              -I$(ROOT)/src -I$(ROOT)/tests/common -I$(SYSINC)

BPF_SOURCES  := $(wildcard *.c)
BPF_PROGRAMS := $(BPF_SOURCES:.c=.o)
BNT_HEADERS := $(ROOT)/src/bnt_tc_ingress.h \
                $(ROOT)/src/bnt_tc_egress.h \
                $(ROOT)/src/bnt_xdp.h \
                $(ROOT)/src/bnt_core.h \
                $(ROOT)/tests/common/test_result.h

all: $(BPF_PROGRAMS)

%.o: %.c $(BNT_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_PROGRAMS)

.PHONY: all clean
