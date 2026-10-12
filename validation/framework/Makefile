CLANG ?= $(shell command -v clang 2>/dev/null || printf clang)
ARCH ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BNT_INC ?= ../../src
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I$(SYSINC) -I$(BNT_INC)
BNT_INLINE_ALL ?= 0
EXTRA_CFLAGS ?=
XDP_EXTRA_CFLAGS ?= -DBNT_INLINE_ALL=$(BNT_INLINE_ALL)
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

xdp_%.o: EXTRA_CFLAGS += $(XDP_EXTRA_CFLAGS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
