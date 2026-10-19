# framework_inlined: NO duplicated sources. Builds the exact same programs as
# ../framework but with BNT_INLINE_ALL=1 (every bnt operation inlined into the
# program; no global subprograms).
#
# Note: only the XDP objects differ from ../framework's default globals build. On
# TC, BNT_INLINE_ALL is forced to 1 by the backend headers, so the tc_*.o here are
# byte-identical to ../framework's — the runner therefore uses only xdp_*.o here.
CLANG ?= $(shell command -v clang 2>/dev/null || printf clang)
ARCH ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BNT_INC ?= ../../src
SRCDIR ?= ../framework
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRCDIR) -I$(SYSINC) -I$(BNT_INC)
BNT_INLINE_ALL ?= 1
EXTRA_CFLAGS ?=
XDP_EXTRA_CFLAGS ?= -DBNT_INLINE_ALL=$(BNT_INLINE_ALL)
SRCS := $(notdir $(wildcard $(SRCDIR)/*.c))
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

xdp_%.o: EXTRA_CFLAGS += $(XDP_EXTRA_CFLAGS)

%.o: $(SRCDIR)/%.c
	$(CLANG) $(BPF_CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
