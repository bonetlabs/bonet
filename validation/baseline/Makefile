CLANG ?= $(shell command -v clang 2>/dev/null || printf clang)
ARCH ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I$(SYSINC)
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
