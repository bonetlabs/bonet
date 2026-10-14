CLANG   ?= $(shell command -v clang 2>/dev/null || printf clang)
HOST_CC ?= $(CLANG)
PYTHON  ?= python3
ARCH    ?= x86
SYSINC  ?= /usr/include/$(shell uname -m)-linux-gnu
ROOT    ?= ../..
BUILD   := build

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types \
              -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) \
              -I$(ROOT)/src -I$(SYSINC)
HOST_CFLAGS := -O2 -g -Wall -Wextra -I$(SYSINC)
HOST_LDLIBS := -lbpf -lelf -lz

BNT_HEADERS := $(wildcard $(ROOT)/src/*.h)
OBJECTS     := $(BUILD)/globals.o $(BUILD)/globals_strict.o

.PHONY: all check clean

all: $(OBJECTS) $(BUILD)/load_each

$(BUILD):
	mkdir -p $@

$(BUILD)/globals.c: gen_programs.py $(BNT_HEADERS) | $(BUILD)
	$(PYTHON) gen_programs.py $@ -- $(CLANG) $(BPF_CFLAGS)

$(BUILD)/globals.o: $(BUILD)/globals.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/globals_strict.o: $(BUILD)/globals.c
	$(CLANG) $(BPF_CFLAGS) -DBNT_STRICT_ALIGN=1 -c $< -o $@

$(BUILD)/load_each: load_each.c | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@ $(HOST_LDLIBS)

# Needs root (or CAP_BPF + CAP_NET_ADMIN).
check: all
	./$(BUILD)/load_each $(BUILD)/globals.o
	./$(BUILD)/load_each --strict $(BUILD)/globals_strict.o

clean:
	rm -rf $(BUILD)
