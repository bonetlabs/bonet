CLANG   ?= $(shell command -v clang 2>/dev/null || printf clang)
HOST_CC ?= $(CLANG)
PYTHON  ?= python3
ARCH    ?= x86
SYSINC  ?= /usr/include/$(shell uname -m)-linux-gnu
ROOT    ?= ../..
BUILD   := build

BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types \
              -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) \
              -I$(ROOT)/src -I. -I$(SYSINC)
HOST_CFLAGS := -O2 -g -Wall -Wextra -I. -I$(SYSINC)
HOST_LDLIBS := -lbpf -lelf -lz

BNT_HEADERS := $(wildcard $(ROOT)/src/*.h)

.PHONY: all objs check coverage clean

all: $(BUILD)/run_api objs

# One program per public API, in the default build (the asm globals).
$(BUILD)/gen/apis.json: gen_programs.py $(BNT_HEADERS)
	$(PYTHON) gen_programs.py $(BUILD)/gen -- $(CLANG) $(BPF_CFLAGS)

objs: $(BUILD)/gen/apis.json
	@$(MAKE) --no-print-directory $(patsubst $(BUILD)/gen/%.c,$(BUILD)/obj/%.o,$(wildcard $(BUILD)/gen/*.c))

$(BUILD)/obj/%.o: $(BUILD)/gen/%.c api_io.h $(BNT_HEADERS)
	@mkdir -p $(BUILD)/obj
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/run_api: run_api.c api_io.h
	mkdir -p $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@ $(HOST_LDLIBS)

# Needs root (or CAP_BPF + CAP_NET_ADMIN): runs every case in this kernel and
# compares the results with model.py.
check: all
	$(PYTHON) check.py gen $(BUILD)
	$(PYTHON) check.py run $(BUILD) $(BUILD)/results
	$(PYTHON) check.py report $(BUILD) $(BUILD)/results

# Branch coverage of the cases, with the interpreter (no root needed).
coverage: objs
	$(PYTHON) coverage.py $(BUILD)

clean:
	rm -rf $(BUILD)
