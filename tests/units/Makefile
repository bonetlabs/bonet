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

.PHONY: all check update-expected clean

all: $(BUILD)/default.stamp $(BUILD)/strict.stamp $(BUILD)/run_case

$(BUILD)/gen.stamp: gen_cases.py cases.py
	$(PYTHON) gen_cases.py $(BUILD)/gen
	touch $@

# One object per case, in the default build and with BNT_STRICT_ALIGN=1.
$(BUILD)/default.stamp: $(BUILD)/gen.stamp $(BNT_HEADERS)
	mkdir -p $(BUILD)/default
	for f in $(BUILD)/gen/case_*.c; do \
		$(CLANG) $(BPF_CFLAGS) -c $$f -o $(BUILD)/default/$$(basename $$f .c).o || exit 1; \
	done
	touch $@

$(BUILD)/strict.stamp: $(BUILD)/gen.stamp $(BNT_HEADERS)
	mkdir -p $(BUILD)/strict
	for f in $(BUILD)/gen/case_*.c; do \
		$(CLANG) $(BPF_CFLAGS) -DBNT_STRICT_ALIGN=1 -c $$f -o $(BUILD)/strict/$$(basename $$f .c).o || exit 1; \
	done
	touch $@

$(BUILD)/run_case: run_case.c
	mkdir -p $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@ $(HOST_LDLIBS)

# Needs root (or CAP_BPF + CAP_NET_ADMIN). Both builds must match expected.json.
check: all
	$(PYTHON) check.py $(BUILD)/default $(BUILD)/strict

# Records expected.json from the default build. Run only after checking that
# a behaviour change is intended.
update-expected: all
	$(PYTHON) check.py --update $(BUILD)/default

clean:
	rm -rf $(BUILD)
