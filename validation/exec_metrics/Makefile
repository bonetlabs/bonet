CC     ?= clang
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BUILD  := build

.PHONY: all clean

all: $(BUILD)/verifier_stats

$(BUILD)/verifier_stats: verifier_stats.c
	mkdir -p $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -I$(SYSINC) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf $(BUILD)
