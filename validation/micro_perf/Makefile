CC     ?= clang
CLANG  ?= clang
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BUILD  := build
BPF_CFLAGS := -O2 -g -Wall -target bpf -mcpu=v3 -I$(SYSINC)

.PHONY: all clean

all: $(BUILD)/bench_prog $(BUILD)/bench_wrap.o $(BUILD)/sink.o $(BUILD)/ref_case.o \
     $(BUILD)/ref/DROP.o $(BUILD)/ref/PASS.o $(BUILD)/ref/TX.o $(BUILD)/ref/REDIRECT.o

$(BUILD)/bench_prog: bench_prog.c
	mkdir -p $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -I$(SYSINC) $< -o $@ -lbpf -lelf -lz

$(BUILD)/ref/%.o: ref.bpf.c
	mkdir -p $(BUILD)/ref
	$(CLANG) $(BPF_CFLAGS) -DREF_$* -c $< -o $@

$(BUILD)/%.o: %.bpf.c
	mkdir -p $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)
