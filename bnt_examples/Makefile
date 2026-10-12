CLANG ?= $(shell command -v clang 2>/dev/null || printf clang)
HOST_CC ?= $(CLANG)
ARCH ?= x86
SYSINC ?= /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -O2 -g -Wall -Wextra -Werror=incompatible-pointer-types -target bpf -D__TARGET_ARCH_$(ARCH) -I../src -I$(SYSINC)
HOST_CFLAGS := -O2 -g -Wall -Wextra -I../src -I$(SYSINC)
HOST_LDLIBS := -lbpf -lelf -lz

SOURCES := \
	xdp_drop_telnet.c \
	xdp_drop_telnet_find.c \
	xdp_drop_telnet_next_macro.c \
	xdp_drop_telnet_next_direct.c \
	xdp_vlan_ipv4_ttl_guard.c \
	xdp_ipv6_icmp6_filter.c \
	tc_http_to_8080.c \
	tc_ipv4_dnat.c \
	tc_udp_dnat_recompute.c \
	xdp_insert_ipv4_outer.c \
	xdp_remove_ipv4_outer.c \
	tc_insert_ipv6_outer.c \
	xdp_vlan_insert_remove.c \
	tc_vlan_insert_remove.c \
	xdp_insert_mpls_label.c \
	xdp_insert_srh.c \
	xdp_arp_responder.c \
	xdp_icmp4_echo_id_rewrite.c \
	xdp_tcp_snat_recompute.c \
	xdp_fib4_forward.c \
	xdp_fib6_forward.c \
	xdp_mpls_forward.c

PROGRAMS := $(SOURCES:.c=.o)
LOAD_CHECKER := verify_load

.PHONY: all bpf load-check syntax-check clean

all: bpf

bpf: $(PROGRAMS)

%.o: %.c ../src/bnt_xdp.h ../src/bnt_tc_ingress.h ../src/bnt_tc_egress.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LOAD_CHECKER): verify_load.c
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@ $(HOST_LDLIBS)

load-check: bpf $(LOAD_CHECKER)
	@status=0; \
	for f in $(PROGRAMS); do \
		echo "loading $$f"; \
		if ! ./$(LOAD_CHECKER) $$f; then \
			status=1; \
		fi; \
	done; \
	exit $$status

syntax-check:
	@set -e; \
	for f in $(SOURCES); do \
		echo "checking $$f"; \
		$(CLANG) $(HOST_CFLAGS) -c $$f -o /tmp/$$f.o; \
	done

clean:
	rm -f $(PROGRAMS) $(LOAD_CHECKER)
