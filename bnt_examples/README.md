# bnt v2 example programs

This directory contains a compact validation suite for `bnt_xdp.h`, `bnt_tc_ingress.h`, and `bnt_tc_egress.h`.
Each example focuses on one or more library surfaces so that you can test the parser incrementally instead of validating everything at once.

XDP examples include `bnt_xdp.h`; TC ingress examples include `bnt_tc_ingress.h`; TC egress programs include `bnt_tc_egress.h`. The examples use the v2 libbpf-style naming convention, such as `bnt_eth__parse()` and `bnt_ipv4__get_protocol()`, and avoid direct access to internal `__` fields.

## Files and what they validate

### 1. `xdp_drop_telnet.c`
Validates:
- `bnt_eth__parse()`
- `bnt_ipv4__parse()`
- `bnt_tcp__parse()`
- `bnt_tcp__get_dest()`
- `bnt_tcp__get_flags()`

Behavior:
- Drops IPv4/TCP SYN packets to port 23.

Suggested traffic:
- `hping3 -S -p 23 <target>`
- `nc -vz <target> 23`

Expected result:
- SYN packets to port 23 are dropped.
- Other traffic passes.

### 1a. `xdp_drop_telnet_find.c`
Validates:
- `bnt_ctx__find_tcp()`
- high-level ctx walker over bnt-supported stacks

Behavior:
- Drops TCP SYN packets to port 23 on supported stacks found by the ctx walker.

### 1b. `xdp_drop_telnet_debug/`
Validates:
- `bnt_debug.h`
- explicit `bnt_dbg_*__printk()` helpers
- explicit `bnt_dbg_*__emit_ringbuf()` helpers
- per-header `struct bnt_dbg_*_event` binary event ABI
- explicit `bnt_dbg_*__update_map()` helpers
- map-backed storage of per-header event structs

Behavior:
- Contains separate `.bpf.c` programs and userspace loaders for printk,
  ringbuffer, and map-backed debug output.
- Each userspace program takes the interface name as its only argument.

### 1c. `xdp_drop_telnet_next_macro.c`
Validates:
- `bnt_eth__next_header()`
- `bnt_ipv4__next_header()`
- macro dispatch from the destination header pointer type

Behavior:
- Same as `xdp_drop_telnet.c`, using the typed next-header macro wherever it can.

### 1d. `xdp_drop_telnet_next_direct.c`
Validates:
- `bnt_eth__next_ipv4()`
- `bnt_ipv4__next_tcp()`
- explicit typed next-header helpers without the aggregating macro

Behavior:
- Same as `xdp_drop_telnet.c`, using the typed next-header functions directly.

### 2. `xdp_vlan_ipv4_ttl_guard.c`
Validates:
- VLAN-aware Ethernet parsing
- `bnt_eth__get_vlan_depth()`
- `bnt_ipv4__get_ttl()`
- `bnt_ipv4__set_ttl()`
- IPv4 header checksum update after TTL rewrite

Behavior:
- Only acts on VLAN-tagged IPv4/UDP packets.
- Drops packets with TTL `<= 1`.
- Decrements TTL otherwise.

Suggested traffic:
- Send VLAN-tagged UDP packets with different TTL values.
- A practical way is to generate traffic from a VLAN subinterface and observe with `tcpdump -e -vv`.

Expected result:
- TTL decreases by one.
- Packets with TTL 1 are dropped.

### 3. `xdp_ipv6_icmp6_filter.c`
Validates:
- `bnt_ipv6__parse()`
- bounded IPv6 extension-header walk
- `bnt_icmp6__parse()`
- conservative fragment handling

Behavior:
- Drops ICMPv6 Echo Requests.
- Passes fragmented IPv6 packets unchanged.

Suggested traffic:
- `ping6 <target>`
- Optional: generate packets with a Hop-by-Hop or Destination Options header and verify that ICMPv6 is still found.

Expected result:
- Echo Requests are dropped.
- Other IPv6 traffic passes.

### 4. `tc_http_to_8080.c`
Validates:
- IPv4 / IPv6 dual-stack dispatch
- `bnt_tcp__parse()` on the skb backend
- `bnt_tcp__set_dest()` checksum adjustment

Behavior:
- Rewrites TCP destination port 80 to 8080.

Suggested traffic:
- `curl http://<target>/`
- or any TCP client targeting port 80.

Expected result:
- The packet reaches port 8080 instead of port 80.
- Checksums remain valid.

### 5. `tc_ipv4_dnat.c`
Validates:
- `bnt_ipv4__get_daddr()`
- `bnt_ipv4__set_daddr()`
- L3 checksum update
- TCP/UDP pseudo-header checksum updates after IPv4 address rewrite
- `bnt_tcp__set_dest()` / `bnt_udp__set_dest()` on skb packets

Behavior:
- Rewrites destination IPv4 `192.168.1.100` to `10.0.0.2`.
- Rewrites TCP port `443 -> 8443`.
- Rewrites UDP port `53 -> 1053`.

Suggested traffic:
- TCP: `curl https://192.168.1.100/`
- UDP: `dig @192.168.1.100 example.org`

Expected result:
- Destination IP and service port are rewritten.
- Checksums remain valid.

### 6. `xdp_arp_responder.c`
Validates:
- `bnt_arp__parse()`
- `bnt_arp__is_eth_ipv4()`
- ARP SHA/SPA/THA/TPA getters and setters
- Ethernet source/destination rewrite helpers
- full in-place packet transformation followed by `XDP_TX`

Behavior:
- Answers ARP requests for `10.0.0.2` using a fixed MAC address.

Suggested traffic:
- `arping -I <iface> 10.0.0.2`

Expected result:
- The program emits an in-place ARP reply.
- The reply contains the configured service MAC.

### 7. `xdp_icmp4_echo_id_rewrite.c`
Validates:
- `bnt_icmp4__parse()`
- `bnt_icmp4__get_type()`
- `bnt_icmp4__set_echo_id()`
- ICMPv4 checksum update after rewrite

Behavior:
- Rewrites the ICMPv4 echo identifier to `0x1234`.

Suggested traffic:
- `ping <target>`
- Observe with `tcpdump -vv -X` or with Wireshark.

Expected result:
- Echo Requests pass, but the identifier field is rewritten.
- ICMP checksum remains valid.

### 8. `xdp_fib4_forward.c`
Validates:
- `bnt_ipv4__fib_lookup()`
- `bnt_fib4__is_success()`
- `bnt_fib4__get_out_ifindex()`
- `bnt_fib4__get_smac()`
- `bnt_fib4__get_dmac()`
- `bnt_ipv4__dec_ttl(..., expired)`
- Ethernet source/destination rewrite helpers followed by `bpf_redirect()`

Behavior:
- Performs a minimal IPv4 FIB lookup.
- Passes packets unchanged when the FIB helper does not return success.
- On FIB success, drops packets with TTL `<= 1`.
- Otherwise, decrements TTL, rewrites source/destination MAC addresses, and redirects to the FIB out-ifindex.

Suggested traffic:
- Route IPv4 packets through the attached XDP interface.
- Observe with `tcpdump -e -n` on ingress and egress interfaces.

Expected result:
- Successfully routed packets leave with updated Ethernet addresses and TTL decremented by one.

### 9. `xdp_fib6_forward.c`
Validates:
- `bnt_ipv6__fib_lookup()`
- `bnt_fib6__is_success()`
- `bnt_fib6__get_out_ifindex()`
- `bnt_fib6__get_smac()`
- `bnt_fib6__get_dmac()`
- `bnt_ipv6__dec_hop_limit(..., expired)`
- Ethernet source/destination rewrite helpers followed by `bpf_redirect()`

Behavior:
- Performs a minimal IPv6 FIB lookup.
- Passes packets unchanged when the FIB helper does not return success.
- On FIB success, drops packets with hop limit `<= 1`.
- Otherwise, decrements hop limit, rewrites source/destination MAC addresses, and redirects to the FIB out-ifindex.

Suggested traffic:
- Route IPv6 packets through the attached XDP interface.
- Observe with `tcpdump -e -n` on ingress and egress interfaces.

Expected result:
- Successfully routed packets leave with updated Ethernet addresses and hop limit decremented by one.

### 9a. `xdp_mpls_forward.c`
Validates:
- `bnt_eth__next_mpls()`
- `bnt_mpls__get_ttl()` / `bnt_mpls__set_ttl()`
- `bnt_mpls__is_bos()` and `bnt_mpls__next_mpls()` (label stack walk)
- `bnt_mpls__next_ipv4()` / `bnt_mpls__next_ipv6()`

Behavior:
- Drops the packet if the top label's TTL is `<= 1`.
- Otherwise decrements the top label's TTL.
- Walks down to the bottom of the label stack and logs whether the payload
  underneath is IPv4 or IPv6.

Suggested traffic:
- Send an MPLS-encapsulated IPv4 or IPv6 packet (e.g. via `scapy` or a router
  that pushes a label) through the attached XDP interface.

Expected result:
- The top label's TTL is decremented by one; `bpf_printk` (via
  `cat /sys/kernel/debug/tracing/trace_pipe`) reports the payload type.

### 10. Structural edits (insert / remove)

These show packet resizing. Remember that an insert/remove invalidates existing
views: re-parse afterwards before reusing them.

- `xdp_insert_ipv4_outer.c`: inserts an outer IPv4 header (IPIP) after
  Ethernet/VLAN, turning the existing IPv4 payload into a tunnelled inner packet.
- `xdp_remove_ipv4_outer.c`: removes an outer IPv4 header (IHL=5), mapping IPIP
  back to IPv4 and IPv6-in-IP back to IPv6.
- `tc_insert_ipv6_outer.c`: the TC counterpart, inserting an outer IPv6 header via
  `bpf_skb_adjust_room()`.
- `xdp_vlan_insert_remove.c` / `tc_vlan_insert_remove.c`: push then pop an 802.1Q
  VLAN tag (a round-trip that leaves the packet unchanged).
- `xdp_insert_mpls_label.c`: pushes one MPLS label onto IPv4 traffic via
  `bnt_eth__insert_mpls()`.
- `xdp_insert_srh.c`: SRv6 H.Insert — adds a 2-segment Segment Routing Header
  after the IPv6 base header via `bnt_ipv6__insert_srh()`.

### 11. Full checksum recompute

These use the `*_no_csum` setters together with the `recompute_csum` helpers
(full recompute over the payload, bounded by `BNT_MAX_PAYLOAD`) instead of
incremental updates.

- `xdp_tcp_snat_recompute.c`: TCP source NAT on XDP, recomputing the IPv4 and TCP
  checksums from scratch.
- `tc_udp_dnat_recompute.c`: UDP destination NAT on TC, recomputing the IPv4 and
  UDP checksums from scratch.

> `verify_load.c` is not a BPF program: it is a small host-side loader (libbpf)
> used to load an object and report verifier success or failure.

## Recommended validation order

1. `xdp_drop_telnet.c`
2. `xdp_drop_telnet_find.c`
3. `xdp_drop_telnet_next_macro.c`
4. `xdp_drop_telnet_next_direct.c`
5. `xdp_drop_telnet_debug/`
6. `xdp_icmp4_echo_id_rewrite.c`
7. `xdp_vlan_ipv4_ttl_guard.c`
8. `xdp_ipv6_icmp6_filter.c`
9. `tc_http_to_8080.c`
10. `tc_ipv4_dnat.c`
11. `xdp_arp_responder.c`
12. `xdp_fib4_forward.c`
13. `xdp_fib6_forward.c`
14. `xdp_mpls_forward.c`

This order starts with read-only parsing, then moves to single-field rewrites, then to VLAN and IPv6 corner cases, and finally to multi-field rewrites and in-place packet synthesis.

## Build example

Adjust `__TARGET_ARCH_*` to your target architecture.
The provided `Makefile` defaults to `x86`.

The default target emits real BPF object files:

```bash
make
```

To run only the host-side syntax check without leaving `.o` files in this
directory, use:

```bash
make syntax-check
```

Or build a single example manually from this directory. Use `-I../src` so the compiler can find the bnt headers:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I../src -c xdp_drop_telnet.c -o xdp_drop_telnet.o
```

## Example attach commands

### XDP

```bash
ip link set dev <iface> xdp obj xdp_drop_telnet.o sec xdp
```

### TC ingress

```bash
tc qdisc add dev <iface> clsact
tc filter add dev <iface> ingress bpf da obj tc_http_to_8080.o sec classifier
```

### TC egress

```bash
tc qdisc add dev <iface> clsact
tc filter add dev <iface> egress bpf da obj tc_ipv4_dnat.o sec classifier
```

## Practical verification tips

- Use `tcpdump -vv -e -n` or Wireshark to inspect field changes.
- For rewrite examples, always verify both the field values and the checksum validity.
- Keep one example per object file while iterating, so attach/debug cycles stay simple.

## Header requirements

The v2 examples intentionally use the system libbpf headers through includes such as `<bpf/bpf_helpers.h>` and `<bpf/bpf_endian.h>`. Install `libbpf-dev` or your distribution's equivalent before building.
