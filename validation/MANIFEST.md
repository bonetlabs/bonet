# BONet benchmark suite proposal

This archive contains paired eBPF benchmark programs under:

- `baseline/`: handwritten eBPF implementations.
- `framework/`: equivalent implementations using the BONet/bnt API.

The suite is split into two experimental levels.

## Fairness policy

- Framework programs should use the explicit parser/navigation path
  (`bnt_eth__parse()`, `bnt_eth__next_ipv4()`/`bnt_eth__next_ipv6()`,
  `bnt_ipv4__next_*()`, `bnt_ipv6__next_*()`, or direct L4 parse from a
  computed next offset). Do not use `bnt_ctx__find_*()` in paper benchmarks
  unless the benchmark is specifically about those convenience walkers.
- Baseline programs should be handwritten, self-contained C eBPF programs.
  Do not use a shared baseline helper header or support library in the paper
  benchmarks. If a baseline needs parsing, bounds checks, skb load/store, or
  checksum handling, write that logic directly inside the single benchmark
  entry function. Avoid local `parse_*`/`rewrite_*` helper functions in the
  baseline, so the comparison is not framework style versus local-library
  style.
- The default metrics workflow counts the benchmark `.c` programs, not the
  external framework implementation in `src/`. This makes source metrics a
  comparison between self-contained handwritten programs and the corresponding
  framework-based application code. Object and verifier metrics still include
  the inlined/generated code that actually reaches the BPF program.

## Level 1: library-isolation benchmarks

These benchmarks minimize application logic and are intended to isolate the direct effect of the library on parsing, bounds checks, field access, field rewrite, checksum handling, and XDP/TC backend usage.

| File | Program type | Main library surface under test |
|---|---|---|
| `xdp_firewall_static.c` | XDP | Ethernet/IPv4/TCP parsing, TCP destination port and flags access |
| `xdp_vlan_ipv4_ttl_guard.c` | XDP | VLAN parsing, IPv4/UDP dispatch, TTL rewrite, IPv4 checksum update |
| `xdp_ipv6_icmp6_filter.c` | XDP | IPv6 extension-header bounded walk, ICMPv6 access |
| `tc_http_to_8080.c` | TC classifier | dual-stack TCP lookup on skb, TCP port rewrite, checksum update |
| `tc_ipv4_dnat.c` | TC classifier | IPv4 daddr rewrite, TCP/UDP port rewrite, L3/L4 checksum update |
| `xdp_arp_responder.c` | XDP | ARP parsing, Ethernet/ARP field rewrite, XDP_TX packet transformation |

## Level 2: realistic/end-to-end benchmark

| File | Program type | What is intentionally added |
|---|---|---|
| `xdp_firewall_map.c` | XDP | BPF map lookup for runtime-configurable blocked TCP ports |
| `xdp_acl_firewall_e2e.c` | XDP | dual-stack ACL lookup with packet and byte counters |
| `tc_service_dnat_e2e.c` | TC classifier | service table lookup, packet and byte counters, TCP/UDP DNAT |

The Level 2 programs should not be used alone to attribute overhead to the
library, because map lookup and counter updates are application logic. They are
useful to show that the library remains comparable in more deployable programs.

## Suggested usage

From the directory containing `baseline/`, `framework/`, and a sibling `src/` directory from the BONet repository:

```bash
make -C baseline
make -C framework
```

If you place this archive under `validation/benchmarks/`, build the framework side with:

```bash
make -C framework BNT_INC=../../src
```

For software-engineering metrics, copy or symlink these two directories into the existing `validation/` workflow, or run `softeng_perf/compare_metrics.py` by pointing `--baseline` and `--framework` at these folders.
