# BONet

> Header-only, verifier-friendly packet parsing & rewriting for eBPF (XDP & TC).

**BONet**, short for *BPF Operations for NETworking*, lets you write eBPF data paths with small typed packet *views* instead of raw pointer arithmetic, manual bounds checks, byte-order juggling, and hand-rolled checksum updates.

In its default mode every packet access is compiled into a global BPF subprogram
that the kernel verifier checks **once, in isolation**, so an operation that
verifies keeps verifying regardless of the program around it.

```c
#include "bnt_xdp.h"

SEC("xdp")
int xdp_drop_telnet(struct xdp_md *ctx)
{
    bnt_eth  eth;
    bnt_ipv4 ip;
    bnt_tcp  tcp;
    __u16 dport;
    bool  syn;

    if (bnt_eth__parse(ctx, 0, &eth))    return XDP_PASS;
    if (bnt_eth__next_ipv4(&eth, &ip))   return XDP_PASS;   /* not IPv4 */
    if (bnt_ipv4__next_tcp(&ip, &tcp))   return XDP_PASS;   /* not TCP  */

    if (bnt_tcp__get_dport(&tcp, &dport) || bnt_tcp__is_syn(&tcp, &syn))
        return XDP_PASS;
    return (dport == 23 && syn) ? XDP_DROP : XDP_PASS;
}
```

## Features

- Typed views for Ethernet, VLAN, MPLS, ARP, IPv4 / IPv6 (incl. extension
  headers), TCP, UDP, ICMPv4 / ICMPv6, and SRv6.
- Parse, navigate, read, modify, insert/remove headers, and recompute checksums.
- One API, two backends: **XDP** (`struct xdp_md *`) and **TC** (`struct __sk_buff *`).
- Bounds checks and incremental checksum updates handled for you.
- Default *verified-in-isolation* mode, plus an inline mode and a legacy-kernel mode, via build flags.

## Requirements

- **clang/LLVM 16 or newer** with the `bpf` target (gcc cannot target BPF; clang 15
  and older are not supported). Tested through clang 22.
- **`-mcpu=v3`** in the default build mode. clang 16–19 default to v1; clang 18 and
  newer stop the build with an error if the level is lower.
- **Linux kernel UAPI headers.** `bnt` declares the BPF helpers it uses itself, so
  it does **not** depend on libbpf. (Your program still needs `bpf/bpf_helpers.h`
  for the usual `SEC()` scaffolding.)

```bash
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Installation

`BONet` is header-only. In your code, include a **single backend header** for your hook (`bnt_xdp.h`, `bnt_tc_ingress.h`, or `bnt_tc_egress.h`); it pulls in everything else.

### Use it in place (no install)

Point the compiler at `src/`:

```bash
clang -O2 -g -target bpf -mcpu=v3 -I/path/to/bonet/src -c prog.c -o prog.o
```

### Install, then consume via pkg-config (recommended)

Install once, system-wide:

```bash
cmake -S . -B build && sudo cmake --install build
```

This puts the headers in `/usr/local/include`, which clang searches by default
(also with `-target bpf`), so `#include <bnt_xdp.h>` needs no `-I`. It also
installs a pkg-config file and a CMake package config. Without CMake, use
pkg-config:

```bash
clang -O2 -g -target bpf -mcpu=v3 $(pkg-config --cflags bnt) -c prog.c -o prog.o
```

### If you already use CMake

The same install exports a package config:

```cmake
find_package(bnt REQUIRED)
target_link_libraries(myprog PRIVATE bnt::bnt)   # adds -I.../include
```

`bnt::bnt` only propagates the include path; you still compile the BPF object
with your own `clang -target bpf` rule.

> No CMake at hand? Copy the headers manually instead of `cmake --install`:
> `sudo install -m0644 src/bnt_*.h /usr/local/include/` (gives you the headers,
> but no pkg-config/CMake config).

## License

MIT. See [LICENSE](LICENSE). (Individual BPF programs declare a `"GPL"` license
string where the kernel requires it for certain helpers.)
