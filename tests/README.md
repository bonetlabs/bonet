# Functional Tests

The test tree is split between shared runner code and suite-specific BPF
programs:

- `go/` contains the shared client/server runner and helper package.
- `config.ini` contains the shared machine/interface defaults used by every
  suite.
- `run_tests.sh` builds the selected suite and starts either the server side or
  the client side.
- `csum/` contains the checksum BPF programs, `tests.csv`, and its local
  `Makefile`.
  Its local `Makefile` compiles every `.c` file in that directory.
- `checksum_extra/` contains additional checksum cases that are intentionally
  kept separate from the original checksum suite.
- `parser/` covers parser navigation, VLAN, IPv4 fragments, IPv6 extension
  headers, typed `next_header`, and context-level `find_*` helpers.
- `rewrite/` covers public getter/setter helpers across Ethernet-adjacent L3/L4
  protocols.
- `debug/` covers the optional `bnt_debug.h` event helpers.
- `common/` contains shared BPF-side test support, including the
  `bnt_test_result` map ABI used by map-backed suites.
- `globals/` loads every XDP global on its own.
- `units/` calls every XDP global on prepared packets and checks the results.
- `api/` calls every public XDP API, in the default build (asm globals), and
  checks the results against a reference model.

`globals/` and `units/` run on one machine (see below). The other suites run
between two machines; each owns a `tests.csv` file, loaded on every runner
startup, that describes the object files to attach, the attach type, the
traffic protocol, the IP family, and whether the client should send padded
payloads.

## Single-machine tests

`run_tests.sh` does not run these. From `tests/`, as root:

```sh
make check-local
```

`globals/` loads each global in three builds: the default one, where the
globals come from `bnt_asm_globals.h`; one with the C globals
(`BNT_ASM_GLOBALS=0`); and, under `BPF_F_STRICT_ALIGNMENT`, a
`BNT_STRICT_ALIGN=1` build. The kernel only verifies the globals a program
calls, so this covers the ones no other test reaches. The `bnt_debug.h`
globals are left out.

`units/` runs the cases in `cases.py` with `BPF_PROG_TEST_RUN`, in the same
three builds,
and compares the return value, the output buffer and the packet with
`expected.json`. After an intended behaviour change, record new results with
`make -C units update-expected`. For the FIB lookups the output buffer is not
compared, since it depends on the routing table; for `csum_blk`
it is compared folded to 16 bits, since the raw `bpf_csum_diff` value changes
with the kernel version.

`api/` builds one program per public API (`gen_programs.py`) and runs it on
the cases of `cases.py`: a corpus of packets, each cut at every length, plus
NULL pointers, out-of-range offsets and boundary arguments. `model.py` gives
the expected result from the protocols, not from the C code; a call that fails
must leave the packet unchanged. `check.py report` lists the failing cases.
`make -C api coverage` reports branch coverage, on the interpreter of
`validation/exec_metrics`.

## Configuration

Before running tests, create the local config file:

```sh
cp config_example.ini config.ini
```

Use the same `config.ini` on both machines. Fill `[machine_a]` with the client
machine address and interface, fill `[machine_b]` with the server machine
address and interface, and keep the same roles on both copies of the file. Use
IPv4/IPv6 addresses that are reachable between the machines, and use the real
network interface name, for example `eth0`, `ens3`, or `enp0s8`, not `lo`
unless both sides really run on the same host.

`--config` can be passed more than once. Files are loaded in order and later
files override earlier values, so `run_tests.sh` can apply the shared
`tests/config.ini` first and then an optional suite-local `config.ini`.

At startup, client and server exchange a suite manifest and the client's IPv6
reachability result. A manifest mismatch aborts before any BPF program is
attached; IPv6 tests are skipped through explicit `SKIP` messages so the two
machines keep the same test cursor.

When running `all`, `run_tests.sh` stops at the first failing or interrupted
suite. This is intentional: if one side keeps advancing after a verifier
failure or `Ctrl+C`, the two machines can only reconnect to different suites.

`[test].verify_timeout` controls the per-program verify/load timeout in
seconds and defaults to `30.0`. Pass `--verify-timeout N` to override it for a
run, or a negative value to disable the timeout.

`[test].verify_policy` controls verifier failures and defaults to
`unverified`:

- `unverified` marks every affected test as `UNVERIFIED` and keeps the suite
  cursor synchronized on both machines.
- `fail` aborts the suite immediately on the first pre-verification failure.

The `expected` column is now interpreted by the runner:

- `packet_reaches_port_8888`, `tcp_handshake_reaches_port_8888`, and the
  existing padded-packet expectation wait for traffic at `PortTo`.
- `map_status_ok` polls the loaded BPF object's `bnt_test_result` map and
  expects status `OK`.
- Expectations can be combined, for example
  `map_status_ok_and_packet_reaches_port_8888`.

Supported `proto` values are `tcp`, `udp`, `icmp4`, `icmp6`, `arp`,
`vlan1-udp4`, `vlan2-udp4`, `udp4-frag`, `ipv6-ext-icmp6`, and
`ipv6-too-deep`. Raw Ethernet generators require the client to run with the
same privileges already needed for attaching BPF programs.

Common commands:

```sh
make all
./run_tests.sh --suite csum server
./run_tests.sh --suite csum client
./run_tests.sh --suite parser server
./run_tests.sh --suite parser client
./run_tests.sh server all
./run_tests.sh client all
```
