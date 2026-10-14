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
- `globals/` loads every XDP global subprogram on its own, in the default build
  and with `BNT_STRICT_ALIGN=1` under `BPF_F_STRICT_ALIGNMENT`. The kernel only
  verifies the globals a program calls, so this catches a global that no other
  test reaches. It runs on one machine, outside `run_tests.sh`:
  `make -C globals check` (needs root). The debug-header globals are not
  included.

Each suite owns a `tests.csv` file. The CSV is loaded on every runner startup
and describes the object files to attach, the attach type, the traffic protocol,
the IP family, and whether the client should send padded payloads.

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
