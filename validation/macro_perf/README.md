# BONet IPv4 Forwarding Performance Experiment

This directory contains an SRPerf-style performance experiment for BONet IPv4 forwarding. It compares three SUT forwarding cases with the same IPv4/UDP traffic:

- `framework`: attach `validation/framework/xdp_fib4_forward.o`, implemented with the BONet/bnt API (default `BNT_INLINE_ALL=0`: packet access in global subprograms, verified in isolation).
- `framework-inlined`: attach `validation/framework_inlined/xdp_fib4_forward.o`, the same bnt API built with `BNT_INLINE_ALL=1` (every operation inlined into the program, no global subprograms). **XDP only** — on TC `BNT_INLINE_ALL` is forced to 1 regardless (no isolated packet-access path exists there: `__bnt_data_ptr` is XDP-only, TC uses skb helpers), so a `framework-inlined-tc` case would be byte-identical to `framework-tc` and is intentionally omitted.
- `baseline`: attach `validation/baseline/xdp_fib4_forward.o`, handwritten eBPF.
- `framework-tc` / `baseline-tc`: the TC variants of the above.
- `kernel`: detach XDP and use normal Linux kernel IPv4 forwarding.

The main reportable metric is PDR/Rmax: the highest packet rate for which the delivery ratio stays above the configured threshold, normally `0.995` (drop ratio <= 0.5%). MRR can still be useful as a stress test, but it is not the primary paper metric for this experiment.

## 1. Machine Roles

Use the same two-node shape as SRPerf:

```text
TRex/orchestrator machine                    SUT machine
+------------------------+                   +-------------------------+
| runs runner.py         |                   | runs forwarding path    |
| runs TRex server       |                   | has two dataplane NICs  |
| TRex port 0  ----------+-------------------> SUT rx interface        |
| TRex port 1  <---------+-------------------+ SUT tx interface        |
+------------------------+                   +-------------------------+
```

The orchestrator is the machine that runs `validation/macro_perf/runner.py`. Normally this is the TRex/tester machine, because it must import the TRex STL Python API and talk to the TRex server.

The SUT is the machine being measured. The runner configures it either through SSH or locally:

- Use `sut.mode: ssh` when TRex and SUT are different machines. This is the normal setup.
- Use `sut.mode: local` only when you run the runner directly on the SUT.

## 2. Example Topology

The checked-in benchmark profiles use the following placeholder topology. Replace
the interface names, MAC addresses, management host, TRex PCI IDs, and optional
IRQ fields before running on a real testbed:

```text
TRex port 0 / PCI 07:00.0 / MAC 02:00:00:00:01:01
  -> SUT eth1 / MAC 02:00:00:00:01:02 / IPv4 10.8.0.2/24

SUT eth2 / MAC 02:00:00:00:02:02 / IPv4 10.7.0.2/24
  -> TRex port 1 / PCI 08:00.0 / MAC 02:00:00:00:02:01

SUT SSH management IP: 192.0.2.10
Synthetic benchmark destination: 48.0.0.2/24
```

The traffic IP addresses are synthetic benchmark addresses. They can stay as-is
if they do not conflict with your lab network.

## 3. SUT Prerequisites

On the SUT machine, install the tools needed to build and attach the eBPF programs:

```bash
sudo apt update
sudo apt install -y clang llvm make gcc iproute2 ethtool libbpf-dev libelf-dev zlib1g-dev pkg-config
```

The BONet repository must exist on the SUT. The default path used by the configs is:

```bash
/path/to/bonet
```

For SSH mode, the SSH user must be able to run the SUT commands with `sudo`. Passwordless sudo is the easiest setup because the runner executes non-interactive commands such as:

```bash
sudo env ... bash validation/macro_perf/sut_forwarding.sh prepare framework
```

Stop `irqbalance` during measurements if you use IRQ pinning:

```bash
sudo systemctl stop irqbalance || true
systemctl is-active irqbalance
```

`inactive` is the expected state for controlled runs.

## 4. TRex Installation And Server

Install TRex on the TRex/orchestrator machine. The examples below use:

```bash
/opt/trex/v3.08
```

Install the Python dependency used by the runner:

```bash
cd /path/to/bonet/validation/macro_perf
python3 -m pip install -r requirements.txt
```

The runner needs the TRex STL Python API path in YAML:

```yaml
trex:
  api_path: /opt/trex/v3.08/automation/trex_control_plane/interactive
```

Start TRex before running the benchmark:

```bash
cd /opt/trex/v3.08
sudo ./t-rex-64 -i --no-ofed-check
```

Leave TRex running while you run `runner.py` from another shell. `--no-ofed-check` is used in this testbed because the host does not provide the Mellanox `ofed_info` tool, while the mlx5 DPDK path still works.

If TRex reports missing hugepages after setting 100G bandwidth, allocate hugepages on the TRex host:

```bash
grep Huge /proc/meminfo
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
grep Huge /proc/meminfo
```

Use `2048` if the VM does not have enough RAM, or `8192` if TRex still needs more memory.

## 5. TRex `/etc/trex_cfg.yaml`

TRex reads `/etc/trex_cfg.yaml` when `t-rex-64` starts. For this experiment the `dest_mac` values must be the SUT interface MACs, not the other TRex port MACs. `dpdk_setup_ports.py -i` often generates loopback-style MACs, so edit the file manually.

Example TRex configuration:

```yaml
- version: 2
  interfaces: ['07:00.0', '08:00.0']
  port_bandwidth_gb: 100
  port_mtu: 9000
  port_info:
      - dest_mac: 02:00:00:00:01:02
        src_mac:  02:00:00:00:01:01
      - dest_mac: 02:00:00:00:02:02
        src_mac:  02:00:00:00:02:01

  platform:
      master_thread_id: 0
      latency_thread_id: 1
      dual_if:
        - socket: 0
          threads: [2,3,4,5,6,7,8,9,10,11,12,13,14,15]
```

Meaning:

- `interfaces[0]` is TRex port 0, connected to the SUT receive interface.
- `interfaces[1]` is TRex port 1, connected to the SUT transmit interface.
- `port_info[0].dest_mac` is the MAC of `network.sut_rx_iface`.
- `port_info[1].dest_mac` is the MAC of `network.sut_tx_iface`.
- `port_bandwidth_gb: 100` makes TRex interpret `100%` as 100G line rate.
- `port_mtu: 9000` avoids the mlx5 MTU configuration failure observed with TRex defaults.

After editing the file, restart TRex:

```bash
sudo pkill -f t-rex-64 || true
cd /opt/trex/v3.08
sudo ./t-rex-64 -i --no-ofed-check
```

Check that both links are up and show `speed 100000 Mbps`.

## 6. YAML Configuration

Start from one of the checked-in profiles if you are configuring a new testbed:

```bash
cd /path/to/bonet/validation/macro_perf
cp config.debug.yaml config.local.yaml
```

### 6.1 SUT SSH

```yaml
sut:
  mode: ssh
  bonet_root: /path/to/bonet
  sudo: true
  settle_seconds: 1
  ssh:
    host: 192.0.2.10
    user: benchmark
    key: /path/to/ssh_key
    port: 22
```

`host` is the SUT management address, not one of the dataplane experiment addresses. The SSH path can be different from the traffic IPs.

### 6.2 TRex Client

```yaml
trex:
  server: 127.0.0.1
  api_path: /opt/trex/v3.08/automation/trex_control_plane/interactive
  tx_port: 0
  rx_port: 1
  duration: 10
  warmup: 1
  samples: 1
  stats_settle_seconds: 1
```

- `server`: TRex RPC server. Use `127.0.0.1` when the runner runs on the TRex host.
- `tx_port`: TRex port that sends to the SUT receive interface.
- `rx_port`: TRex port that receives from the SUT transmit interface.
- `duration`: seconds per measured TRex trial.
- `warmup`: trials discarded before collecting samples.
- `samples`: measured trials per probed PDR rate.

### 6.3 Network Fields

```yaml
network:
  sut_rx_iface: eth1
  sut_rx_ipv4: 10.8.0.2
  sut_rx_prefix: 24
  sut_rx_mac: "02:00:00:00:01:02"

  sut_tx_iface: eth2
  sut_tx_ipv4: 10.7.0.2
  sut_tx_prefix: 24
  sut_tx_mac: "02:00:00:00:02:02"

  tg_tx_ipv4: 10.8.0.1
  tg_tx_mac: "02:00:00:00:01:01"

  tg_rx_ipv4: 10.7.0.1
  tg_rx_mac: "02:00:00:00:02:01"

  traffic_src_ipv4: 10.8.0.1
  traffic_dst_ipv4: 48.0.0.2
  traffic_dst_prefix: 24
```

Mapping:

- `sut_rx_iface`: SUT NIC connected to TRex `tx_port`.
- `sut_rx_mac`: destination MAC used in generated pcaps.
- `sut_tx_iface`: SUT NIC connected to TRex `rx_port`.
- `tg_tx_mac`: source MAC used in generated pcaps.
- `tg_rx_ipv4` and `tg_rx_mac`: static neighbor installed on the SUT for forwarded packets.
- `traffic_dst_ipv4` and `traffic_dst_prefix`: synthetic destination route installed on the SUT.

The SUT script installs a route equivalent to:

```bash
ip route replace 48.0.0.0/24 via 10.7.0.1 dev eth2
```

## 7. IRQ Pinning

The default benchmark profiles do not pin IRQs. They assume:

- `irqbalance` is stopped during measurements.
- The system default NIC queue/IRQ placement is used.
- The same SUT state is used for `framework`, `baseline`, and `kernel`.

This is the recommended default unless you have a separately validated IRQ
placement policy. It is methodologically valid as long as the same policy is
used for every case and reported with the results.

Keep these YAML fields empty for the default profile:

```yaml
network:
  sut_rx_irq_min:
  sut_rx_irq_max:
  sut_rx_irq_core:
  sut_tx_irq_min:
  sut_tx_irq_max:
  sut_tx_irq_core:
```

Before running, stop `irqbalance` on the SUT:

```bash
sudo systemctl stop irqbalance || true
systemctl is-active irqbalance
```

`inactive` is the expected state.

If IRQs were manually pinned in a previous experiment, reboot the SUT before the
final run, or reset the affected IRQs to all CPUs. First identify the relevant
IRQ numbers for your NICs:

```bash
for dev in eth1 eth2; do
  pci=$(basename "$(readlink -f /sys/class/net/$dev/device)")
  grep "$pci" /proc/interrupts
done
```

Then reset the selected IRQs to the CPU range used by your SUT:

```bash
for irq in <irq-list>; do
  if [ -e /proc/irq/$irq/smp_affinity_list ]; then
    echo 0-15 | sudo tee /proc/irq/$irq/smp_affinity_list
  fi
done
```

Optional IRQ pinning is still supported by the runner, but use it only after validating which completion IRQs carry the benchmark traffic on that SUT. To discover candidates:

```bash
for dev in eth1 eth2; do
  pci=$(basename "$(readlink -f /sys/class/net/$dev/device)")
  echo
  echo "$dev -> $pci"
  grep "$pci" /proc/interrupts
done
```

If you decide to pin IRQs, fill the YAML fields and rerun all cases from scratch. Do not compare pinned and unpinned runs.

## 8. Experiments And Packet Sizes

The paper profile is PDR-only:

```yaml
experiments:
  - name: ipv4-forward-78-pdr
    rate: pdr
    frame_size: 78
    runs: 10
    starting_tx_rate_pps: 50000
    max_tx_rate_pps: 3000000
    ndr_window_pps: 5000
    delivery_ratio: 0.995
```

`ipv4-forward-78-pdr` uses a 78-byte Ethernet frame without FCS. SRPerf's `*-64.pcap` files are 64 bytes at IPv6 L3, which is 78 bytes once the Ethernet header is included. This is the default paper-style packet size while still using IPv4 traffic.

PDR fields:

- `starting_tx_rate_pps`: first lower bound. It must be safely below the real PDR.
- `max_tx_rate_pps`: upper search bound. Raise it only if the result gets close to this value.
- `ndr_window_pps`: final binary-search window. Lower is more precise and slower.
- `delivery_ratio`: threshold. `0.995` means drop ratio <= 0.5%.
- `runs`: independent PDR searches used to compute mean and standard deviation.

## 9. Running

Use the debug profile first:

```bash
cd /path/to/bonet/validation/macro_perf
./runner.py --config config.debug.yaml
```

Run the paper profile:

```bash
./runner.py --config config.paper.yaml
```

Or run only one experiment:

```bash
./runner.py --config config.paper.yaml --experiments ipv4-forward-78-pdr
```

Or run only selected cases:

```bash
./runner.py --config config.paper.yaml --cases framework,baseline
./runner.py --config config.paper.yaml --cases kernel
```

Skip rebuilding object files:

```bash
./runner.py --config config.paper.yaml --skip-build
```

Leave the final SUT configuration in place for manual inspection:

```bash
./runner.py --config config.paper.yaml --skip-clean
```

Without `--skip-clean`, the runner detaches XDP and removes the benchmark route and neighbor at the end.

## 10. What The Runner Does

For each case, the runner:

1. Builds the selected XDP object unless `--skip-build` is used.
2. Configures SUT interface MACs and IPv4 addresses.
3. Enables IPv4 forwarding and disables rp_filter on the involved interfaces.
4. Installs the static neighbor for the TRex receive port.
5. Installs the benchmark route toward TRex port 1.
6. Disables common offloads with `ethtool`.
7. Applies optional IRQ pinning from YAML when those fields are set.
8. Attaches the selected XDP program, or detaches XDP for `kernel`.
9. Runs the configured TRex experiments.

## 11. Results

Results are written under:

```bash
validation/macro_perf/results/
```

The output filename is timestamped:

```text
bonet-ipv4-forward-YYYYMMDD-HHMMSS.json
```

Generated pcaps are written under:

```bash
validation/macro_perf/pcap/
```

Both directories are ignored by git.

## 12. Checklist For A New Testbed

Before the real run:

- Configure `/etc/trex_cfg.yaml` with SUT destination MACs, not loopback TRex MACs.
- Set `port_bandwidth_gb` to the real link speed, e.g. `100` for 100G.
- Start TRex and verify both links are up.
- Verify `trex.api_path` imports `trex_stl_lib` on the orchestrator machine.
- Verify `sut.ssh.host`, `sut.ssh.user`, and `sut.ssh.key`.
- Stop `irqbalance`.
- Leave IRQ YAML fields empty unless you are intentionally running a separately validated IRQ-pinned experiment.
- Verify TRex port 0 is cabled to `network.sut_rx_iface`.
- Verify `network.sut_tx_iface` is cabled to TRex port 1.
- Verify all four MAC addresses in YAML.
- Run `config.debug.yaml` first.
- Run `config.paper.yaml` only after debug delivery ratios make sense.

## 13. Troubleshooting

If TRex import fails, check `trex.api_path`:

```bash
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/trex/v3.08/automation/trex_control_plane/interactive")
import trex_stl_lib.api
print("ok")
PY
```

If no packets arrive at the SUT, verify TRex is using DUT/SUT destination MACs in `/etc/trex_cfg.yaml` and restart TRex.

If no packets return to TRex port 1, check the SUT route and neighbor:

```bash
ip route get 48.0.0.2
ip neigh show dev eth2
ip -s link show eth1
ip -s link show eth2
```

If native XDP attach fails, try generic XDP:

```yaml
xdp:
  mode: xdpgeneric
  section: xdp
```

If a PDR run aborts because the lower bound is below the threshold, reduce `starting_tx_rate_pps`, for example from `50000` to `10000`.

If the final PDR is close to `max_tx_rate_pps`, raise `max_tx_rate_pps` and rerun. If the final PDR is far below the upper bound, leave the upper bound lower to save time.
