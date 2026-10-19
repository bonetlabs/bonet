# Forwarding throughput (PDR)

Measures the Packet Delivery Rate of the XDP workloads on two machines: a TRex
traffic generator and a System Under Test. Everything is driven from this
machine with `remote.py`; the run itself continues on the TRex machine if this
one disconnects.

PDR is the highest offered rate at which at least 99.5% of the packets come
back, found by binary search. Each workload/case pair is searched once per
repetition, in an order shuffled per repetition. Before each search the SUT's
output is compared with the packets the workload must produce; a mismatch
stops the run.

## Layout

```text
testbed.yaml       machines, links, MACs, pinned queue/CPU (the only per-testbed file)
profiles/          what to measure: build flags, cases, workloads, PDR method
  paper.yaml       Fig. 4: MMLF, DNAT, ENCAP x plain, inline, globals C, globals asm, kernel
  debug.yaml       paper.yaml with one short search each (~15 min)
  runtime.yaml     run time of the program per packet, from bpf_stats (no PDR)
  legacy.yaml      the experiments of the old configs (IPv4/IPv6, encapsulations, TC)
remote.py          the driver (below)
report.py          per-run and cumulative reports
bench/             copied to the machines for each run
  runner.py        on TREX: checks and PDR searches, through the TRex API
  sut.sh           on the SUT: attach a case, counters, cleanup
  packets.py       traffic and the expected output of each workload
results/           runs (ignored by git)
```

## Run time per packet

`-p runtime` measures something else on the same setup: how long the XDP
program itself runs per packet on the SUT, with the real NIC, cache and
batching. There is no PDR search. For each workload and case, after the usual
check, `kernel.bpf_stats_enabled` is turned on, TRex sends traffic at each rate
of `runtime.rates_pps` (one rate below every PDR, so that all cases run at the
same load), and `run_time_ns` and `run_cnt` of the attached program are read
before and after the trial: their ratio is the time per packet, the globals
included. The statistics cost two clock reads per run, so they are on only
during these trials, never during a PDR search. The kernel case has no program
and is left out.

```bash
./remote.py run -p runtime --note "run time per packet"   # about 40 minutes
```

The results go to `runtime.csv`, and the report gives the mean time per packet
of each case with its 95% interval and its difference from the plain program.

## Testbed

Two machines reachable from here by ssh, named `TREX` and `SUT` in
`~/.ssh/config` (other names: set `trex.ssh` and `sut.ssh` in `testbed.yaml`),
with passwordless sudo and at least two cables between them. `./remote.py
setup` finds the rest and writes it to `testbed.yaml`:

- the links, from which SUT MAC answers an all-nodes ping on each TREX port;
  ordered by TREX PCI address, the first carries the traffic to the SUT, the
  second the forwarded traffic back;
- PCI addresses, MACs, users, home directories, CPUs (TRex worker threads:
  2..n-1), channels (the pinned RX queue: 2, or the last one);
- the control path: the runner on TREX drives the SUT over ssh, to the SUT's
  management address if TREX can reach it, otherwise over a third link with
  192.168.250.1/.2 (on FABRIC the VMs cannot reach each other's management
  addresses).

Values already in `testbed.yaml` are kept: edit to override, delete a key (or
the file) to have it found again. `./remote.py topology` shows what setup would
find without changing anything.

On the SUT all traffic is steered to one RX queue (`sut.rx_queue`), and its
interrupt, with that of the TX queue XDP_REDIRECT uses, is pinned to
`sut.rx_cpu`; irqbalance is stopped. The check verifies that the RX interrupts
land on that CPU.

TRex is downloaded from trex-tgn.cisco.com with a plain `curl`; if that fails
(the server has had certificate problems), setup says so and TRex has to be put
in `trex.trex_dir` by hand.

## Use

One-time setup of a new slice (idempotent):

```bash
./remote.py setup         # testbed.yaml, packages, TRex, /etc/trex_cfg.yaml, hugepages, ssh key
./remote.py trex start    # TRex server in tmux on TREX
```

A run:

```bash
./remote.py run -p paper --note "asm globals vs C globals"
./remote.py status              # progress, ETA, last log lines
./remote.py fetch --wait        # download every 15 min until done, rebuilding the reports
```

`./remote.py resume` restarts a stopped run where it left off (completed
searches are kept), `./remote.py stop` interrupts it, `./remote.py report`
rebuilds the reports from what was downloaded. A paper run takes about 11 h.

The report needs matplotlib: `python3 -m venv .venv && .venv/bin/pip install
matplotlib pyyaml` (remote.py uses `.venv` when present).

## Cases

| case | object |
|---|---|
| `plain` | `baseline/xdp_<program>.c` |
| `inline` | `framework/xdp_<program>.c`, `-DBNT_INLINE_ALL=1` |
| `globals-c` | `framework/xdp_<program>.c`, `-DBNT_ASM_GLOBALS=0`: the C globals |
| `globals-asm` | `framework/xdp_<program>.c`: the default build, with `src/bnt_asm_globals.h` |
| `kernel` | no program: iptables/iproute2 equivalent (`bench/sut.sh: kernel_setup`) |

Every object of a run is built here with the profile's compiler and flags
(clang 18.1.3, `-mcpu=v3`, as global mode requires) and pushed to the SUT; the
objects and their hashes are kept with the run.

## Checks

Before every search, 64 packets are sent at 1 kpps and captured on TRex port 1:

- each must equal the workload's model in `bench/packets.py` (MMLF: TOS 0x2e,
  TTL-1; DNAT: daddr 10.7.0.1, IP and UDP checksums, TTL-1; ENCAP: outer IPv6
  fd08::2 > fd03::2; for the kernel, the inner hop limit is decremented and the
  outer flow label is not checked). Workloads without a model are only checked
  to come back;
- the kernel's forwarding counters must not move for XDP/TC cases (a program
  returning XDP_PASS would otherwise be forwarded by the kernel and look fine),
  and must count every packet for the kernel case;
- the RX interrupts must be on the pinned CPU;
- a program must be attached.

## Results

`results/<run>/`:

- `trials.csv`: every TRex trial (rate, tx/rx packets, delivery ratio, warm-up or measured)
- `searches.csv`: every PDR search (result, final bounds, steps)
- `runtime.csv`: every runtime trial (`-p runtime`: rate, tx/rx packets, run_cnt, run_time_ns)
- `checks.csv`: every check, with the attached program's tag and sizes
- `meta.json`, `plan.json`, `git.diff`, `objs/`: what was run, from which commit
- `log.txt`, `sut-info.txt`
- `report/summary.md`: the run's report, with `pdr.png`/`pdr.pdf` (Fig. 4),
  `reps.png` (every search) and `summary.csv`

`results/REPORT.md`, `history.csv`, `history-<profile>.png`: every run,
side by side.

Means come with 95% confidence intervals (Student t over the repetitions);
differences between cases are differences of means with Welch's 95% interval.
