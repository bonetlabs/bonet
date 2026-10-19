# Execution time in the kernel

Times the XDP workloads of `../framework` (and `../baseline`) and the globals
on their unit cases with `BPF_PROG_TEST_RUN`, on one machine. It complements
`../exec_metrics`, which counts executed instructions in an interpreter, and
`../macro_perf`, which measures forwarding throughput on two machines.

`bench_prog` runs a program in rounds of many iterations with
`BPF_F_TEST_XDP_LIVE_FRAMES`, so the action is carried out: `XDP_TX` and
`XDP_REDIRECT` send the packet out of a veth. Live frames reuse the pages as
the last iteration left them, so every run goes through `bench_wrap.bpf.c`,
which copies the original packet back and tail calls the program: a program
that rewrites or grows the packet is timed on a fresh one each time. Before
the rounds, one plain run prints the action and the output packet, to check
that the packet takes the path meant to be measured.

## Running

As root, in a scratch VM (`vm_net.sh` changes routes and forwarding settings):

```bash
make                                       # here and in ../exec_metrics
IF=$(../exec_metrics/vm_net.sh build/sink.o)
./bench_workloads.py $IF asm=WL_ASM c=WL_C inline=WL_INLINE baseline=WL_BASE > workloads.tsv
./bench_globals.py ../../tests/units/build/gen/cases.json $IF \
    asm=../../tests/units/build/default c=../../tests/units/build/c > globals.tsv
```

`WL_*` are directories with one `<workload>.o` per workload, as
`make -C ../framework` builds them. `vm_net.sh` sets up the routes that make
`bpf_fib_lookup` succeed and attaches `build/sink.o` to the other end of the
veth, where it counts and drops what arrives.

`bench_workloads.py` prints, for each build and case of
`../exec_metrics/workloads.py`: the action and packet of the check run, the ns
per packet of each round, and the packets that reached the other end. It also
times `build/ref/<ACTION>.o`, a program that only takes the case's action, as
the build `ref`: a workload costs its time minus ref's. An `XDP_TX` or
`XDP_REDIRECT` case must deliver every packet (`-n` × `-r`).

`bench_globals.py` times each case program of `tests/units` with its return
value patched from `XDP_PASS` to `XDP_DROP`, since building an skb costs more,
and varies more, than most globals. `build/ref_case.o`, the same program
without the call, is the build `ref`.

## Reading the numbers

The time includes the action: about 20 ns for `XDP_DROP` and 60 ns for
`XDP_REDIRECT` in a VM, more than many globals cost. Rounds of the same build
differ by a few ns, and on a laptop with power and core types changing under
the VM, builds with the same code can differ by 5%. Differences of a few ns
between builds need a pinned core on a quiet machine.
