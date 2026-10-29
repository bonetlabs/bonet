# Portability across kernels and compilers

Two checks of BONet's default build (XDP, asm globals):

- **Compilers** (`compilers.sh`, no VM, a few seconds): the asm globals must
  be the same code with every supported clang, 16 to 22.
- **Kernels** (`matrix.sh`, one VM per kernel): the globals, the unit cases of
  `tests/units` and the 14 workloads of `../framework` must load on every
  kernel from 5.12 on and behave as recorded in `tests/units/expected.json`.
  Both the asm and the C globals are tested, built with any number of
  compilers. The summary also gives the verifier's instructions and the stack
  depth of the paper's workloads on each kernel.

Nothing here needs root on the host: compilers and kernels are downloaded
and unpacked into directories of your choice, and the tests run as root inside
the VMs.

## Requirements

- Linux on x86-64, with `/dev/kvm` usable by your user (the VMs use KVM).
- `curl`, `dpkg-deb`, `python3`, `make`, a host C compiler and the libbpf,
  libelf and zlib headers (Ubuntu: `libbpf-dev libelf-dev zlib1g-dev`), for
  the loaders `tests/units/build/run_case` and
  `../exec_metrics/build/verifier_stats`.
- `qemu-system-x86` and [virtme-ng](https://github.com/arighi/virtme-ng). It
  installs without root:

  ```sh
  pip install --target ~/vng virtme-ng
  export PYTHONPATH=~/vng PATH=~/vng/bin:$PATH
  ```

- `bpftool`, only for `compilers.sh -s`.

## Compilers

```sh
./fetch-clang.sh ~/bnt-clang                      # every compiler of clang.txt
./compilers.sh -o /tmp/bnt-cc \
    clang16=~/bnt-clang/bin/clang16 clang17=~/bnt-clang/bin/clang17 \
    clang18=~/bnt-clang/bin/clang18 clang19=~/bnt-clang/bin/clang19 \
    clang20=~/bnt-clang/bin/clang20 clang21=~/bnt-clang/bin/clang21 \
    clang22=~/bnt-clang/bin/clang22
```

`fetch-clang.sh` takes the exact package versions listed in `clang.txt` from
the Ubuntu archive and writes `~/bnt-clang/bin/<label>`, a script that runs
that clang with its own libraries. Any other clang can be passed as well.

`compilers.sh` builds `tests/globals` with each compiler and prints, for each,
whether its globals are the same code as with the first one. Exit status 1
means some compiler differs. With `-s DIR`, where `DIR` holds the objects of
`../exec_metrics/candidates.py`, it also checks each build against the
configurations chosen for the asm (`../exec_metrics/check_asm.py`).

## Kernels

```sh
./fetch-kernels.sh ~/bnt-kernels                  # every kernel of kernels.txt (about 14 GB)
setsid nohup ./matrix.sh -k ~/bnt-kernels -o ~/bnt-matrix \
    -c clang20=~/bnt-clang/bin/clang20 > ~/bnt-matrix.log 2>&1 &
```

`fetch-kernels.sh` downloads the mainline builds of kernel.ubuntu.com and the
Ubuntu kernels listed in `kernels.txt`, and unpacks image and modules. Names
can be given to fetch only some.

`matrix.sh` builds everything with each `-c` compiler (`build.sh`), then
boots each kernel in a VM that runs `test.sh`, and prints the summary at the
end. 38 kernels and seven compilers take about half an hour. Started again
with the same arguments, it skips the kernels already tested. Give kernel
names after the options to test only those, for instance three compilers on
three kernels:

```sh
./matrix.sh -k ~/bnt-kernels -o ~/bnt-cross -c clang16=... -c clang18=... -c clang22=... \
    v5.12.19 v6.1 ubuntu-7.0.0-38
```

Run it detached as above: virtme-ng can hang when started from a tmux pane.

### Output

`OUT/results/<kernel>/<compiler>/` holds, from inside the VM:

| file | content |
|---|---|
| `globals.tsv` | `verifier_stats` on every global, asm (`globals.o`) and C (`globals_c.o`) |
| `units.txt` | `tests/units/check.py`: each case against `expected.json` |
| `workloads.tsv` | `verifier_stats` on the workloads, asm then C |
| `baseline.tsv` | `verifier_stats` on the plain eBPF workloads |
| `log/` | the verifier log of every program that failed to load |

`summary.py OUT/results` prints them again, for instance:

```
kernel             compiler     globals asm      C  units asm        C workloads asm      C
v5.12.19           clang21            94/94  94/94    133/133  133/133         14/14  14/14
v5.12.19           clang22            94/94  92/94    133/133  131/133         14/14  14/14
```

then, for MMLF, DNAT and ENCAP, the verifier's processed instructions and
the stack depth (main program plus globals) as `plain/asm/C`.

What to expect with the current sources:

- The asm globals load and give the expected results on every kernel of
  `kernels.txt`, with every compiler from 16 to 22.
- The C globals load everywhere except with clang 22 on kernels up to 6.3,
  where the verifier rejects `tcp_recompute_csum_v4` and
  `udp_recompute_csum_v4`. The default build uses the asm globals, which do
  not depend on the compiler.
- Two plain workloads do not load with some compilers, on every kernel:
  `xdp_acl_firewall_e2e` with clang 19 to 22, `xdp_srv6_encap` with clang 17.
- The verifier's instructions for the BONet workloads change by a few percent
  between kernel series; those of the plain workloads do not. The stack depth
  is the same code everywhere, but from 6.7 (and 6.6.159) the kernel rounds
  each frame up to 8 bytes, so the reported total grows.

## Files

| file | |
|---|---|
| `clang.txt` | compilers: label, Ubuntu source package, version, packages |
| `kernels.txt` | kernels: mainline name, or name and package URL |
| `fetch-clang.sh`, `fetch-kernels.sh` | download and unpack, without root |
| `compilers.sh`, `compare_globals.py` | same asm globals with every compiler |
| `build.sh` | everything `matrix.sh` loads, built with one compiler |
| `matrix.sh`, `test.sh` | one VM per kernel, `test.sh` inside it |
| `summary.py` | the tables above |
