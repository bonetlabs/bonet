# framework

eBPF programs written with the `bnt` library, one per `../baseline/` counterpart
of the same name. This is the `bnt` side of the validation comparison.

Each file is either an XDP program (`xdp_*`) or a TC program (`tc_*`).

Build (from this directory):

```bash
make            # default BNT_INLINE_ALL=0 (globals mode)
make clean
```

See [`../README.md`](../README.md) (section "Verification modes") for the other
build modes and how to select them. The fully inlined build lives in
`../framework_inlined/`.

Check they pass the kernel verifier (from the repo root):

```bash
./verify_all.sh validation/framework
```
