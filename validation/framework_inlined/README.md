# framework_inlined

The same programs as [`../framework/`](../framework/), built with
`BNT_INLINE_ALL=1` (everything inlined into the program, no global subprograms).

This directory keeps **no sources of its own**: its `Makefile` compiles
`../framework/`'s `.c` files with the inline flag, dropping the object files here.
That way the globals objects (in `../framework/`) and the inline objects (here)
coexist for side-by-side comparison.

The inline build differs from the globals build **only on XDP**. On TC,
`BNT_INLINE_ALL` is forced to `1` regardless, so the `tc_*.o` produced here are
byte-identical to `../framework/`'s. The `macro_perf` `framework-inlined` case
therefore attaches the `xdp_*` objects from this directory.

Build (from this directory):

```bash
make
make clean
```

Check they pass the kernel verifier (from the repo root):

```bash
./verify_all.sh validation/framework_inlined
```
