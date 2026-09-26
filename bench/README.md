# Benchmark

Compares the six implementations on the four public operations. Run it with:

```bash
bench/run.sh              # n=100000, min of 5 runs
bench/run.sh 200000 7     # heavier
```

One driver per language (`bench.rb`, `bench.py`, `bench.js`, `bench.lua`,
`bench.rs`, `bench.c`), each taking `<op> <n>` and printing
`<op> <ns per op> <checksum>`. `run.sh` builds the two compiled ones, runs every
cell `reps` times, and prints the minimum.

## Rules the numbers depend on

- **Timing is inside the process.** Interpreter startup and the 1024-UUID corpus
  for `decode` and `predicate` are both excluded, so the cells measure the
  operation and nothing else.
- **Minimum, not mean.** The minimum is the run least contaminated by other load.
  Repeating one cell seven times on the reference machine spread 2.8%, so treat
  differences under ~5% as noise.
- **The checksum is load-bearing.** Rust uses `black_box` and C writes through a
  `volatile`; without them the optimizer deletes calls whose results go unused.
- **Lua's column is CPU time**, from `os.clock`, because standard Lua has no
  monotonic wall clock. Nothing here blocks, so the two track each other, but it
  is the one column not measured on a wall clock.
- **Only the public API is measured.** An earlier one-off also timed the raw
  entropy draw, which meant reaching into private internals six different ways.
  That was a diagnostic, not something to maintain here.
- Numbers are comparable between columns only within one run on one machine.
  Re-run rather than quoting the table in `README.md`, which records one machine.
