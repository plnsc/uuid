#!/bin/bash
# Runs the four public operations across all six implementations and prints one
# table of ns per operation.
#
#   bench/run.sh [n] [reps]        # defaults: 100000 iterations, 5 repetitions
#
# Each cell is the minimum across repetitions, the run least contaminated by other
# load. Timing is inside each driver, so startup and corpus setup are excluded.
# Numbers are comparable between columns only on one machine in one run: never
# carry them across machines.
#
# Needs ruby, python3, node, lua and cc on PATH, plus rustc: if rustup installed
# it without touching your PATH, this falls back to ~/.cargo/bin/rustc, and $RUSTC
# overrides either. Compiled drivers are built into bench/ (both are gitignored).

set -u

cd "$(dirname "$0")/.."

N=${1:-100000}
REPS=${2:-5}
OPS="generate generate_random decode predicate"
LANGS="ruby python js lua rust c"

RUSTC=${RUSTC:-$(command -v rustc || true)}
if [ -z "$RUSTC" ] && [ -x "$HOME/.cargo/bin/rustc" ]; then
  RUSTC="$HOME/.cargo/bin/rustc"
fi
if [ -z "$RUSTC" ]; then
  echo "rustc not found: add it to PATH or set RUSTC" >&2
  exit 1
fi

"$RUSTC" --edition 2021 -O bench/bench.rs -o bench/bench_rs || {
  echo "rustc build failed" >&2; exit 1; }
cc -std=c11 -O2 -pthread bench/bench.c -o bench/bench_c || {
  echo "cc build failed" >&2; exit 1; }

run_one() {  # <lang> <op> <n>
  case $1 in
    ruby)   ruby bench/bench.rb "$2" "$3" ;;
    python) python3 bench/bench.py "$2" "$3" ;;
    js)     node bench/bench.js "$2" "$3" ;;
    lua)    lua bench/bench.lua "$2" "$3" ;;
    rust)   bench/bench_rs "$2" "$3" ;;
    c)      bench/bench_c "$2" "$3" ;;
  esac
}

echo "UUIDv7 benchmark: n=$N, min of $REPS runs, ns per operation"
echo
printf '%-16s' "op"
for lang in $LANGS; do printf '%10s' "$lang"; done
echo

for op in $OPS; do
  printf '%-16s' "$op"
  for lang in $LANGS; do
    best=""
    for _ in $(seq 1 "$REPS"); do
      value=$(run_one "$lang" "$op" "$N" | awk '{print $2}')
      [ -z "$value" ] && { echo " (failed: $lang $op)" >&2; exit 1; }
      best=$(awk -v a="$value" -v b="$best" 'BEGIN { print (b == "" || a < b) ? a : b }')
    done
    printf '%10s' "$best"
  done
  echo
done
