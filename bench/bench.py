#!/usr/bin/env python3
"""Python driver for the cross-implementation benchmark.

    python3 bench/bench.py <op> <n>

Prints "<op> <ns per op> <checksum>". Timing happens inside the process, so
interpreter startup is excluded, and the corpus for the read operations is built
before the clock starts. The checksum exists only so no operation can be
optimized away. bench/run.sh drives this; see bench/README.md for the rules.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import uuid_v7  # noqa: E402

op, n = sys.argv[1], int(sys.argv[2])
warmup = max(n // 10, 1)
clock = time.perf_counter_ns

corpus = [uuid_v7.generate() for _ in range(1024)]
total = 0

if op == "generate":
    for _ in range(warmup):
        uuid_v7.generate()
    t0 = clock()
    for _ in range(n):
        total += len(uuid_v7.generate())
    t1 = clock()
elif op == "generate_random":
    for _ in range(warmup):
        uuid_v7.generate_random()
    t0 = clock()
    for _ in range(n):
        total += len(uuid_v7.generate_random())
    t1 = clock()
elif op == "decode":
    for i in range(warmup):
        uuid_v7.decode(corpus[i & 1023])
    t0 = clock()
    for i in range(n):
        total += uuid_v7.decode(corpus[i & 1023])["rand_a"]
    t1 = clock()
elif op == "predicate":
    for i in range(warmup):
        uuid_v7.is_valid(corpus[i & 1023])
    t0 = clock()
    for i in range(n):
        total += uuid_v7.is_valid(corpus[i & 1023])
    t1 = clock()
else:
    sys.exit(f"unknown op: {op}")

print("%s %.1f %d" % (op, (t1 - t0) / n, total))
