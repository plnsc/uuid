#!/usr/bin/env node
// JavaScript driver for the cross-implementation benchmark.
//
//   node bench/bench.js <op> <n>
//
// Prints "<op> <ns per op> <checksum>". Timing is inside the process, so startup
// is excluded, and the corpus for the read operations is built before the clock
// starts. The checksum only keeps operations from being optimized away.
// bench/run.sh drives this; the rules are in bench/README.md.

"use strict";

const u = require("../uuid_v7");

const op = process.argv[2];
const n = Number(process.argv[3]);
const warmup = Math.max(Math.floor(n / 10), 1);
const clock = process.hrtime.bigint;

const corpus = Array.from({ length: 1024 }, () => u.generate());
let total = 0n;
let t0, t1;

if (op === "generate") {
  for (let i = 0; i < warmup; i++) u.generate();
  t0 = clock();
  for (let i = 0; i < n; i++) total += BigInt(u.generate().length);
  t1 = clock();
} else if (op === "generate_random") {
  for (let i = 0; i < warmup; i++) u.generateRandom();
  t0 = clock();
  for (let i = 0; i < n; i++) total += BigInt(u.generateRandom().length);
  t1 = clock();
} else if (op === "decode") {
  for (let i = 0; i < warmup; i++) u.decode(corpus[i & 1023]);
  t0 = clock();
  for (let i = 0; i < n; i++) total += BigInt(u.decode(corpus[i & 1023]).rand_a);
  t1 = clock();
} else if (op === "predicate") {
  for (let i = 0; i < warmup; i++) u.isValid(corpus[i & 1023]);
  t0 = clock();
  for (let i = 0; i < n; i++) total += u.isValid(corpus[i & 1023]) ? 1n : 0n;
  t1 = clock();
} else {
  console.error(`unknown op: ${op}`);
  process.exit(1);
}

console.log(`${op} ${(Number(t1 - t0) / n).toFixed(1)} ${total}`);
