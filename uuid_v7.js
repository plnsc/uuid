#!/usr/bin/env node
// =============================================================================
// UUIDv7: JavaScript implementation of RFC 9562 §5.7
// https://www.rfc-editor.org/rfc/rfc9562#section-5.7
//
// Siblings (uuid_v7.rb, .py, .lua, .rs, .c) share this field layout and the same
// monotonicity contract. CommonJS, so it runs as `node uuid_v7.js` with no
// package.json. Needs a global Web Crypto (Node 19+) and BigInt (ES2020).
//
// Three language traits shape this implementation:
//   * Numbers are IEEE-754 doubles, exact only to 2^53, so packing uses BigInt
//     and decode returns rand_b as a BigInt (`assemble`, `decode`).
//   * Single-threaded event loop, so no mutex (`Generator`).
//   * No integer type, so 3.0 and 3 are the same value (`generateBulk`).
//
// 128-bit field layout (big-endian, MSB first):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           unix_ts_ms                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          unix_ts_ms           |  ver  |        rand_a         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |var|                         rand_b                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           rand_b                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Field       Bits    Position        Description
// ─────────────────────────────────────────────────────────────────
// unix_ts_ms  48      [127..80]  Unix epoch timestamp (milliseconds)
// ver          4      [79..76]   Version = 0b0111 (7)
// rand_a      12      [75..64]   Random data / monotonic counter
// var          2      [63..62]   Variant = 0b10 (RFC 4122 / 9562)
// rand_b      62      [61..0]    Cryptographically random data
// =============================================================================

"use strict";

// ── Constants ────────────────────────────────────────────────────────────────

const VERSION = 0x7;   // 4-bit version field value
const VARIANT = 0b10;  // 2-bit variant field value (MSBs of octet 8)

const RAND_A_BITS = 12;
const RAND_B_BITS = 62;
const MAX_RAND_A = (1 << RAND_A_BITS) - 1;              // 0xFFF, fits a Number
const MAX_RAND_B = (1n << BigInt(RAND_B_BITS)) - 1n;    // 0x3FFF_FFFF_FFFF_FFFF

// RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── Entropy source ───────────────────────────────────────────────────────────

// Web Crypto is a CSPRNG, like Ruby's SecureRandom, Python's os.urandom, and the
// /dev/urandom Rust and C read. There is no Math.random fallback: it is not
// cryptographically secure, and failing loudly beats degrading silently.
//
// Bytes are drawn ahead, so one getRandomValues call serves many draws: per-call
// measured ~2450 ns against ~43 ns amortized over a block this size. All six
// siblings pool for that reason, and the other five must guard the pool against
// fork(), which would hand parent and child the same bytes. This one need not:
// Node has no fork, and a worker thread gets its own isolate, hence its own pool.
//
// Reading the block through a DataView matters as much as the pooling:
// getBigUint64 replaces an eight-step BigInt fold that cost ~490 ns on its own.
const _pool = new Uint8Array(4096);
const _view = new DataView(_pool.buffer);
let _poolOff = _pool.length;

/**
 * Returns `bits` random bits. Every caller asks for a power-of-two range, so
 * masking suffices, with no modulo bias to correct.
 *
 * @param {number} bits
 * @returns {bigint}
 */
function randomBits(bits) {
  if (_poolOff + 8 > _pool.length) {
    crypto.getRandomValues(_pool);
    _poolOff = 0;
  }

  const v = _view.getBigUint64(_poolOff);
  _poolOff += 8;

  return v & ((1n << BigInt(bits)) - 1n);
}

// ── Assembly ─────────────────────────────────────────────────────────────────

/**
 * Packs the fields into a 128-bit integer and formats the UUID string.
 *
 * A Number is exact only to 2^53, too narrow for a 128-bit value, so packing is
 * done in BigInt. Positions count 127 as the MSB, the opposite of the RFC-style
 * ruler in the file header, which numbers bits from 0 left to right:
 *
 *   [127..80]  unix_ts_ms   (48 bits)
 *   [79..76]   ver          ( 4 bits)  -> 0b0111
 *   [75..64]   rand_a       (12 bits)
 *   [63..62]   var          ( 2 bits)  -> 0b10
 *   [61..0]    rand_b       (62 bits)
 *
 * Keep the template literal. uuid_v7.rs and uuid_v7.c emit the nibbles by hand
 * because their formatting libraries parse a template at run time, but
 * toString(16) is native while a 32-step loop over BigInt is not: hand-rolling
 * measured 11.8x slower (3056 ns against 260), the widest margin of the four.
 *
 * @param {number} unixTsMs 48-bit millisecond timestamp
 * @param {number} randA    12-bit value (counter or random)
 * @param {bigint} randB    62-bit random value
 * @returns {string} formatted UUID
 */
function assemble(unixTsMs, randA, randB) {
  const n =
    (BigInt(unixTsMs) << 80n) |
    (BigInt(VERSION) << 76n) |
    (BigInt(randA & MAX_RAND_A) << 64n) |
    (BigInt(VARIANT) << 62n) |
    (randB & MAX_RAND_B);

  const hex = n.toString(16).padStart(32, "0");

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}` +
         `-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// ── Generator ────────────────────────────────────────────────────────────────

/**
 * UUIDv7 generator.
 *
 * Method 2 (monotonic counter) of RFC 9562 §6.2: rand_a is a counter re-seeded
 * on each new millisecond, so ordering is strict even within one millisecond;
 * rand_b is always fresh random data. On overflow (> 0xFFF) the timestamp is
 * bumped 1 ms, the "counter rollover" that section permits.
 *
 * No mutex, unlike the Ruby, Python, Rust and C siblings: JavaScript runs one
 * event loop and nextState contains no await, so nothing can interleave it.
 * Worker threads get their own isolate and generator, so they never share this
 * state.
 *
 *   const gen = new Generator();
 *   gen.generate();  // => "018f2e39-59b7-7e82-9c3a-4d5b9e2f1a60"
 */
class Generator {
  constructor() {
    this.lastMs = 0;  // last timestamp used
    this.seq = 0;     // rand_a counter within a millisecond
  }

  /**
   * Advances internal state and returns [ms, seq, randB].
   *
   * @returns {[number, number, bigint]}
   */
  nextState() {
    let ms = Date.now();

    if (ms > this.lastMs) {
      // ── New millisecond: re-seed the counter ─────────────────────────────
      // An 11-bit seed keeps the MSB free, leaving room for 2048 increments.
      this.seq = Number(randomBits(RAND_A_BITS - 1));
      this.lastMs = ms;
    } else {
      // ── Same (or rare clock regression) millisecond: increment ───────────
      this.seq += 1;

      if (this.seq > MAX_RAND_A) {
        // Counter exhausted, so bump the virtual clock by 1 ms (RFC 9562 §6.2)
        this.lastMs += 1;
        this.seq = Number(randomBits(RAND_A_BITS - 1));
      }

      ms = this.lastMs;
    }

    return [ms, this.seq, randomBits(RAND_B_BITS)];
  }

  /**
   * Generate a UUIDv7, monotonic within 1 ms.
   *
   * @returns {string} lowercase UUID string
   */
  generate() {
    return assemble(...this.nextState());
  }

  /**
   * Generate a UUIDv7 by Method 1, with fully random rand_a and rand_b.
   * Simpler, but NOT monotonic within a millisecond.
   *
   * @returns {string}
   */
  generateRandom() {
    return assemble(
      Date.now(),
      Number(randomBits(RAND_A_BITS)),
      randomBits(RAND_B_BITS),
    );
  }

  /**
   * Generate `n` monotonically ordered UUIDv7s.
   *
   * @param {number} n number of UUIDs to generate (must be positive)
   * @returns {string[]}
   * @throws {TypeError} if `n` is not a positive integer
   */
  generateBulk(n) {
    if (!Number.isInteger(n) || n <= 0) {
      throw new TypeError("n must be a positive integer");
    }

    const out = new Array(n);
    for (let i = 0; i < n; i++) out[i] = this.generate();
    return out;
  }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/**
 * Decodes a UUIDv7 string into its constituent fields.
 *
 * rand_b is a BigInt because 62 bits exceed the 2^53 a Number represents
 * exactly. unix_ts_ms (48 bits) and rand_a (12 bits) fit, so they stay Numbers.
 *
 * @param {string} uuid UUID string, any letter case
 * @returns {{uuid: string, version: number, variant: string, unix_ts_ms: number,
 *            timestamp: Date, rand_a: number, rand_b: bigint}}
 *   uuid        canonical lowercase UUID string
 *   version     must be 7
 *   variant     e.g. "0b10"
 *   unix_ts_ms  Unix timestamp in milliseconds
 *   timestamp   reconstructed from unix_ts_ms
 *   rand_a      12-bit rand_a field value
 *   rand_b      62-bit rand_b field value
 * @throws {TypeError} if the format, version, or variant is invalid
 */
function decode(uuid) {
  if (typeof uuid !== "string" || !UUID_REGEX.test(uuid)) {
    throw new TypeError(`Invalid UUID format: ${JSON.stringify(uuid)}`);
  }

  const n = BigInt(`0x${uuid.replace(/-/g, "")}`);

  const version = Number((n >> 76n) & 0xfn);
  const variant = Number((n >> 62n) & 0x3n);

  if (version !== VERSION) {
    throw new TypeError(
      `Not a UUIDv7 (version field = ${version}, expected 7)`,
    );
  }

  if (variant !== VARIANT) {
    throw new TypeError(
      `Invalid variant bits (got 0b${variant.toString(2).padStart(2, "0")}, expected 0b10)`,
    );
  }

  const unixTsMs = Number((n >> 80n) & 0xffffffffffffn);

  return {
    uuid: uuid.toLowerCase(),
    version,
    variant: `0b${variant.toString(2).padStart(2, "0")}`,
    unix_ts_ms: unixTsMs,
    timestamp: new Date(unixTsMs),
    rand_a: Number((n >> 64n) & BigInt(MAX_RAND_A)),
    rand_b: n & MAX_RAND_B,
  };
}

/**
 * True if `uuid` is a well-formed UUIDv7.
 *
 * @param {string} uuid
 * @returns {boolean}
 */
function isValid(uuid) {
  try {
    decode(uuid);
    return true;
  } catch (e) {
    if (e instanceof TypeError) return false;
    throw e;
  }
}

// ── Module-level convenience API ─────────────────────────────────────────────

// Shared default generator, created eagerly at load time.
const defaultGenerator = new Generator();

/** Monotonic UUIDv7 from the shared default generator. @returns {string} */
const generate = () => defaultGenerator.generate();

/** UUIDv7 with fully random rand_a and rand_b (Method 1). @returns {string} */
const generateRandom = () => defaultGenerator.generateRandom();

/** `n` monotonically ordered UUIDv7s from the default generator. @returns {string[]} */
const generateBulk = (n) => defaultGenerator.generateBulk(n);

module.exports = {
  VERSION,
  VARIANT,
  RAND_A_BITS,
  RAND_B_BITS,
  MAX_RAND_A,
  MAX_RAND_B,
  UUID_REGEX,
  Generator,
  decode,
  isValid,
  generate,
  generateRandom,
  generateBulk,
  defaultGenerator,
};

// =============================================================================
// Self-contained test / demo (run with: node uuid_v7.js)
// =============================================================================
if (require.main === module) {
  (async () => {
    console.log("=".repeat(68));
    console.log("  UUIDv7: RFC 9562 JavaScript Implementation");
    console.log("=".repeat(68));

    // ── Basic generation ─────────────────────────────────────────────────────
    console.log("\n── Single UUID (monotonic) ──────────────────────────────────────────");
    const uuid = generate();
    console.log(`  ${uuid}`);

    console.log("\n── Single UUID (random Method 1) ───────────────────────────────────");
    console.log(`  ${generateRandom()}`);

    // ── Decode ───────────────────────────────────────────────────────────────
    console.log("\n── Decode ───────────────────────────────────────────────────────────");
    const info = decode(uuid);
    for (const [k, v] of Object.entries(info)) {
      console.log(`  ${k.padEnd(12)}  ${v instanceof Date ? v.toISOString() : v}`);
    }

    // ── Bulk & monotonicity ──────────────────────────────────────────────────
    console.log("\n── Bulk generation (10): monotonicity check ────────────────────────");
    const batch = generateBulk(10);
    for (const u of batch) console.log(`  ${u}`);

    const sorted = [...batch].sort();
    console.log(`\n  Sorted == generated order? ${sorted.every((u, i) => u === batch[i])}`);

    // ── High-volume monotonicity stress test ─────────────────────────────────
    console.log("\n── Stress test: 100_000 UUIDs, all unique, lexically ordered ────────");
    const big = generateBulk(100000);
    console.log(`  Unique?  ${new Set(big).size === big.length}`);
    console.log(`  Sorted?  ${big.every((u, i) => i === 0 || big[i - 1] <= u)}`);

    // ── Async interleaving test ──────────────────────────────────────────────
    // One event loop, so this stands in for the thread-safety test in the Ruby,
    // Python, Rust and C siblings: four async tasks yield to the microtask queue
    // between calls, interleaving into the shared generator.
    console.log("\n── Async interleaving: 4 tasks × 5_000 UUIDs ───────────────────────");
    const buckets = await Promise.all(
      Array.from({ length: 4 }, async () => {
        const bucket = [];
        for (let i = 0; i < 5000; i++) {
          bucket.push(generate());
          await null;
        }
        return bucket;
      }),
    );
    const every = buckets.flat();
    console.log(`  Total:   ${every.length}`);
    console.log(`  Unique?  ${new Set(every).size === every.length}`);

    // ── Validation ───────────────────────────────────────────────────────────
    console.log("\n── Validation ───────────────────────────────────────────────────────");
    const examples = [
      [generate(), true],
      ["00000000-0000-7000-8000-000000000000", true],   // minimal valid v7
      ["ffffffff-ffff-7fff-bfff-ffffffffffff", true],   // max timestamp, year 10889
      ["f81d4fae-7dec-11d0-a765-00a0c91e6bf6", false],  // v1
      ["550e8400-e29b-41d4-a716-446655440000", false],  // v4
      ["not-a-uuid", false],
      ["", false],
    ];
    for (const [u, expected] of examples) {
      const result = isValid(u);
      const status = result === expected ? "✓" : "✗";
      console.log(`  ${status}  isValid(${JSON.stringify(u).slice(0, 45).padEnd(45)}) => ${result}`);
    }

    // ── RFC 9562 Appendix A.6 test vector ────────────────────────────────────
    console.log("\n── RFC 9562 Appendix A.6 test vector ───────────────────────────────");
    // From the RFC: 017F22E2-79B0-7CC3-98C4-DC0C0C07398F, whose
    // unix_ts_ms = 0x017F22E279B0 = 1645557742000 (2022-02-22T19:22:22Z, printed
    // there as 2:22:22 PM GMT-05:00)
    const tv = decode("017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
    console.log(`  UUID:        ${tv.uuid}`);
    console.log(`  unix_ts_ms:  ${tv.unix_ts_ms}  (expected: 1645557742000)`);
    console.log(`  timestamp:   ${tv.timestamp.toISOString()}`);
    console.log(`  version:     ${tv.version}  (expected: 7)`);
    console.log(`  variant:     ${tv.variant}  (expected: 0b10)`);
    console.log(`  rand_a:      0x${tv.rand_a.toString(16).toUpperCase()}`);
    console.log(`  rand_b:      0x${tv.rand_b.toString(16).toUpperCase()}`);

    console.log("\n" + "=".repeat(68));
  })();
}
