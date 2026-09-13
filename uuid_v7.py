#!/usr/bin/env python3
# =============================================================================
# UUIDv7: Python implementation of RFC 9562, Section 5.7
# https://www.rfc-editor.org/rfc/rfc9562#section-5.7
# https://datatracker.ietf.org/doc/html/rfc9562
# https://en.wikipedia.org/wiki/Universally_unique_identifier
#
# Port of uuid_v7.rb, with the same field layout and monotonicity contract.
#
# 128-bit field layout (big-endian, MSB first):
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           unix_ts_ms                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          unix_ts_ms           |  ver  |        rand_a         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |var|                         rand_b                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           rand_b                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Field       Bits    Position        Description
# ─────────────────────────────────────────────────────────────────
# unix_ts_ms  48      [127..80]  Unix epoch timestamp (milliseconds)
# ver          4      [79..76]   Version = 0b0111 (7)
# rand_a      12      [75..64]   Random data / monotonic counter
# var          2      [63..62]   Variant = 0b10 (RFC 4122 / 9562)
# rand_b      62      [61..0]    Cryptographically random data
# =============================================================================

from __future__ import annotations

import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

VERSION = 0x7          # 4-bit version field value
VARIANT = 0b10         # 2-bit variant field value (MSBs of octet 8)

RAND_A_BITS = 12
RAND_B_BITS = 62
MAX_RAND_A = (1 << RAND_A_BITS) - 1   # 0xFFF
MAX_RAND_B = (1 << RAND_B_BITS) - 1   # 0x3FFF_FFFF_FFFF_FFFF

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
UUID_REGEX = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)

__all__ = [
    "Generator",
    "decode",
    "is_valid",
    "generate",
    "generate_random",
    "generate_bulk",
]


# ── Generator ────────────────────────────────────────────────────────────────


class Generator:
    """Thread-safe UUIDv7 generator.

    Method 2 (monotonic counter) of RFC 9562 §6.2: rand_a is a counter re-seeded
    on each new millisecond, giving strict lexicographic ordering even within a
    single millisecond; rand_b is always fresh random data. On counter overflow
    (> 0xFFF) the timestamp is bumped 1 ms, the "counter rollover" that same
    section permits.

        gen = Generator()
        gen.generate()  # => "018f2e39-59b7-7e82-9c3a-4d5b9e2f1a60"
    """

    __slots__ = ("_lock", "_last_ms", "_seq")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = 0   # last timestamp used
        self._seq = 0       # rand_a counter within a millisecond

    def generate(self) -> str:
        """Generate a UUIDv7, monotonic within 1 ms.

        :return: lowercase UUID string
        """
        with self._lock:
            ms, seq, rand_b = self._next_state()
        return _assemble(ms, seq, rand_b)

    def generate_random(self) -> str:
        """Generate a UUIDv7 by Method 1, with fully random rand_a and rand_b.

        Simpler, but NOT monotonic within a millisecond.
        """
        ms = _current_ms()
        rand_a = secrets.randbelow(MAX_RAND_A + 1)
        rand_b = secrets.randbelow(MAX_RAND_B + 1)
        return _assemble(ms, rand_a, rand_b)

    def generate_bulk(self, n: int) -> list[str]:
        """Generate `n` monotonically ordered UUIDv7s.

        :param n: number of UUIDs to generate (must be positive)
        :raises ValueError: if `n` is not a positive integer
        """
        if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
            raise ValueError("n must be a positive integer")

        return [self.generate() for _ in range(n)]

    # ── internals ────────────────────────────────────────────────────────────

    def _next_state(self) -> tuple[int, int, int]:
        """Advance internal state and return (ms, seq, rand_b).

        MUST be called while holding self._lock.
        """
        ms = _current_ms()

        if ms > self._last_ms:
            # ── New millisecond: re-seed the counter ─────────────────────────
            # An 11-bit seed keeps the MSB free, leaving room for 2048 increments.
            self._seq = secrets.randbelow(1 << (RAND_A_BITS - 1))
            self._last_ms = ms
        else:
            # ── Same (or rare clock regression) millisecond: increment ───────
            self._seq += 1

            if self._seq > MAX_RAND_A:
                # Counter exhausted, so bump the virtual clock by 1 ms (§6.2)
                self._last_ms += 1
                self._seq = secrets.randbelow(1 << (RAND_A_BITS - 1))

            ms = self._last_ms

        rand_b = secrets.randbelow(MAX_RAND_B + 1)
        return ms, self._seq, rand_b


def _current_ms() -> int:
    """Current Unix timestamp in whole milliseconds."""
    return time.time_ns() // 1_000_000


def _assemble(unix_ts_ms: int, rand_a: int, rand_b: int) -> str:
    """Pack all fields into a 128-bit integer and format the UUID string.

    Positions below count 127 as the MSB, the opposite of the RFC-style
    ruler in the file header, which numbers bits from 0 left to right:

      [127..80]  unix_ts_ms   (48 bits)
      [79..76]   ver          ( 4 bits)  -> 0b0111
      [75..64]   rand_a       (12 bits)
      [63..62]   var          ( 2 bits)  -> 0b10
      [61..0]    rand_b       (62 bits)

    :param unix_ts_ms: 48-bit millisecond timestamp
    :param rand_a: 12-bit value (counter or random)
    :param rand_b: 62-bit random value
    :return: formatted UUID
    """
    n = ((unix_ts_ms << 80)
         | (VERSION << 76)
         | ((rand_a & MAX_RAND_A) << 64)
         | (VARIANT << 62)
         | (rand_b & MAX_RAND_B))

    hex_str = format(n, "032x")
    return (f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}"
            f"-{hex_str[16:20]}-{hex_str[20:32]}")


# ── Decoder ──────────────────────────────────────────────────────────────────


def decode(uuid: str) -> dict[str, Any]:
    """Decode a UUIDv7 string into its constituent fields.

    :param uuid: UUID string, any letter case
    :return: dict with keys:
        "uuid"       (str)      canonical lowercase UUID string
        "version"    (int)      must be 7
        "variant"    (str)      e.g. "0b10"
        "unix_ts_ms" (int)      Unix timestamp in milliseconds
        "timestamp"  (datetime) UTC datetime reconstructed from unix_ts_ms
        "rand_a"     (int)      12-bit rand_a field value
        "rand_b"     (int)      62-bit rand_b field value
    :raises ValueError: if the format, version, or variant is invalid
    """
    if not isinstance(uuid, str) or not UUID_REGEX.match(uuid):
        raise ValueError(f"Invalid UUID format: {uuid!r}")

    n = int(uuid.replace("-", ""), 16)

    version = (n >> 76) & 0xF
    variant = (n >> 62) & 0x3

    if version != VERSION:
        raise ValueError(
            f"Not a UUIDv7 (version field = {version}, expected 7)"
        )

    if variant != VARIANT:
        raise ValueError(
            f"Invalid variant bits (got 0b{variant:02b}, expected 0b10)"
        )

    unix_ts_ms = (n >> 80) & 0xFFFF_FFFF_FFFF
    rand_a = (n >> 64) & MAX_RAND_A
    rand_b = n & MAX_RAND_B

    return {
        "uuid": uuid.lower(),
        "version": version,
        "variant": f"0b{variant:02b}",
        "unix_ts_ms": unix_ts_ms,
        "timestamp": _EPOCH + timedelta(milliseconds=unix_ts_ms),
        "rand_a": rand_a,
        "rand_b": rand_b,
    }


def is_valid(uuid: str) -> bool:
    """True if `uuid` is a well-formed UUIDv7."""
    try:
        decode(uuid)
        return True
    except ValueError:
        return False


# ── Module-level convenience API ─────────────────────────────────────────────

# Shared, thread-safe default generator.
_default_generator = Generator()


def generate() -> str:
    """Monotonic UUIDv7 from the shared default generator. Thread-safe."""
    return _default_generator.generate()


def generate_random() -> str:
    """UUIDv7 with fully random rand_a and rand_b (Method 1)."""
    return _default_generator.generate_random()


def generate_bulk(n: int) -> list[str]:
    """`n` monotonically ordered UUIDv7s from the default generator."""
    return _default_generator.generate_bulk(n)


# =============================================================================
# Self-contained test / demo (run with: python3 uuid_v7.py)
# =============================================================================
if __name__ == "__main__":
    print("=" * 68)
    print("  UUIDv7: RFC 9562 Python Implementation")
    print("=" * 68)

    # ── Basic generation ─────────────────────────────────────────────────────
    print("\n── Single UUID (monotonic) ──────────────────────────────────────────")
    uuid = generate()
    print(f"  {uuid}")

    print("\n── Single UUID (random Method 1) ───────────────────────────────────")
    print(f"  {generate_random()}")

    # ── Decode ───────────────────────────────────────────────────────────────
    print("\n── Decode ───────────────────────────────────────────────────────────")
    info = decode(uuid)
    for k, v in info.items():
        print(f"  {k:<12}  {v}")

    # ── Bulk & monotonicity ──────────────────────────────────────────────────
    print("\n── Bulk generation (10): monotonicity check ────────────────────────")
    batch = generate_bulk(10)
    for u in batch:
        print(f"  {u}")
    print(f"\n  Sorted == generated order? {sorted(batch) == batch}")

    # ── High-volume monotonicity stress test ─────────────────────────────────
    print("\n── Stress test: 100_000 UUIDs, all unique, lexically ordered ────────")
    big = generate_bulk(100_000)
    print(f"  Unique?  {len(set(big)) == len(big)}")
    print(f"  Sorted?  {all(a <= b for a, b in zip(big, big[1:]))}")

    # ── Thread-safety test ───────────────────────────────────────────────────
    print("\n── Thread-safety: 4 threads × 5_000 UUIDs ──────────────────────────")
    results: list[list[str]] = [[] for _ in range(4)]

    def _fill(bucket: list[str]) -> None:
        for _ in range(5_000):
            bucket.append(generate())

    threads = [threading.Thread(target=_fill, args=(b,)) for b in results]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    every = [u for bucket in results for u in bucket]
    print(f"  Total:   {len(every)}")
    print(f"  Unique?  {len(set(every)) == len(every)}")

    # ── Validation ───────────────────────────────────────────────────────────
    print("\n── Validation ───────────────────────────────────────────────────────")
    examples = [
        (generate(), True),
        ("00000000-0000-7000-8000-000000000000", True),   # minimal valid v7
        ("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", False),  # v1
        ("550e8400-e29b-41d4-a716-446655440000", False),  # v4
        ("not-a-uuid", False),
        ("", False),
    ]
    for u, expected in examples:
        result = is_valid(u)
        status = "✓" if result == expected else "✗"
        print(f"  {status}  is_valid({repr(u)[:45]:<45}) => {result}")

    # ── RFC 9562 Appendix A.6 test vector ────────────────────────────────────
    print("\n── RFC 9562 Appendix A.6 test vector ───────────────────────────────")
    # The RFC provides:  017F22E2-79B0-7CC3-98C4-DC0C0C07398F
    # unix_ts_ms = 0x017F22E279B0 = 1645557742000  (2022-02-22T19:22:22.000Z, i.e. 2:22:22 PM GMT-05:00)
    test_vec = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
    tv = decode(test_vec)
    print(f"  UUID:        {tv['uuid']}")
    print(f"  unix_ts_ms:  {tv['unix_ts_ms']}  (expected: 1645557742000)")
    print(f"  timestamp:   {tv['timestamp']}")
    print(f"  version:     {tv['version']}  (expected: 7)")
    print(f"  variant:     {tv['variant']}  (expected: 0b10)")
    print(f"  rand_a:      0x{tv['rand_a']:X}")
    print(f"  rand_b:      0x{tv['rand_b']:X}")

    print("\n" + "=" * 68)
