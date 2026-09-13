# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Four parallel, dependency-free implementations of UUIDv7 (**RFC 9562 §5.7**), plus study notes on the spec.

| File | Runtime | Stdlib |
|---|---|---|
| `uuid_v7.rb` | Ruby | `securerandom` |
| `uuid_v7.py` | Python 3 | `secrets`, `threading` |
| `uuid_v7.js` | Node 19+ (global Web Crypto, BigInt, CommonJS) | `crypto` global |
| `uuid_v7.lua` | Lua 5.3+ (64-bit ints, bitwise ops) | `io`, `os`, `string` |

All four share the same field layout, the same monotonicity contract, and the same demo output. No gemspec, Gemfile, `pyproject.toml`, rockspec, `package.json`, or test framework.

`.gitignore` covers build cruft and macOS files. `specs/` is deliberately **not** ignored, since the vendored RFC is meant to be committed.

## Commands

```bash
ruby uuid_v7.rb      # Ruby demo + self-tests
python3 uuid_v7.py   # Python demo + self-tests
node uuid_v7.js      # JavaScript demo + self-tests
lua uuid_v7.lua      # Lua demo + self-tests
```

Each runs the same suite in the same order: generation, decode, bulk monotonicity, 100k stress, concurrency, validation table, RFC A.6 vector.

Self-tests live at the bottom of each file: `if __FILE__ == $PROGRAM_NAME` (Ruby), `if __name__ == "__main__"` (Python), `require.main === module` (JavaScript), `if modname == nil` (Lua, `modname` being the `...` captured at the top). There is no separate test file; new behavior gets a new section there.

**Results print as `true`/`false` or `✓`/`✗` and never set a non-zero exit code, so read the output.**

## Architecture

Three layers in each file. Ruby namespaces them in a `UUIDv7` module, Python in the module itself, JavaScript in `module.exports`, Lua in a returned table `M` (`local uuid_v7 = require("uuid_v7")`).

- **`Generator`**: stateful, holding `last_ms` and `seq`, advanced by `next_state`. Bit-packing (`assemble`) is pure. Ruby and Python lock the state; JavaScript and Lua do not (see parity table).
- **Stateless parsing**: `decode`, `valid?` / `is_valid` / `isValid`.
- **Module-level API**: `generate` / `generate_random` / `generate_bulk` delegate to one shared generator built at load time. It is process-global, so its counter is shared by all callers; instantiate `Generator` directly for an independent sequence.

### Monotonicity contract

`generate` implements RFC 9562 §6.2 **Method 2**: `rand_a` (12 bits) is a counter, not random data.

- New millisecond → counter re-seeded with an **11-bit** random value, leaving the MSB clear so ~2048 increments fit before overflow.
- Same millisecond, or clock regression (same `else` branch) → counter increments.
- Overflow past `0xFFF` → `last_ms` bumped by 1 ms; the virtual clock may run ahead of the real one, by design.

So lexicographic sort of `generate` output yields creation order. `generate_random` (Method 1, random `rand_a`) does **not**, so keep the two paths distinct.

Ordering never depends on the clock, only timestamp *accuracy* does. That is what makes Lua's clock fallback acceptable.

### Bit layout

`unix_ts_ms`(48) | `ver`=7(4) | `rand_a`(12) | `var`=0b10(2) | `rand_b`(62)

Ruby, Python, and JavaScript pack this into one 128-bit integer formatted as 32 hex digits, using BigInt in JavaScript because a Number is exact only to 2^53; `decode` reverses it with shifts and masks.

Lua's integers are 64-bit and cannot, so `assemble` emits hex group by hex group. Groups align with field boundaries except `rand_b`, whose top 14 bits share group 4 with the variant; `decode` rebuilds it as `((group4 & 0x3FFF) << 48) | group5`. This is the only structural divergence among the four.

Offsets must stay consistent across the header diagram, `assemble`, and `decode`, **in all four files**.

### Cross-language parity

Behavior changes propagate to all four in the same commit. Intentional differences:

| | Ruby | Python | JavaScript | Lua |
|---|---|---|---|---|
| Namespace | `UUIDv7` module | the module itself | `module.exports` (CommonJS) | returned table `M` |
| Function names | snake_case | snake_case | camelCase (`generateRandom`, `generateBulk`) | snake_case |
| Method call | `gen.generate` | `gen.generate()` | `gen.generate()` | `gen:generate()` (colon) |
| Predicate | `valid?` | `is_valid` | `isValid` | `is_valid` |
| Invalid input | `ArgumentError` | `ValueError` | `TypeError` | `error()`; `is_valid` uses `pcall` |
| Format check | `UUID_REGEX` | `UUID_REGEX` (`re`) | `UUID_REGEX` | `UUID_PATTERN`, with 8-4-4-4-12 spelled out because Lua patterns lack `{n}` and alternation |
| CSPRNG | `SecureRandom.random_number(n)` | `secrets.randbelow(n)` | `crypto.getRandomValues`, no fallback | `/dev/urandom`, falling back to `math.random` |
| Clock | `Process.clock_gettime(CLOCK_REALTIME, :millisecond)` | `time.time_ns() // 1_000_000` | `Date.now()` | luaposix / luasocket if present, else `os.time` + `os.clock` |
| Concurrency | `Mutex` | `threading.Lock` | none, since there is one event loop | none, since standard Lua has no preemptive threads |
| Packing | one 128-bit integer | one 128-bit integer | one 128-bit `BigInt` | per hex group (64-bit ceiling) |
| `decode` timestamp | `Time` (UTC) | `datetime` (tz-aware UTC) | `Date` | `string`, `"YYYY-MM-DD HH:MM:SS.mmm UTC"` |
| `decode` numerics | Integer | `int` | Number, except `rand_b`, a `BigInt` | 64-bit integer |
| `decode` result | `Hash`, Symbol keys | `dict`, `str` keys | plain object with `str` keys | `table` with `str` keys |

Keys inside `decode`'s result are RFC field names (`unix_ts_ms`, `rand_a`, `rand_b`) and stay snake_case in every language, JavaScript included.

- Bulk type checks: Python rejects `bool` explicitly (`True` is an `int`); JavaScript's `Number.isInteger` accepts `3.0`, since the language has no distinct integer type; Lua's `math.type(n) ~= "integer"` rejects it.
- JavaScript has no entropy fallback by design: `crypto.getRandomValues` or a thrown error, never a silent downgrade to `Math.random`. Worker threads get their own isolate and generator, so they never share the counter.
- `M.entropy_source` and `M.clock_source` report which Lua fallback is live, and the demo prints both. **`math.random` is not a CSPRNG**: losing the urandom path is a security regression, not a cosmetic one.
- Lua's clock fallback interpolates within the current second via `os.clock`, re-anchoring on each `os.time` tick so drift stays under one second. Measured at real millisecond resolution (~986 distinct sub-second values over 2s), but it tracks CPU time, so it lags under blocking I/O.
- JavaScript's concurrency test uses four async tasks awaiting between calls; Lua's uses four round-robin coroutines. Both exercise interleaved access to the shared generator (the strongest concurrency each language offers), but neither is evidence of preemptive thread safety.

The four are wire-compatible: any UUID decodes identically in the other three. Check that after touching `assemble` or `decode`.

## Conventions

- `decode` raises on bad format, wrong version, or wrong variant; the predicate is `decode` with that error swallowed. Keep validation in `decode` rather than duplicating it.
- Verify spec claims against the vendored `specs/` (`rfc9562.txt`, `.pdf`, `.mhtml`), grepping those instead of fetching the RFC.
- `README.md` is pt-BR; code and comments are English. Preserve both.
- Doc-comment style is per-language, never mixed: YARD (`@param`/`@return`/`@raise`) in Ruby; Sphinx docstrings (`:param:`/`:return:`/`:raises:`) plus type hints in Python; JSDoc (`@param`/`@returns`/`@throws`) in JavaScript; LDoc `--` comments in Lua.

## Keeping documentation in sync

Each file is meant to read standalone, so facts are duplicated on purpose and edits must propagate.

| Fact | Also lives in |
|---|---|
| Bit offsets / field widths | per file: header diagram, the `Field / Bits / Position` table, the comment above `assemble`, the shifts in `assemble` and `decode`, plus README's "Estrutura de bits comparada" |
| `VERSION`, `VARIANT`, `RAND_A_BITS`, `RAND_B_BITS` | the constants, their inline comments, and doc comments restating `0b0111` / `0b10` / `0xFFF` |
| Monotonicity strategy | per file: `Generator` doc comment, `next_state` inline comments, `generate` vs `generate_random` docs, plus README's "Como a v7 gera monotonicidade" |
| `decode`'s return shape | per file: the documented key list and the literal it returns |
| The demo script | four main blocks, kept section-for-section parallel |
| Filenames and API surface | each file's "run with:" comment and header cross-references, README's "Implementações" tables and snippets, the Commands section above |
| JavaScript's and Lua's divergences | listed in each of those two headers, with a pointer to the implementing function, plus the parity table |

**Rules:**

- Every doc edit is a four-file edit unless genuinely language-specific. Undocumented divergence is a bug: add a parity-table row instead.
- Adding a public method means implementing it in all four, documenting it in each native style, and adding a matching demo section. Renaming a `decode` key means updating all four key lists, which are the repo's only API reference.
- A workaround forced by a language limit documents *what the limit is*, not just what the code does. `assemble` in JavaScript and Lua, plus Lua's `current_ms` and `rand_bits`, carry longer comments for that reason, so don't trim them.
- `README.md` covers the spec plus, in "Implementações neste repositório", the filenames, API surface, and runnable snippets. Keep API detail at overview depth (per-argument contracts stay in source doc comments) and keep it pt-BR. Its commands and links are verified to work, so re-check after a rename or signature change.
- Cite RFC sections (`RFC 9562 §6.2`) rather than restating rules from memory.
- README's worked example (`01a09896-1ecd-7b03-bb26-376dea2187a4`) is hand-written, not generated. Re-derive it with `decode` if edited.
- The A.6 vector (`017f22e2-79b0-7cc3-98c4-dc0c0c07398f` / `1645557742000`) is fixed by the spec: a mismatch is a code bug, never an expected-value update. Correct UTC rendering is **19:22:22**, since `specs/rfc9562.txt:2329` says 2:22:22 PM GMT-05:00, easily misread as 22:22:22Z. All four decode it to `rand_a = 0xCC3`, `rand_b = 0x18C4DC0C0C07398F`.
- Update this file when the layers, monotonicity contract, parity table, or commands change.
