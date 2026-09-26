# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Six parallel, dependency-free implementations of UUIDv7 (**RFC 9562 §5.7**), plus study notes on the spec.

| File | Runtime | Stdlib |
|---|---|---|
| `uuid_v7.rb` | Ruby | `securerandom` |
| `uuid_v7.py` | Python 3 | `secrets`, `threading` |
| `uuid_v7.js` | Node 19+ (global Web Crypto, BigInt, CommonJS) | `crypto` global |
| `uuid_v7.lua` | Lua 5.3+ (64-bit ints, bitwise ops) | `io`, `os`, `string` |
| `uuid_v7.rs` | Rust 1.70+ (`OnceLock`, const `Mutex::new`, `thread::scope`) | `std` only; POSIX-only, since entropy is `/dev/urandom` |
| `uuid_v7.c` | C11 + POSIX (pthreads, `clock_gettime`) | libc only; POSIX-only, same reason plus the lock |

All six share the same field layout, the same monotonicity contract, and the same demo output. No gemspec, Gemfile, `pyproject.toml`, rockspec, `package.json`, `Cargo.toml`, makefile, or test framework.

`.gitignore` covers build cruft and macOS files. `specs/` is deliberately **not** ignored, since the vendored RFC is meant to be committed.

## Commands

```bash
ruby uuid_v7.rb      # Ruby demo + self-tests
python3 uuid_v7.py   # Python demo + self-tests
node uuid_v7.js      # JavaScript demo + self-tests
lua uuid_v7.lua      # Lua demo + self-tests

rustc --edition 2021 -O uuid_v7.rs -o uuid_v7_rs && ./uuid_v7_rs   # Rust demo + self-tests
cc -std=c11 -O2 -pthread uuid_v7.c -o uuid_v7_c && ./uuid_v7_c      # C demo + self-tests
```

The two compiled siblings write to **distinct** binary names on purpose, so building both cannot overwrite either.

Each runs the same suite in the same order: generation, decode, bulk monotonicity, 100k stress, concurrency, validation table, RFC A.6 vector.

Self-tests live at the bottom of each file: `if __FILE__ == $PROGRAM_NAME` (Ruby), `if __name__ == "__main__"` (Python), `require.main === module` (JavaScript), `if modname == nil` (Lua, `modname` being the `...` captured at the top). Rust and C are compiled, so they have no run-time equivalent and switch at build time instead: `rustc` on the file makes `main` the entry point, while `mod uuid_v7;` from another crate exposes the API and leaves `main` unused, which is what the file's `#![allow(dead_code)]` is for; in C the demo sits behind `#ifndef UUIDV7_NO_MAIN`, so `-DUUIDV7_NO_MAIN` leaves only the API, whether `#include`d or compiled to an object and linked. There is no separate test file; new behavior gets a new section there.

**Results print as `true`/`false` or `✓`/`✗` and never set a non-zero exit code, so read the output.**

## Architecture

Three layers in each file. Ruby namespaces them in a `UUIDv7` module, Python in the module itself, JavaScript in `module.exports`, Lua in a returned table `M` (`local uuid_v7 = require("uuid_v7")`), Rust in the file's own module (`mod uuid_v7;`), C in a `uuidv7_` prefix, having no namespaces at all.

- **`Generator`**: stateful, holding `last_ms` and `seq`, advanced by `next_state`. Bit-packing (`assemble`) is pure. Ruby, Python, Rust, and C lock the state; JavaScript and Lua do not (see parity table). Rust keeps the locked pair in a separate `State` struct, since the mutex has to own what it guards; C keeps the `pthread_mutex_t` inside `uuidv7_generator` next to the fields it protects.
- **Stateless parsing**: `decode`, `valid?` / `is_valid` / `isValid`.
- **Module-level API**: `generate` / `generate_random` / `generate_bulk` delegate to one shared generator built at load time. It is process-global, so its counter is shared by all callers; instantiate `Generator` directly for an independent sequence. Rust's is a plain `static`, which is why `Generator::new` must stay a `const fn`; C's is a `static` too, initialized by `UUIDV7_GENERATOR_INIT` so it needs no startup hook.

### Monotonicity contract

`generate` implements RFC 9562 §6.2 **Method 2**: `rand_a` (12 bits) is a counter, not random data.

- New millisecond → counter re-seeded with an **11-bit** random value, leaving the MSB clear so ~2048 increments fit before overflow.
- Same millisecond, or clock regression (same `else` branch) → counter increments.
- Overflow past `0xFFF` → `last_ms` bumped by 1 ms; the virtual clock may run ahead of the real one, by design.

So lexicographic sort of `generate` output yields creation order. `generate_random` (Method 1, random `rand_a`) does **not**, so keep the two paths distinct.

Ordering never depends on the clock, only timestamp *accuracy* does. That is what makes Lua's clock fallback acceptable.

### Bit layout

`unix_ts_ms`(48) | `ver`=7(4) | `rand_a`(12) | `var`=0b10(2) | `rand_b`(62)

Three structural approaches, because not every language has a 128-bit integer:

1. **One 128-bit integer**, formatted as 32 hex digits: Ruby, Python, JavaScript (BigInt, since a Number is exact only to 2^53), and Rust (native `u128`). `decode` reverses it with shifts and masks.
2. **Two `uint64_t`**: C, since ISO C has no 128-bit type (`__int128` is a compiler extension). The split is exact, because the variant sits at the octet-8 boundary, which is also the halfway point, so `hi` holds `unix_ts_ms | ver | rand_a` and `lo` holds `var | rand_b`.
3. **Per hex group**: Lua, whose integers are 64-bit and signed. Groups align with field boundaries except `rand_b`, whose top 14 bits share group 4 with the variant; `decode` rebuilds it as `((group4 & 0x3FFF) << 48) | group5`. C's group 4 and 5 straddle the same way, but inside `lo` rather than across two separate reads.

Offsets must stay consistent across the header diagram, `assemble`, and `decode`, **in all six files**.

### Cross-language parity

Behavior changes propagate to all six in the same commit. Intentional differences:

| | Ruby | Python | JavaScript | Lua | Rust | C |
|---|---|---|---|---|---|---|
| Namespace | `UUIDv7` module | the module itself | `module.exports` (CommonJS) | returned table `M` | the file's module (`mod uuid_v7;`) | a `uuidv7_` prefix, C having no namespaces |
| Function names | snake_case | snake_case | camelCase (`generateRandom`, `generateBulk`) | snake_case | snake_case | snake_case |
| Method call | `gen.generate` | `gen.generate()` | `gen.generate()` | `gen:generate()` (colon) | `gen.generate()` | `uuidv7_generator_generate(&gen, out)` |
| Predicate | `valid?` | `is_valid` | `isValid` | `is_valid` | `is_valid` | `uuidv7_is_valid` |
| Invalid input | `ArgumentError` | `ValueError` | `TypeError` | `error()`; `is_valid` uses `pcall` | `Err(DecodeError)`, no exceptions; `generate_bulk` panics on `n == 0`, the only bad `usize` | a `uuidv7_status` return code, no exceptions; `generate_bulk` returns `UUIDV7_ERR_ARG` on `n == 0`, the only bad `size_t` |
| Format check | `UUID_REGEX` | `UUID_REGEX` (`re`) | `UUID_REGEX` | `UUID_PATTERN`, with 8-4-4-4-12 spelled out because Lua patterns lack `{n}` and alternation | `UUID_GROUP_WIDTHS`, walked digit by digit in `parse_hex128` because `std` has no regex engine | the same walk in `uuidv7_parse`, libc having no regex either, and `strtoull` being too permissive |
| CSPRNG | `SecureRandom.random_number(n)` | `secrets.randbelow(n)` | `crypto.getRandomValues`, no fallback | `/dev/urandom`, falling back to `math.random` | `/dev/urandom`, no fallback, since `std` has no CSPRNG | `/dev/urandom`, no fallback, since libc has no portable CSPRNG; a missing device calls `abort()` |
| Clock | `Process.clock_gettime(CLOCK_REALTIME, :millisecond)` | `time.time_ns() // 1_000_000` | `Date.now()` | luaposix / luasocket if present, else `os.time` + `os.clock` | `SystemTime::now().duration_since(UNIX_EPOCH)` | `clock_gettime(CLOCK_REALTIME)`, ISO C offering only whole seconds |
| Concurrency | `Mutex` | `threading.Lock` | none, since there is one event loop | none, since standard Lua has no preemptive threads | `Mutex<State>`, recovering the guard on poisoning | `pthread_mutex_t`, because C11 `<threads.h>` is optional and Apple's libc omits it (`__STDC_NO_THREADS__`) |
| Packing | one 128-bit integer | one 128-bit integer | one 128-bit `BigInt` | per hex group (64-bit ceiling) | one 128-bit integer (native `u128`) | two `uint64_t`, split at the variant boundary |
| `decode` timestamp | `Time` (UTC) | `datetime` (tz-aware UTC), `None` past year 9999 | `Date` | `string`, `"YYYY-MM-DD HH:MM:SS.mmm UTC"` | `SystemTime`, an opaque instant the demo formats itself | `struct tm` (UTC, from `gmtime_r`), the demo adding the milliseconds |
| `decode` numerics | Integer | `int` | Number, except `rand_b`, a `BigInt` | 64-bit integer | `u64`, except `rand_a`, a `u16`, and `version`/`variant` bits, `u8` | `uint64_t`, except `rand_a`, a `uint16_t`, and `version`, an `unsigned` |
| `decode` result | `Hash`, Symbol keys | `dict`, `str` keys | plain object with `str` keys | `table` with `str` keys | `Decoded` struct, `pub` fields | `uuidv7_decoded` filled through an out-parameter the caller owns |
| Producing a UUID | returns a `String` | returns a `str` | returns a `string` | returns a `string` | returns a `String` | writes into a caller-supplied `uuidv7_str` (36 chars + NUL), since nothing here allocates |
| Demo gate | `__FILE__ == $PROGRAM_NAME` | `__name__ == "__main__"` | `require.main === module` | `modname == nil` | build time: `rustc` vs `mod uuid_v7;` | build time: plain `cc` vs `-DUUIDV7_NO_MAIN` |

Keys inside `decode`'s result are RFC field names (`unix_ts_ms`, `rand_a`, `rand_b`) and stay snake_case in every language, JavaScript included.

- Bulk type checks: Python rejects `bool` explicitly (`True` is an `int`); JavaScript's `Number.isInteger` accepts `3.0`, since the language has no distinct integer type; Lua's `math.type(n) ~= "integer"` rejects it; Rust and C need no check beyond `n == 0`, since `usize` and `size_t` admit nothing else.
- JavaScript has no entropy fallback by design: `crypto.getRandomValues` or a thrown error, never a silent downgrade to `Math.random`. Worker threads get their own isolate and generator, so they never share the counter.
- Rust's entropy is also `/dev/urandom`, but with JavaScript's stance rather than Lua's: no fallback, so a missing device panics. That plus the `read(2)` in `rand_bits` is what makes Rust the one Unix-only sibling. The handle is a `OnceLock<File>` and needs no lock of its own, since the kernel serializes each read.
- Python's `timestamp` is the one field that can come back `None`: `datetime` stops at year 9999, while a 48-bit `unix_ts_ms` reaches 10889-08-02, so the top ~10% of the field has no `datetime`. The other five render those instants fine. `_timestamp` swallows the `OverflowError` because such a UUID is still well-formed, and because `OverflowError` is not a `ValueError`: letting it escape made `is_valid` **raise** instead of answering, breaking the predicate contract. Clamping to `datetime.max` would misreport the instant, so `None` it is. The validation table in all six demos carries `ffffffff-ffff-7fff-bfff-ffffffffffff` to keep this from regressing.
- C's `abort()` on a missing `/dev/urandom` is the same stance as Rust's panic, spelled for an API whose producers return `void`. Do not soften it into a silent `rand()` path.
- C's demo checks uniqueness with `qsort` plus an adjacent compare, since libc has no hash table; every other sibling uses its set type. The monotonicity check runs on the generated order *before* anything is sorted, so the two assertions stay independent.
- C's `gmtime_r` covers the whole 48-bit field on a 64-bit `time_t` (verified at the maximum, 10889-08-02), so it does **not** share the Python limit below. Where `time_t` is 32 bits it can fail; `decode` then zeroes the member instead of failing, since the UUID is still valid.
- Rust's demo carries `utc_string`, a private days-to-civil converter, because `std` has no calendar at all: `SystemTime` cannot be formatted. Adding a date crate would break the dependency-free rule, so `decode` keeps the honest `SystemTime` and only the demo converts.
- `M.entropy_source` and `M.clock_source` report which Lua fallback is live, and the demo prints both. **`math.random` is not a CSPRNG**: losing the urandom path is a security regression, not a cosmetic one.
- Lua's clock fallback interpolates within the current second via `os.clock`, re-anchoring on each `os.time` tick so drift stays under one second. Measured at real millisecond resolution (~986 distinct sub-second values over 2s), but it tracks CPU time, so it lags under blocking I/O.
- JavaScript's concurrency test uses four async tasks awaiting between calls; Lua's uses four round-robin coroutines. Both exercise interleaved access to the shared generator (the strongest concurrency each language offers), but neither is evidence of preemptive thread safety. Ruby, Python, Rust, and C spawn real threads, Rust's via `thread::scope` so the borrow of the `static` generator needs no `Arc`, C's via `pthread_create` into disjoint slices of one buffer. The C build is the one that can be checked mechanically: `cc -fsanitize=thread` runs the demo clean, which is worth re-running after touching the lock.

The six are wire-compatible: any UUID decodes identically in the other five. Check that after touching `assemble` or `decode`.

## Conventions

- `decode` raises on bad format, wrong version, or wrong variant (in Rust, returns `Err`), and on **nothing else**; the predicate is `decode` with that error swallowed, so any other exception escaping `decode` turns the predicate into a raising function rather than an answer. Keep validation in `decode` rather than duplicating it.
- Verify spec claims against the vendored `specs/` (`rfc9562.txt`, `.pdf`, `.mhtml`), grepping those instead of fetching the RFC.
- `README.md` is pt-BR; code and comments are English. Preserve both.
- C builds must stay warning-free under `cc -std=c11 -Wall -Wextra -pedantic`, which is stricter than the documented compile line; check with it after any edit.
- Formatting is hand-done in every file, including `uuid_v7.rs`, which is **not** rustfmt-clean: aligned trailing comments and one-line demo prints keep the six readable side by side. `rustfmt` collapses both, so don't run it (the file says so too).
- Doc-comment style is per-language, never mixed: YARD (`@param`/`@return`/`@raise`) in Ruby; Sphinx docstrings (`:param:`/`:return:`/`:raises:`) plus type hints in Python; JSDoc (`@param`/`@returns`/`@throws`) in JavaScript; LDoc `--` comments in Lua; rustdoc `///` with `# Arguments` / `# Returns` / `# Errors` / `# Panics` headings in Rust; plain `/* */` block comments in C, prose rather than tags, since libc itself documents that way and no C doc generator is assumed.

## Keeping documentation in sync

Each file is meant to read standalone, so facts are duplicated on purpose and edits must propagate.

| Fact | Also lives in |
|---|---|
| Bit offsets / field widths | per file: header diagram, the `Field / Bits / Position` table, the comment above `assemble`, the shifts in `assemble` and `decode`, plus README's "Estrutura de bits comparada" |
| `VERSION`, `VARIANT`, `RAND_A_BITS`, `RAND_B_BITS` | the constants, their inline comments, and doc comments restating `0b0111` / `0b10` / `0xFFF` |
| Monotonicity strategy | per file: `Generator` doc comment, `next_state` inline comments, `generate` vs `generate_random` docs, plus README's "Como a v7 gera monotonicidade" |
| `decode`'s return shape | per file: the documented key list and the literal it returns (in Rust the `Decoded` struct, in C `uuidv7_decoded`, with their field comments) |
| The demo script | six main blocks, kept section-for-section parallel |
| Filenames and API surface | each file's "run with:" comment and header cross-references, README's "Implementações" tables and snippets, the Commands section above |
| JavaScript's, Lua's, Rust's, and C's divergences | listed in each of those four headers, with a pointer to the implementing function, plus the parity table |
| The `rustc` and `cc` invocations | each file's header and demo-section comments, `.gitignore`'s Rust and C blocks, README's "Implementações" table, the Commands section above. The two output names must stay distinct |
| `UUIDV7_SIZE` / the caller-owned buffer | `uuid_v7.c`'s constant, `uuidv7_str`, every producer's signature, and the parity table's "Producing a UUID" row |

**Rules:**

- Every doc edit is a six-file edit unless genuinely language-specific. Undocumented divergence is a bug: add a parity-table row instead.
- Adding a public method means implementing it in all six, documenting it in each native style, and adding a matching demo section. Renaming a `decode` key means updating all six key lists, which are the repo's only API reference. In Rust and C that also means a struct member, since the shape is a struct rather than a map.
- A workaround forced by a language limit documents *what the limit is*, not just what the code does. `assemble` in JavaScript and Lua, plus Lua's `current_ms` and `rand_bits`, Rust's `urandom`, `parse_hex128`, and `utc_string`, and C's `uuidv7_assemble`, `uuidv7_hex_value`, and `demo_all_unique`, carry longer comments for that reason, so don't trim them.
- `README.md` covers the spec, with "Segurança e imprevisibilidade" quoting RFC §8 and §6.9 verbatim, and "Implementações neste repositório" carrying the filenames, API surface, and runnable snippets. Keep API detail at overview depth (per-argument contracts stay in source doc comments) and keep it pt-BR. Its commands and links are verified to work, so re-check after a rename or signature change.
- Cite RFC sections (`RFC 9562 §6.2`) rather than restating rules from memory.
- README's worked example (`01a09896-1ecd-7b03-bb26-376dea2187a4`) is hand-written, not generated. Re-derive it with `decode` if edited.
- The A.6 vector (`017f22e2-79b0-7cc3-98c4-dc0c0c07398f` / `1645557742000`) is fixed by the spec: a mismatch is a code bug, never an expected-value update. Correct UTC rendering is **19:22:22**, since `specs/rfc9562.txt:2329` says 2:22:22 PM GMT-05:00, easily misread as 22:22:22Z. All six decode it to `rand_a = 0xCC3`, `rand_b = 0x18C4DC0C0C07398F`.
- Update this file when the layers, monotonicity contract, parity table, or commands change.
