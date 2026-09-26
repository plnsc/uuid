# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Overview

Six parallel, dependency-free implementations of UUIDv7 (**RFC 9562 §5.7**), plus study notes on the spec.

| File | Runtime | Stdlib |
|---|---|---|
| `uuid_v7.rb` | Ruby | `securerandom` |
| `uuid_v7.py` | Python 3 | `os`, `threading` |
| `uuid_v7.js` | Node 19+ (global Web Crypto, BigInt, CommonJS) | `crypto` global |
| `uuid_v7.lua` | Lua 5.3+ (64-bit ints, bitwise ops) | `io`, `os`, `string` |
| `uuid_v7.rs` | Rust 1.70+ (`OnceLock`, const `Mutex::new`, `thread::scope`) | `std` only; POSIX-only, entropy being `/dev/urandom` |
| `uuid_v7.c` | C11 + POSIX (pthreads, `clock_gettime`) | libc only; POSIX-only, same reason plus the lock |

All six share the field layout, the monotonicity contract, and the demo output. There is no gemspec, Gemfile, `pyproject.toml`, rockspec, `package.json`, `Cargo.toml`, makefile, or test framework.

`bench/` holds the cross-implementation benchmark (one driver per language plus `run.sh`), the only code here that is not an implementation; nothing in the six depends on it. `.gitignore` covers build cruft, macOS files, and the two compiled benchmark drivers; `specs/` is deliberately **not** ignored, since the vendored RFC is meant to be committed.

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

```bash
bench/run.sh            # all six, four operations, one table
bench/run.sh 200000 7   # n and repetitions
```

`run.sh` needs `rustc`: if rustup installed it without touching `PATH`, it falls back to `~/.cargo/bin/rustc`, and `$RUSTC` overrides either. The `rustc` line above assumes it is on `PATH`.

Each demo runs the same suite in the same order: generation, decode, bulk monotonicity, 100k stress, concurrency, validation table, RFC A.6 vector.

Self-tests sit at the bottom of each file, gated by `__FILE__ == $PROGRAM_NAME` (Ruby), `__name__ == "__main__"` (Python), `require.main === module` (JavaScript), `modname == nil` (Lua, `modname` being the `...` captured at the top). Rust and C switch at build time instead: `rustc` on the file makes `main` the entry point, while `mod uuid_v7;` from another crate exposes the API and leaves `main` unused (hence `#![allow(dead_code)]`); in C the demo sits behind `#ifndef UUIDV7_NO_MAIN`, so `-DUUIDV7_NO_MAIN` leaves only the API, whether `#include`d or linked as an object. There is no separate test file: new behavior gets a new section there.

**Results print as `true`/`false` or `✓`/`✗` and never set a non-zero exit code, so read the output.**

## Architecture

Three layers per file, namespaced as a `UUIDv7` module (Ruby), the module itself (Python), `module.exports` (JavaScript), a returned table `M` (Lua, `local uuid_v7 = require("uuid_v7")`), the file's own module (Rust, `mod uuid_v7;`), a `uuidv7_` prefix (C, having no namespaces).

- **`Generator`**: stateful, holding `last_ms` and `seq`, advanced by `next_state`; bit-packing (`assemble`) is pure. Ruby, Python, Rust, and C lock the state, JavaScript and Lua do not (see parity table). Rust keeps the locked pair in a separate `State` struct, since the mutex must own what it guards; C keeps the `pthread_mutex_t` inside `uuidv7_generator`, next to the fields it protects.
- **Stateless parsing**: `decode`, `valid?` / `is_valid` / `isValid`.
- **Module-level API**: `generate` / `generate_random` / `generate_bulk` delegate to one shared generator built at load time. It is process-global, so its counter is shared by all callers; instantiate `Generator` directly for an independent sequence. Rust's is a plain `static`, which is why `Generator::new` must stay a `const fn`; C's is a `static` too, initialized by `UUIDV7_GENERATOR_INIT` so it needs no startup hook.

### Monotonicity contract

`generate` implements RFC 9562 §6.2 **Method 2**: `rand_a` (12 bits) is a counter, not random data.

- New millisecond → counter re-seeded with an **11-bit** random value, leaving the MSB clear so ~2048 increments fit before overflow.
- Same millisecond, or clock regression (same `else` branch) → counter increments.
- Overflow past `0xFFF` → `last_ms` bumped by 1 ms; the virtual clock may run ahead of the real one, by design.

So a lexicographic sort of `generate` output yields creation order. `generate_random` (Method 1, random `rand_a`) does **not**, so keep the two paths distinct. Ordering never depends on the clock, only timestamp *accuracy* does, which is what makes Lua's clock fallback acceptable.

### Entropy pool

All six draw random bits from a pool refilled in 4096-byte blocks, rather than calling the CSPRNG per UUID. The reason is measured: a per-call draw costs ~570 ns (Lua) to ~3230 ns (Python, whose `secrets.randbelow` is rejection sampling), against 23–640 ns pooled. End to end, `generate` went from 3319 to 699 ns in JavaScript (4.8x), 2116 to 880 in Rust (2.4x), 5732 to 3823 in Python (1.5x), 4718 to 3949 in Ruby (1.2x), 3673 to 3215 in Lua (1.14x), and 384 to 338 in C (1.13x). The three slowest gain least because their bottleneck is string assembly, not entropy.

Masking is valid because every caller asks for a power-of-two range, so there is no modulo bias to correct. That is also why Python and Ruby dropped their range APIs (`secrets.randbelow`, `SecureRandom.random_number`) for masked bytes: same distribution, a third to a fifth of the cost.

**A pool is fork-hazardous, and that is not hypothetical.** `fork()` duplicates it, so parent and child are served the same bytes and emit *identical* UUIDs. The C implementation used to read through a `FILE *`, and stdio's buffer did exactly that, on every run. Never add or move a pool without answering for this. What each language can do about it differs enough to be a parity row:

| | guard | cost per draw |
|---|---|---|
| Python | `os.register_at_fork`, the only official hook among the six | none |
| Ruby | compares `Process.pid`, no hook being exposed | ~95 ns |
| Rust | compares `std::process::id()` | ~2 ns |
| C | compares `getpid()` | ~3 ns |
| JavaScript | not needed: Node has no `fork`, and a worker thread gets its own isolate and pool | none |
| Lua | **none possible**: no `fork`, no way to observe one. Latent, and no worse than the stdio buffer it replaced, but a forking host must reload the module in the child |

Consumed bytes are zeroed on the way out in Python, Rust, and C, so only unread entropy stays resident. Ruby and Lua cannot: their pools are immutable strings.

### Bit layout

`unix_ts_ms`(48) | `ver`=7(4) | `rand_a`(12) | `var`=0b10(2) | `rand_b`(62)

Three structural approaches, because not every language has a 128-bit integer:

1. **One 128-bit integer**, formatted as 32 hex digits: Ruby, Python, JavaScript (BigInt, a Number being exact only to 2^53), and Rust (native `u128`). `decode` reverses it with shifts and masks.
2. **Two `uint64_t`**: C, since ISO C has no 128-bit type (`__int128` is a compiler extension). The split is exact, because the variant sits at the octet-8 boundary, which is also the halfway point: `hi` holds `unix_ts_ms | ver | rand_a`, `lo` holds `var | rand_b`.
3. **Per hex group**: Lua, whose integers are 64-bit and signed. Groups align with field boundaries except `rand_b`, whose top 14 bits share group 4 with the variant, so `decode` rebuilds it as `((group4 & 0x3FFF) << 48) | group5`. C's groups 4 and 5 straddle the same way, but inside `lo`.

Offsets must stay consistent across the header diagram, `assemble`, and `decode`, **in all six files**.

### String assembly

`assemble` is where the cost sits once entropy is pooled, and the two compiled files handle it differently from the four interpreted ones **on purpose**:

- **Rust and C emit the nibbles themselves**, over `UUID_GROUP_WIDTHS` / a position table. The formatting libraries were the bottleneck: Rust's `format!("{n:032x}")` plus a second `format!` for the hyphens measured 759 ns of an 853 ns `generate`, and C's `snprintf` 245 of 348, both parsing a template at run time. After the change, `generate` is 164 ns in Rust and 105 in C.
- **The four interpreted siblings keep their format primitive**, because there it is native code while a 32-step loop is not: hand-rolling measured **5.6x slower in Lua**, **6.6x in Python**, **9.7x in Ruby**, **11.8x in JavaScript**. All four say so at `assemble`, each with its own figure; do not "fix" them to match Rust and C.

Rust's remaining ~60 ns behind C is one 36-byte heap allocation, the price of returning an owned `String` as five of the six do, against C writing into the caller's buffer. It is an API difference, not a safety cost, and bounds checking does not show up at all: the iterator spelling beat an index-table spelling (79 ns against 114), both safe.

`is_valid` follows the same split. In Rust it goes through a private `parse_checked` rather than `decode`, since building `Decoded` to drop it cost more than the parse (242 ns against 38); C achieves the same by passing a NULL out-parameter. Validation still lives in one place in both.

### Cross-language parity

Behavior changes propagate to all six in the same commit. Intentional differences:

| | Ruby | Python | JavaScript | Lua | Rust | C |
|---|---|---|---|---|---|---|
| Namespace | `UUIDv7` module | the module itself | `module.exports` (CommonJS) | returned table `M` | the file's module (`mod uuid_v7;`) | a `uuidv7_` prefix |
| Function names | snake_case | snake_case | camelCase (`generateRandom`, `generateBulk`) | snake_case | snake_case | snake_case |
| Method call | `gen.generate` | `gen.generate()` | `gen.generate()` | `gen:generate()` (colon) | `gen.generate()` | `uuidv7_generator_generate(&gen, out)` |
| Predicate | `valid?` | `is_valid` | `isValid` | `is_valid` | `is_valid` | `uuidv7_is_valid` |
| Invalid input | `ArgumentError` | `ValueError` | `TypeError` | `error()`; `is_valid` uses `pcall` | `Err(DecodeError)`, no exceptions; `generate_bulk` panics on `n == 0`, the only bad `usize` | a `uuidv7_status` code, no exceptions; `generate_bulk` returns `UUIDV7_ERR_ARG` on `n == 0`, the only bad `size_t` |
| Format check | `UUID_REGEX` | `UUID_REGEX` (`re`) | `UUID_REGEX` | `UUID_PATTERN`, 8-4-4-4-12 spelled out because Lua patterns lack `{n}` and alternation | `UUID_GROUP_WIDTHS`, walked digit by digit in `parse_hex128`, `std` having no regex | the same walk in `uuidv7_parse`, libc having no regex either and `strtoull` being too permissive |
| CSPRNG | `SecureRandom.bytes` | `os.urandom` | `crypto.getRandomValues`, no fallback | `/dev/urandom`, falling back to `math.random` | `/dev/urandom`, no fallback, `std` having no CSPRNG | `/dev/urandom` read directly, no fallback, libc having no portable CSPRNG; a missing device calls `abort()` |
| Entropy pool | module-level, own `Mutex` | module-level, own `threading.Lock` | module-level, no lock needed | module-level, no lock needed | `thread_local!` with a `const` initializer | `_Thread_local` |
| Fork guard | `Process.pid` per draw | `os.register_at_fork` | not applicable, Node has no `fork` | **none possible** | `std::process::id()` per draw | `getpid()` per draw |
| Zeroes consumed bytes | no, immutable `String` | yes, `bytearray` | no | no, immutable string | yes | yes |
| Clock | `Process.clock_gettime(CLOCK_REALTIME, :millisecond)` | `time.time_ns() // 1_000_000` | `Date.now()` | luaposix / luasocket if present, else `os.time` + `os.clock` | `SystemTime::now().duration_since(UNIX_EPOCH)` | `clock_gettime(CLOCK_REALTIME)`, ISO C offering only whole seconds |
| Concurrency | `Mutex` | `threading.Lock` | none, one event loop | none, standard Lua having no preemptive threads | `Mutex<State>`, recovering the guard on poisoning | `pthread_mutex_t`, C11 `<threads.h>` being optional and Apple's libc omitting it (`__STDC_NO_THREADS__`) |
| Packing | one 128-bit integer | one 128-bit integer | one 128-bit `BigInt` | per hex group (64-bit ceiling) | one 128-bit integer (native `u128`) | two `uint64_t`, split at the variant boundary |
| Formatting | `format` | f-string | template literal | `string.format` | nibbles by hand, no `format!` | nibbles by hand, no `snprintf` |
| Predicate path | via `decode` | via `decode` | via `decode` | via `decode` | via private `parse_checked` | via `decode` with a NULL out-parameter |
| `decode` timestamp | `Time` (UTC) | `datetime` (tz-aware UTC), `None` past year 9999 | `Date` | `string`, `"YYYY-MM-DD HH:MM:SS.mmm UTC"` | `SystemTime`, an opaque instant the demo formats itself | `struct tm` (UTC, from `gmtime_r`), the demo adding the milliseconds |
| `decode` numerics | Integer | `int` | Number, except `rand_b`, a `BigInt` | 64-bit integer | `u64`, except `rand_a` (`u16`) and `version`/`variant` (`u8`) | `uint64_t`, except `rand_a` (`uint16_t`) and `version` (`unsigned`) |
| `decode` result | `Hash`, Symbol keys | `dict`, `str` keys | plain object with `str` keys | `table` with `str` keys | `Decoded` struct, `pub` fields | `uuidv7_decoded` filled through an out-parameter the caller owns |
| Producing a UUID | returns a `String` | returns a `str` | returns a `string` | returns a `string` | returns a `String` | writes into a caller-supplied `uuidv7_str` (36 chars + NUL), nothing here allocating |
| Demo gate | `__FILE__ == $PROGRAM_NAME` | `__name__ == "__main__"` | `require.main === module` | `modname == nil` | build time: `rustc` vs `mod uuid_v7;` | build time: plain `cc` vs `-DUUIDV7_NO_MAIN` |

Keys inside `decode`'s result are RFC field names (`unix_ts_ms`, `rand_a`, `rand_b`) and stay snake_case in every language, JavaScript included.

- `decode` type-guards before matching in all four dynamic languages (`uuid.is_a?(String)`, `isinstance`, `typeof`, `type(uuid) ~= "string"`); Rust and C get it from their signatures, C's `uuidv7_parse` additionally rejecting `NULL`. The guard is not decoration: without it Ruby's non-String path reached `#match?` and raised `NoMethodError`, which `valid?` does not rescue, so the predicate raised instead of answering. Any new entry point takes the same guard.
- Bulk type checks: Python rejects `bool` explicitly (`True` is an `int`); JavaScript's `Number.isInteger` accepts `3.0`, the language having no distinct integer type; Lua's `math.type(n) ~= "integer"` rejects it; Rust and C need no check beyond `n == 0`, since `usize` and `size_t` admit nothing else.
- JavaScript has no entropy fallback by design: `crypto.getRandomValues` or a thrown error, never a silent downgrade to `Math.random`. Worker threads get their own isolate and generator, so they share neither the counter nor the pool. Its pool is read through a `DataView`: `getBigUint64` replaced an eight-step BigInt fold costing ~490 ns per draw, more than half of what pooling saved there.
- Rust's entropy is also `/dev/urandom`, but with JavaScript's stance rather than Lua's: no fallback, so a missing device panics. That plus the `read(2)` behind the pool is what makes Rust, like C, POSIX-only. The handle is a `OnceLock<File>`; the pool reading from it is `thread_local!`, so neither needs a lock.
- Python's `timestamp` is the one field that can come back `None`: `datetime` stops at year 9999, while a 48-bit `unix_ts_ms` reaches 10889-08-02, so the top ~10% of the field has no `datetime`. The other five render those instants fine. `_timestamp` swallows the `OverflowError` because such a UUID is still well-formed, and because `OverflowError` is not a `ValueError`: letting it escape made `is_valid` **raise** instead of answering. Clamping to `datetime.max` would misreport the instant, so `None` it is. All six demos carry `ffffffff-ffff-7fff-bfff-ffffffffffff` in the validation table to keep this from regressing.
- C's `abort()` on a missing `/dev/urandom` is Rust's stance spelled for an API whose producers return `void`. Do not soften it into a silent `rand()` path. C reads the device through a raw fd, not a `FILE *`, on purpose: stdio would add a second buffer behind the pool, with no fork guard, and that is the layer that produced identical parent and child UUIDs before the pool existed. `uuidv7_pool_refill` retries short reads and `EINTR`, and treats anything else as the no-CSPRNG case.
- C's demo checks uniqueness with `qsort` plus an adjacent compare, libc having no hash table; every other sibling uses its set type. The monotonicity check runs on the generated order *before* anything is sorted, so the two assertions stay independent.
- C's `gmtime_r` covers the whole 48-bit field on a 64-bit `time_t` (verified at the maximum, 10889-08-02), so it does not share the Python limit. Where `time_t` is 32 bits it can fail; `decode` then zeroes the member instead of failing, the UUID still being valid.
- Rust's demo carries `utc_string`, a private days-to-civil converter, because `std` has no calendar: `SystemTime` cannot be formatted. A date crate would break the dependency-free rule, so `decode` keeps the honest `SystemTime` and only the demo converts.
- `M.entropy_source` and `M.clock_source` report which Lua fallback is live, and the demo prints both. **`math.random` is not a CSPRNG**: losing the urandom path is a security regression, not a cosmetic one. Lua's clock fallback interpolates within the current second via `os.clock`, re-anchoring on each `os.time` tick so drift stays under one second. Measured at real millisecond resolution (~986 distinct sub-second values over 2s), but it tracks CPU time, so it lags under blocking I/O.
- JavaScript's concurrency test uses four async tasks awaiting between calls; Lua's uses four round-robin coroutines. Both exercise interleaved access to the shared generator (the strongest concurrency each language offers), but neither is evidence of preemptive thread safety. Ruby, Python, Rust, and C spawn real threads, Rust's via `thread::scope` so the borrow of the `static` generator needs no `Arc`, C's via `pthread_create` into disjoint slices of one buffer. The C build is the one checkable mechanically: `cc -fsanitize=thread` runs the demo clean, worth re-running after touching the lock.

The six are wire-compatible: any UUID decodes identically in the other five. Check that after touching `assemble` or `decode`.

## Conventions

- `decode` raises on bad format, wrong version, or wrong variant (in Rust, returns `Err`), and on **nothing else**; the predicate is `decode` with that error swallowed, so any other exception escaping `decode` turns the predicate into a raising function rather than an answer. Keep validation in `decode` rather than duplicating it.
- Verify spec claims against the vendored `specs/` (`rfc9562.txt`, `.pdf`, `.mhtml`), grepping those instead of fetching the RFC. Cite sections (`RFC 9562 §6.2`) rather than restating rules from memory.
- `README.md` is pt-BR; code and comments are English. Preserve both.
- The benchmark measures only the **public** API, four operations, one driver per language. An earlier one-off also timed the raw entropy draw, which meant reaching into private internals six different ways; that stayed out on purpose. Its rules, and why each exists, are in `bench/README.md`: timing inside the process, minimum rather than mean, `black_box` in Rust and a `volatile` in C so the optimizer cannot delete the calls, and Lua's column being CPU time because standard Lua has no monotonic wall clock.
- README's performance table is one machine, one run. Re-measure rather than quoting it, and update both it and the "Entropy pool" figures in the same commit as any change that moves them. Individual runs are noisy, unevenly by language: one cell repeated nine times spread 6.6% (Rust `generate`), 9.9% (C `decode`) and 34% (Ruby predicate). The `min` of 5 reproduces within a few percent; a single run does not, so raise `reps` before believing a small change.
- Touching entropy means re-answering the fork question in that language and re-running its fork test: a pool that outlives a `fork()` makes parent and child emit identical UUIDs, the one failure this project exists to avoid. The measured figures under "Entropy pool" are `min` of 5 runs at N=100k on one machine; re-measure rather than copying them if the pool changes.
- C builds must stay warning-free under `cc -std=c11 -Wall -Wextra -pedantic`, stricter than the documented compile line; check with it after any edit.
- Formatting is hand-done in every file, including `uuid_v7.rs`, which is **not** rustfmt-clean: aligned trailing comments and one-line demo prints keep the six readable side by side. `rustfmt` collapses both, so don't run it (the file says so too).
- Doc-comment style is per-language, never mixed: YARD (`@param`/`@return`/`@raise`) in Ruby; Sphinx docstrings (`:param:`/`:return:`/`:raises:`) plus type hints in Python; JSDoc (`@param`/`@returns`/`@throws`) in JavaScript; LDoc `--` comments in Lua; rustdoc `///` with `# Arguments` / `# Returns` / `# Errors` / `# Panics` in Rust; plain `/* */` prose in C, libc documenting that way and no C doc generator being assumed.

## Keeping documentation in sync

Each file is meant to read standalone, so facts are duplicated on purpose and edits must propagate.

| Fact | Also lives in |
|---|---|
| Bit offsets / field widths | per file: header diagram, the `Field / Bits / Position` table, the comment above `assemble`, the shifts in `assemble` and `decode`, plus README's "Estrutura de bits comparada" |
| `VERSION`, `VARIANT`, `RAND_A_BITS`, `RAND_B_BITS` | the constants, their inline comments, and doc comments restating `0b0111` / `0b10` / `0xFFF` |
| Monotonicity strategy | per file: `Generator` doc comment, `next_state` inline comments, `generate` vs `generate_random` docs, plus README's "Como a v7 gera monotonicidade" |
| The assembly strategy | per file: the comment above `assemble` (in Rust and C, its warning not to propagate the hand-rolled writer), CLAUDE.md's "String assembly", and README's "Desempenho" bullets |
| `decode`'s return shape | per file: the documented key list and the literal it returns (in Rust the `Decoded` struct, in C `uuidv7_decoded`, with their field comments) |
| The demo script | six main blocks, kept section-for-section parallel |
| Filenames and API surface | each file's "run with:" comment and header cross-references, README's "Implementações" tables and snippets, the Commands section above |
| JavaScript's, Lua's, Rust's, and C's divergences | listed in each of those four headers, with a pointer to the implementing function, plus the parity table |
| The `rustc` and `cc` invocations | each file's header and demo-section comments, `.gitignore`'s Rust and C blocks, README's "Implementações" table, the Commands section above. The two output names must stay distinct |
| The benchmark's operation list | `bench/run.sh`'s `OPS`, each driver's `case`/`if` chain, `bench/README.md`, and README's "Desempenho" table |
| The entropy pool: block size, fork guard, zeroing | per file: the "Entropy pool" (or "Entropy source") comment block and `rand_bits`, plus CLAUDE.md's "Entropy pool" section, its three parity rows, and README's "Pool de entropia" |
| `UUIDV7_SIZE` / the caller-owned buffer | `uuid_v7.c`'s constant, `uuidv7_str`, every producer's signature, and the parity table's "Producing a UUID" row |

**Rules:**

- Every doc edit is a six-file edit unless genuinely language-specific. Undocumented divergence is a bug: add a parity-table row instead.
- Adding a public method means implementing it in all six, documenting it in each native style, and adding a matching demo section. Renaming a `decode` key means updating all six key lists, which are the repo's only API reference; in Rust and C that also means a struct member, the shape being a struct rather than a map.
- A workaround forced by a language limit documents *what the limit is*, not just what the code does. `assemble` in JavaScript and Lua, Lua's `current_ms` and `rand_bits`, Rust's `urandom`, `parse_hex128`, and `utc_string`, and C's `uuidv7_assemble`, `uuidv7_hex_value`, and `demo_all_unique` carry longer comments for that reason, so don't trim them.
- `README.md` covers the spec, with "Segurança e imprevisibilidade" quoting RFC §8 and §6.9 verbatim, and "Implementações neste repositório" carrying the filenames, API surface, and runnable snippets. Keep API detail at overview depth (per-argument contracts stay in source doc comments) and keep it pt-BR. Its commands and links are verified to work, so re-check after a rename or signature change.
- README's worked example (`01a09896-1ecd-7b03-bb26-376dea2187a4`) is hand-written, not generated. Re-derive it with `decode` if edited.
- The A.6 vector (`017f22e2-79b0-7cc3-98c4-dc0c0c07398f` / `1645557742000`) is fixed by the spec: a mismatch is a code bug, never an expected-value update. Correct UTC rendering is **19:22:22**, since `specs/rfc9562.txt:2329` says 2:22:22 PM GMT-05:00, easily misread as 22:22:22Z. All six decode it to `rand_a = 0xCC3`, `rand_b = 0x18C4DC0C0C07398F`.
- Update this file when the layers, monotonicity contract, parity table, or commands change.
