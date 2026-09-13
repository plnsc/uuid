# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Three parallel, dependency-free implementations of UUIDv7 per **RFC 9562 §5.7**, plus study notes on the UUID spec:

| File | Runtime | Stdlib used |
|---|---|---|
| `uuid_v7.rb` | Ruby | `securerandom` |
| `uuid_v7.py` | Python 3 | `secrets`, `threading` |
| `uuid_v7.lua` | Lua 5.3+ (needs 64-bit ints and bitwise ops) | `io`, `os`, `string` |

No gemspec, Gemfile, `pyproject.toml`, rockspec, or test framework. Ruby is the original; Python and Lua are deliberate ports of it — same field layout, same monotonicity contract, same demo output. Treat them as one design with three hosts (see "Cross-language parity").

Git repository, branch `main`, no commits yet. `.gitignore` covers the Python/Ruby/Lua build cruft and macOS files; `specs/` is deliberately **not** ignored — the vendored RFC is meant to be committed.

## Commands

```bash
ruby uuid_v7.rb      # Ruby demo + self-tests
python3 uuid_v7.py   # Python demo + self-tests
lua uuid_v7.lua      # Lua demo + self-tests
```

All three run the same suite in the same order: generation, decode, bulk monotonicity, 100k stress, concurrency, validation table, RFC A.6 vector. Outputs should stay comparable side by side.

The self-tests live at the bottom of each file — `if __FILE__ == $PROGRAM_NAME` (Ruby), `if __name__ == "__main__"` (Python), `if modname == nil` (Lua, where `modname` is the `...` captured at the top of the file). Adding behavior means adding a section there; there is no separate test file. The checks print `true`/`false` or `✓`/`✗` rather than exiting non-zero, so **read the output — a failure will not fail the process**.

## Architecture

All three files have the same three layers. Ruby wraps them in a `UUIDv7` module; Python uses the module itself as the namespace; Lua returns a module table `M` (`local uuid_v7 = require("uuid_v7")`).

**Layers:**

- **`Generator`** — stateful. Holds `last_ms` and `seq`; `next_state` advances them, and bit-packing (`assemble`) is pure. Ruby and Python guard the state with a `Mutex` / `threading.Lock`; Lua has none, deliberately (see parity table).
- **Stateless parsing** — `decode` and `valid?` / `is_valid`.
- **Module-level convenience API** — `generate` / `generate_random` / `generate_bulk` delegate to a single shared default generator created at load time. Because that generator is process-global, its monotonic counter is shared across all callers; construct a `Generator` explicitly if a caller needs an independent sequence.

### Monotonicity contract

`generate` implements RFC 9562 §6.2 **Method 2**: `rand_a` (12 bits) is a counter, not random data.

- On a new millisecond the counter is re-seeded with an **11-bit** random value, deliberately leaving the MSB clear so ~2048 increments fit before overflow.
- Within the same millisecond (or on clock regression, handled by the same `else` branch) the counter increments.
- On overflow past `0xFFF`, `last_ms` is bumped by 1 ms — the virtual clock can run ahead of the real clock, by design.

Consequence: sorting `generate` output lexicographically yields creation order. `generate_random` (Method 1, fully random `rand_a`) does **not** provide this — keep the two paths distinct when editing.

This contract is what makes the Lua clock fallback (below) acceptable: ordering never depends on the clock, only timestamp *accuracy* does.

### Bit layout

Layout: `unix_ts_ms`(48) | `ver`=7(4) | `rand_a`(12) | `var`=0b10(2) | `rand_b`(62).

Field positions are documented in each file's header comment and repeated above `assemble`. Ruby and Python pack everything into one arbitrary-precision integer and format it with `%032x`; `decode` reverses that with shifts and masks.

**Lua cannot do this** — its integers are 64-bit, so `assemble` emits the value hex group by hex group. The groups align with field boundaries except for `rand_b`, whose top 14 bits share group 4 with the variant; `decode` reassembles it as `((group4 & 0x3FFF) << 48) | group5`. This is the one place where the three implementations genuinely differ in structure rather than in spelling. Any change to offsets must stay consistent across the header diagram, `assemble`, and `decode`, **in all three files**.

### Cross-language parity

A change to behavior in one file belongs in the others in the same commit. What intentionally differs:

| | Ruby | Python | Lua |
|---|---|---|---|
| Namespace | `UUIDv7` module | the module itself | returned table `M` |
| Method call | `gen.generate` | `gen.generate()` | `gen:generate()` (colon) |
| Predicate | `valid?` | `is_valid` | `is_valid` |
| Invalid input | raises `ArgumentError` | raises `ValueError` | `error()`; `is_valid` uses `pcall` |
| Format check | `UUID_REGEX` | `UUID_REGEX` (`re`) | `UUID_PATTERN` — Lua patterns have no `{n}` or alternation, so the 8-4-4-4-12 shape is spelled out literally |
| CSPRNG | `SecureRandom.random_number(n)` | `secrets.randbelow(n)` | reads `/dev/urandom`, falls back to `math.random` |
| Clock | `Process.clock_gettime(CLOCK_REALTIME, :millisecond)` | `time.time_ns() // 1_000_000` | luaposix / luasocket if present, else `os.time` + `os.clock` interpolation |
| Concurrency | `Mutex` | `threading.Lock` | none — no preemptive threads in standard Lua |
| Packing | one 128-bit integer | one 128-bit integer | per hex group (64-bit ceiling) |
| `decode` timestamp | `Time` (UTC) | `datetime` (tz-aware UTC) | formatted `string`, `"YYYY-MM-DD HH:MM:SS.mmm UTC"` |
| `decode` result | `Hash`, Symbol keys | `dict`, `str` keys | `table`, `str` keys — same names throughout |

Language-specific notes:

- Python's `generate_bulk` rejects `bool` explicitly (`True` is an `int` in Python, so `isinstance(n, int)` alone would accept it). Lua uses `math.type(n) ~= "integer"`, which rejects floats like `3.0`.
- Lua's fallbacks are introspectable at runtime: `M.entropy_source` and `M.clock_source` report which path is live, and the demo prints both. **`math.random` is not a CSPRNG** — if the urandom path is ever unavailable, that is a security-relevant degradation, not a cosmetic one.
- Lua's clock fallback interpolates within the current second with `os.clock`, re-anchoring on every `os.time` tick so drift cannot exceed one second. Measured resolution on the fallback path is real milliseconds (~986 distinct sub-second values over a 2s run), but it is CPU time, so it lags under blocking I/O.
- Lua's concurrency test uses four round-robin coroutines instead of threads. It exercises interleaved access to the shared generator, which is the strongest concurrency the language offers here; it is *not* evidence of preemptive thread safety.

The implementations are wire-compatible: a UUID generated by any one of them decodes identically in the other two. That is worth checking after touching `assemble` or `decode`.

## Conventions

- `decode` raises on bad format, wrong version, or wrong variant; `valid?` / `is_valid` is `decode` with that error swallowed. Validation logic should keep flowing through `decode` rather than being duplicated in the predicate.
- Reference material for verifying spec claims is vendored in `specs/` (`rfc9562.txt`, `.pdf`, `.mhtml`) — grep those rather than fetching the RFC.
- `README.md` is written in Portuguese (pt-BR); code and comments are in English. Preserve both when editing.
- Doc-comment style is per-language and should not be mixed: YARD tags (`@param` / `@return` / `@raise`) in Ruby; Sphinx-style docstrings (`:param:` / `:return:` / `:raises:`) plus type hints in Python; LDoc-style `--` comments (`@param` / `@return` / `@raise`) in Lua.

## Keeping documentation in sync

Documentation here is duplicated across several surfaces on purpose (each file is meant to be readable standalone), so edits have to propagate. Written in English to match the rest of this file, even though `README.md` is pt-BR.

**Where the same facts live more than once:**

| Fact | Appears in |
|---|---|
| Bit offsets / field widths | in **each** of the three files: header ASCII diagram, the `Field / Bits / Position` table under it, the comment above `assemble`, the shifts in `assemble`, the shifts and masks in `decode` — plus README's "Estrutura de bits comparada" table |
| Constant values (`VERSION`, `VARIANT`, `RAND_A_BITS`, `RAND_B_BITS`) | the constants themselves, their inline comments, the doc comments that restate `0b0111` / `0b10` / `0xFFF` |
| Monotonicity strategy (Method 2, 11-bit re-seed, counter rollover) | in **each** file: `Generator` doc comment, inline comments in `next_state`, `generate` vs `generate_random` doc comments — plus README's "Como a v7 gera monotonicidade" |
| Return-value shape of `decode` | in **each** file: the documented key list and the actual literal at the end of the method |
| The demo/self-test script | the three main blocks, kept section-for-section parallel |
| Filenames and the public API surface | each file's "run with:" comment and header cross-references, README's "Implementações" tables and snippets, the Commands section above — a rename touches all three places |
| Lua's divergences | `uuid_v7.lua`'s header comment summarises all three, each with a pointer to the function that implements it — plus the parity table above |

Change one, grep for the others.

**Rules of thumb:**

- Every doc edit is a **three-file** edit unless it is genuinely language-specific — the parity table is the list of things allowed to differ. Add a row there rather than letting an undocumented divergence appear.
- Renaming or adding a `decode` key means updating the documented key list in all three files in the same commit — those lists are the only API reference the repo has.
- Adding a public method: implement it in all three, document it in each file's native style, and add a matching section to each demo block. The demo blocks double as usage documentation.
- A workaround forced by a language limit gets a comment saying *what the limit is*, not just what the code does — that is why `assemble`, `current_ms`, and `rand_bits` in the Lua file carry longer comments than their Ruby and Python counterparts. Keep that asymmetry; it is the point.
- `README.md` is primarily about the UUID *specification*, but its "Implementações neste repositório" section also lists the filenames, the shared API surface, and runnable snippets. Keep API detail there at overview depth — the per-argument contract stays in the source doc comments — and keep the whole file pt-BR.
- Every command and link in `README.md` should actually run/resolve; the snippets there were verified against the real files, so re-check them after a rename or signature change.
- Spec claims (in either language) must be checkable against `specs/rfc9562.txt`; cite the section (`RFC 9562 §6.2`) the way existing comments do rather than restating the rule from memory.
- README's worked example (`01a09896-1ecd-7b03-bb26-376dea2187a4`, decoded field by field) is a hand-written illustration, not generated output. If you edit it, re-derive the fields with `decode` so the hex, the timestamp, and the prose stay consistent.
- The RFC A.6 test vector in the demo blocks (`017f22e2-79b0-7cc3-98c4-dc0c0c07398f` / `1645557742000`) is fixed by the spec — treat a mismatch as a bug in the code, never update the expected values to match output. Its correct UTC rendering is **19:22:22**; `specs/rfc9562.txt:2329` states it as 2:22:22 PM GMT-05:00, which is easy to misread as 22:22:22Z. All three files decode it to `rand_a = 0xCC3`, `rand_b = 0x18C4DC0C0C07398F`.
- Update this file when the layers, the monotonicity contract, the parity table, or the run commands change.
