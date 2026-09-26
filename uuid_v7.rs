// =============================================================================
// UUIDv7: Rust implementation of RFC 9562 §5.7
// https://www.rfc-editor.org/rfc/rfc9562#section-5.7
//
// Siblings (uuid_v7.rb, .py, .js, .lua, .c) share this field layout and the same
// monotonicity contract. No Cargo.toml and no crates, so plain rustc builds it,
// on Rust 1.70+ (`OnceLock`, const `Mutex::new`, `thread::scope`):
//
//   rustc --edition 2021 -O uuid_v7.rs -o uuid_v7_rs && ./uuid_v7_rs
//
// Four language traits shape this implementation:
//   * No exceptions, so `decode` returns `Result<Decoded, DecodeError>` and the
//     fields land in a struct, not a map (`Decoded`, `decode`).
//   * Compiled, not interpreted, so the script-vs-module switch the siblings
//     make at run time happens here at build time (`main`).
//   * `std` has no CSPRNG, so entropy comes straight from /dev/urandom, which
//     makes this a POSIX-only sibling, as uuid_v7.c also is (`rand_bits`).
//   * `std` has neither a regex engine nor a calendar, so the format check is
//     hand-rolled and the demo carries its own UTC formatter (`parse_hex128`,
//     `utc_string`).
//
// Rust does have a native `u128`, so packing needs neither JavaScript's BigInt,
// Lua's per-group emission, nor C's pair of `uint64_t` (`assemble`).
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

// One file serving as both the demo binary and a reusable module: built with
// `rustc`, every item is reachable from `main`; declared as `mod uuid_v7;`,
// `main` and the demo-only `utc_string` are what goes unused instead.
#![allow(dead_code)]

// Formatting is deliberately hand-done rather than rustfmt-clean, keeping the
// aligned trailing comments and one-line demo prints that let this file be read
// side by side with its siblings. `rustfmt` collapses both; that diff is
// cosmetic, and taking it costs the parallelism.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Constants ────────────────────────────────────────────────────────────────

pub const VERSION: u8 = 0x7;    // 4-bit version field value
pub const VARIANT: u8 = 0b10;   // 2-bit variant field value (MSBs of octet 8)

pub const RAND_A_BITS: u32 = 12;
pub const RAND_B_BITS: u32 = 62;
pub const MAX_RAND_A: u16 = (1 << RAND_A_BITS) - 1;   // 0xFFF
pub const MAX_RAND_B: u64 = (1 << RAND_B_BITS) - 1;   // 0x3FFF_FFFF_FFFF_FFFF

const MASK_48: u64 = 0xFFFF_FFFF_FFFF;   // unix_ts_ms

/// RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
///
/// `std` ships no regex engine, so the shape is checked digit by digit against
/// these widths in [`parse_hex128`] instead of against a pattern.
pub const UUID_GROUP_WIDTHS: [usize; 5] = [8, 4, 4, 4, 12];

/// Length of the canonical form: 32 hex digits plus 4 hyphens.
const UUID_LEN: usize = 36;

/// Lowercase nibbles, the inverse of what `hex_value` does in [`parse_hex128`].
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

// ── Entropy source ───────────────────────────────────────────────────────────

// `std` ships no CSPRNG (that lives in the `rand` / `getrandom` crates) and this
// file takes no dependencies, so entropy comes straight from /dev/urandom: a
// CSPRNG, like Ruby's SecureRandom, Python's os.urandom and JavaScript's Web
// Crypto, and the same device uuid_v7.c opens. Reading it directly is what keeps
// these two siblings off Windows.
//
// There is no fallback: either the CSPRNG is there or the call panics, degrading
// silently to a pseudo-random generator being a security regression, not an
// inconvenience.
//
// The handle is opened once and kept open.
fn urandom() -> &'static File {
    static URANDOM: OnceLock<File> = OnceLock::new();

    URANDOM.get_or_init(|| {
        File::open("/dev/urandom")
            .expect("cannot open /dev/urandom, and there is no non-CSPRNG fallback")
    })
}

/// Bytes drawn ahead, so one `read(2)` serves many calls.
///
/// `File::read_exact` is unbuffered, so a draw per call measured ~1330 ns
/// against ~23 ns amortized over a block this size. All six siblings pool for
/// that reason, and all six owe the same two answers:
///
/// * `fork()` duplicates the pool, so parent and child would be served the same
///   bytes and emit identical UUIDs. `std` has no `fork`, but a caller reaching
///   for `libc::fork` is enough, so every draw compares the pid:
///   `std::process::id()` costs about 2 ns.
/// * the pool holds entropy not yet used, so bytes are zeroed as they are handed
///   out, keeping resident only what is still unread.
///
/// Being `thread_local!`, it needs no lock of its own, and two threads can never
/// be served the same bytes.
const POOL_LEN: usize = 4096;

struct Pool {
    bytes: [u8; POOL_LEN],
    off: usize,
    pid: u32,
}

thread_local! {
    // `const` initializer, so access is a plain TLS load with no lazy-init check.
    static POOL: RefCell<Pool> = const {
        RefCell::new(Pool {
            bytes: [0; POOL_LEN],
            off: POOL_LEN,
            pid: 0,
        })
    };
}

/// Returns `bits` random bits. Every caller asks for a power-of-two range, so
/// masking suffices, with no modulo bias to correct.
///
/// # Panics
///
/// If /dev/urandom cannot be opened or read.
fn rand_bits(bits: u32) -> u64 {
    POOL.with(|cell| {
        let pool = &mut *cell.borrow_mut();

        let pid = std::process::id();
        if pid != pool.pid {
            pool.pid = pid;
            pool.off = POOL_LEN; // drop whatever fork() handed us
        }

        if pool.off + 8 > POOL_LEN {
            let mut src = urandom();
            src.read_exact(&mut pool.bytes).expect("/dev/urandom read failed");
            pool.off = 0;
        }

        let window = &mut pool.bytes[pool.off..pool.off + 8];
        let v = u64::from_le_bytes(window.try_into().expect("an 8-byte window"));
        window.fill(0);
        pool.off += 8;

        v & ((1 << bits) - 1)
    })
}

// ── Clock ────────────────────────────────────────────────────────────────────

/// Current Unix timestamp in whole milliseconds.
///
/// # Panics
///
/// If the system clock is set before the Unix epoch, which `SystemTime` reports
/// as an error rather than a negative duration.
fn current_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is set before the Unix epoch")
        .as_millis() as u64
}

// ── Assembly ─────────────────────────────────────────────────────────────────

/// Packs the fields into a 128-bit integer and formats the UUID string.
///
/// Positions count 127 as the MSB, the opposite of the RFC-style ruler in the
/// file header, which numbers bits from 0 left to right:
///
/// ```text
///   [127..80]  unix_ts_ms   (48 bits)
///   [79..76]   ver          ( 4 bits)  -> 0b0111
///   [75..64]   rand_a       (12 bits)
///   [63..62]   var          ( 2 bits)  -> 0b10
///   [61..0]    rand_b       (62 bits)
/// ```
///
/// # Arguments
///
/// * `unix_ts_ms` - 48-bit millisecond timestamp
/// * `rand_a` - 12-bit value (counter or random)
/// * `rand_b` - 62-bit random value
///
/// # Returns
///
/// The formatted UUID. Every field is masked to its width first, so a wider
/// argument truncates instead of overflowing into its neighbour.
///
/// The nibbles are emitted over [`UUID_GROUP_WIDTHS`] rather than through
/// `format!`, where nearly all of this function's cost lived:
/// `format!("{n:032x}")` plus a second `format!` for the hyphens measured 759 ns
/// against 79 ns here, the formatting machinery parsing its template at run time
/// and allocating twice. `uuid_v7.c` dropped `snprintf` for the same reason.
/// Written with iterators rather than an index table, which is also the faster of
/// the two safe spellings (79 ns against 114), the optimizer having an easier time
/// proving the bounds.
///
/// **Do not carry this to the four interpreted siblings.** There the format
/// primitive is native code and a 32-step scripted loop is not: measured 5.6x
/// slower in Lua, 6.6x in Python, 9.7x in Ruby, 11.8x in JavaScript.
fn assemble(unix_ts_ms: u64, rand_a: u16, rand_b: u64) -> String {
    let n: u128 = ((unix_ts_ms & MASK_48) as u128) << 80
        | (VERSION as u128) << 76
        | ((rand_a & MAX_RAND_A) as u128) << 64
        | (VARIANT as u128) << 62
        | (rand_b & MAX_RAND_B) as u128;

    let mut out = String::with_capacity(UUID_LEN);
    let mut shift = 124;

    for (group, width) in UUID_GROUP_WIDTHS.iter().enumerate() {
        if group > 0 {
            out.push('-');
        }

        for _ in 0..*width {
            out.push(HEX_DIGITS[((n >> shift) & 0xF) as usize] as char);
            shift -= 4;
        }
    }

    out
}

// ── Generator ────────────────────────────────────────────────────────────────

/// The mutable half of a [`Generator`], the part the mutex guards.
struct State {
    last_ms: u64,   // last timestamp used
    seq: u16,       // rand_a counter within a millisecond
}

impl State {
    /// Advances the state and returns `(ms, seq, rand_b)`.
    fn next_state(&mut self) -> (u64, u16, u64) {
        let mut ms = current_ms();

        if ms > self.last_ms {
            // ── New millisecond: re-seed the counter ─────────────────────────
            // An 11-bit seed keeps the MSB free, leaving room for 2048 increments.
            self.seq = rand_bits(RAND_A_BITS - 1) as u16;
            self.last_ms = ms;
        } else {
            // ── Same (or rare clock regression) millisecond: increment ───────
            self.seq += 1;

            if self.seq > MAX_RAND_A {
                // Counter exhausted, so bump the virtual clock by 1 ms (RFC 9562 §6.2)
                self.last_ms += 1;
                self.seq = rand_bits(RAND_A_BITS - 1) as u16;
            }

            ms = self.last_ms;
        }

        (ms, self.seq, rand_bits(RAND_B_BITS))
    }
}

/// Thread-safe UUIDv7 generator.
///
/// Method 2 (monotonic counter) of RFC 9562 §6.2: `rand_a` is a counter
/// re-seeded on each new millisecond, so ordering is strict even within one
/// millisecond; `rand_b` is always fresh random data. On overflow (> `0xFFF`) the
/// timestamp is bumped 1 ms, the "counter rollover" that section permits.
///
/// ```text
/// let generator = Generator::new();
/// generator.generate();  // => "018f2e39-59b7-7e82-9c3a-4d5b9e2f1a60"
/// ```
///
/// `new` is a `const fn` so a shared instance can be a plain `static`, created
/// before `main` like the siblings' load-time instances, with no lazy cell.
pub struct Generator {
    state: Mutex<State>,
}

// Deliberately no `Default` impl, which is what clippy's new_without_default
// asks for: the five implementations keep one identical public surface, and only
// Rust would grow that extra constructor.
#[allow(clippy::new_without_default)]
impl Generator {
    pub const fn new() -> Self {
        Generator {
            state: Mutex::new(State { last_ms: 0, seq: 0 }),
        }
    }

    /// Generate a UUIDv7, monotonic within 1 ms.
    ///
    /// # Returns
    ///
    /// A lowercase UUID string.
    pub fn generate(&self) -> String {
        // The guard is dropped at the end of this statement, so the bit-packing
        // below happens outside the lock, as in the siblings.
        let (ms, seq, rand_b) = self.lock().next_state();

        assemble(ms, seq, rand_b)
    }

    /// Generate a UUIDv7 by Method 1, with fully random `rand_a` and `rand_b`.
    /// Simpler, but NOT monotonic within a millisecond.
    ///
    /// Touches no shared state, hence no lock.
    pub fn generate_random(&self) -> String {
        assemble(
            current_ms(),
            rand_bits(RAND_A_BITS) as u16,
            rand_bits(RAND_B_BITS),
        )
    }

    /// Generate `n` monotonically ordered UUIDv7s.
    ///
    /// # Arguments
    ///
    /// * `n` - number of UUIDs to generate (must be positive)
    ///
    /// # Panics
    ///
    /// If `n` is zero. The siblings also reject negative and non-integer
    /// arguments; here `usize` rules those out at compile time, so zero is all
    /// that is left to check.
    pub fn generate_bulk(&self, n: usize) -> Vec<String> {
        assert!(n > 0, "n must be a positive integer");

        (0..n).map(|_| self.generate()).collect()
    }

    /// Locks the state, recovering the guard if a previous holder panicked.
    ///
    /// Ruby's `Mutex` and Python's `Lock` have no notion of poisoning, and the
    /// state is a timestamp plus a counter that no panic can leave inconsistent,
    /// so ignoring it keeps behavior identical across the siblings.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// The fields of a UUIDv7, as returned by [`decode`].
///
/// Field names are the RFC's own, so they stay snake_case, which is also Rust's
/// convention. The siblings return a map; Rust has no exceptions to signal a bad
/// input mid-construction, so `decode` returns `Result<Decoded, DecodeError>`
/// and the fields get a struct with their real types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Canonical lowercase UUID string.
    pub uuid: String,
    /// Must be 7.
    pub version: u8,
    /// e.g. `"0b10"`.
    pub variant: String,
    /// Unix timestamp in milliseconds.
    pub unix_ts_ms: u64,
    /// Reconstructed from `unix_ts_ms`.
    pub timestamp: SystemTime,
    /// 12-bit `rand_a` field value.
    pub rand_a: u16,
    /// 62-bit `rand_b` field value.
    pub rand_b: u64,
}

/// Why a string is not a UUIDv7.
///
/// The three variants carry what the siblings put in their exception messages;
/// [`fmt::Display`] renders them with the same wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not 8-4-4-4-12 hex digits.
    Format(String),
    /// Well-formed, but the version field is not 7.
    Version(u8),
    /// Well-formed, but the variant bits are not `0b10`.
    Variant(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Format(uuid) => write!(f, "Invalid UUID format: {uuid:?}"),
            DecodeError::Version(version) => {
                write!(f, "Not a UUIDv7 (version field = {version}, expected 7)")
            }
            DecodeError::Variant(variant) => {
                write!(f, "Invalid variant bits (got 0b{variant:02b}, expected 0b10)")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Parses the canonical form into a 128-bit integer, or `None` if the shape is
/// wrong.
///
/// This is the format check the siblings delegate to a regex: `std` has none, so
/// the group widths from [`UUID_GROUP_WIDTHS`] are walked digit by digit.
/// `char::to_digit` takes either letter case, matching their case-insensitive
/// patterns, and rejects every non-ASCII byte.
fn parse_hex128(uuid: &str) -> Option<u128> {
    let bytes = uuid.as_bytes();

    if bytes.len() != UUID_LEN {
        return None;
    }

    let mut n: u128 = 0;
    let mut i = 0;

    for (group, width) in UUID_GROUP_WIDTHS.iter().enumerate() {
        if group > 0 {
            if bytes[i] != b'-' {
                return None;
            }
            i += 1;
        }

        for _ in 0..*width {
            n = n << 4 | (bytes[i] as char).to_digit(16)? as u128;
            i += 1;
        }
    }

    Some(n)
}

/// Decodes a UUIDv7 string into its constituent fields.
///
/// # Arguments
///
/// * `uuid` - UUID string, any letter case
///
/// # Errors
///
/// [`DecodeError`] if the format, version, or variant is invalid.
pub fn decode(uuid: &str) -> Result<Decoded, DecodeError> {
    let n = parse_checked(uuid)?;

    let version = ((n >> 76) & 0xF) as u8;
    let variant = ((n >> 62) & 0x3) as u8;
    let unix_ts_ms = (n >> 80) as u64 & MASK_48;

    Ok(Decoded {
        // ASCII, since parse_hex128 accepted only hex digits and hyphens, so the
        // Unicode-aware to_lowercase would be doing more work than the input can
        // need.
        uuid: uuid.to_ascii_lowercase(),
        version,
        variant: format!("0b{variant:02b}"),
        unix_ts_ms,
        timestamp: UNIX_EPOCH + Duration::from_millis(unix_ts_ms),
        rand_a: (n >> 64) as u16 & MAX_RAND_A,
        rand_b: n as u64 & MAX_RAND_B,
    })
}

/// Parses and validates, without building a [`Decoded`].
///
/// All [`is_valid`] needs, and the first half of what [`decode`] needs, so
/// validation still lives in one place. Going through `decode` made the predicate
/// allocate a lowercased `String` and a variant `String` only to drop them,
/// costing more than the parse itself: 242 ns against 38. `uuid_v7.c` splits the
/// same way, by passing a NULL out-parameter.
fn parse_checked(uuid: &str) -> Result<u128, DecodeError> {
    let n = parse_hex128(uuid).ok_or_else(|| DecodeError::Format(uuid.to_string()))?;

    let version = ((n >> 76) & 0xF) as u8;
    let variant = ((n >> 62) & 0x3) as u8;

    if version != VERSION {
        return Err(DecodeError::Version(version));
    }

    if variant != VARIANT {
        return Err(DecodeError::Variant(variant));
    }

    Ok(n)
}

/// True if `uuid` is a well-formed UUIDv7.
pub fn is_valid(uuid: &str) -> bool {
    parse_checked(uuid).is_ok()
}

// ── Module-level convenience API ─────────────────────────────────────────────

/// Shared, thread-safe default generator, created before `main` runs.
pub static DEFAULT_GENERATOR: Generator = Generator::new();

/// Monotonic UUIDv7 from the shared default generator. Thread-safe.
pub fn generate() -> String {
    DEFAULT_GENERATOR.generate()
}

/// UUIDv7 with fully random `rand_a` and `rand_b` (Method 1).
pub fn generate_random() -> String {
    DEFAULT_GENERATOR.generate_random()
}

/// `n` monotonically ordered UUIDv7s from the default generator.
pub fn generate_bulk(n: usize) -> Vec<String> {
    DEFAULT_GENERATOR.generate_bulk(n)
}

// =============================================================================
// Self-contained test / demo
// (build and run with: rustc --edition 2021 -O uuid_v7.rs -o uuid_v7_rs && ./uuid_v7_rs)
// =============================================================================
//
// Compiled, so there is no run-time equivalent of Ruby's
// `__FILE__ == $PROGRAM_NAME`: the switch happens at build time. `rustc` on this
// file makes `main` the entry point; declaring it as a module (`mod uuid_v7;`)
// from another crate exposes the API above and leaves `main` unused.

/// Formats a [`SystemTime`] as `"YYYY-MM-DD HH:MM:SS.mmm UTC"`.
///
/// `std` has no calendar: `SystemTime` is an opaque instant, and civil-date
/// conversion lives in the `chrono` / `time` crates. `decode` still returns the
/// real `SystemTime`, so this exists only to print it, as the JavaScript demo
/// calls `Date.prototype.toISOString` and Lua's `decode` uses `os.date`.
///
/// The date arithmetic is Howard Hinnant's `civil_from_days`, which shifts the
/// year to start in March so the leap day falls last and needs no special case.
///
/// # Panics
///
/// If `t` is before the Unix epoch, which a decoded `unix_ts_ms` never is.
fn utc_string(t: SystemTime) -> String {
    let total_ms = t
        .duration_since(UNIX_EPOCH)
        .expect("timestamp is before the Unix epoch")
        .as_millis() as u64;

    let (secs, ms) = (total_ms / 1000, total_ms % 1000);
    let (hour, minute, second) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);

    let z = secs / 86_400 + 719_468;              // days, shifted to 0000-03-01
    let era = z / 146_097;                        // 400-year cycle
    let doe = z - era * 146_097;                  // day of era,  [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;   // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                  // [0, 365]
    let mp = (5 * doy + 2) / 153;                 // March-based month, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1;       // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{ms:03} UTC")
}

fn main() {
    let bar = "=".repeat(68);

    println!("{bar}");
    println!("  UUIDv7: RFC 9562 Rust Implementation");
    println!("{bar}");

    // ── Basic generation ─────────────────────────────────────────────────────
    println!("\n── Single UUID (monotonic) ──────────────────────────────────────────");
    let uuid = generate();
    println!("  {uuid}");

    println!("\n── Single UUID (random Method 1) ───────────────────────────────────");
    println!("  {}", generate_random());

    // ── Decode ───────────────────────────────────────────────────────────────
    println!("\n── Decode ───────────────────────────────────────────────────────────");
    let info = decode(&uuid).expect("a just-generated UUID must decode");
    println!("  {:<12}  {}", "uuid", info.uuid);
    println!("  {:<12}  {}", "version", info.version);
    println!("  {:<12}  {}", "variant", info.variant);
    println!("  {:<12}  {}", "unix_ts_ms", info.unix_ts_ms);
    println!("  {:<12}  {}", "timestamp", utc_string(info.timestamp));
    println!("  {:<12}  {}", "rand_a", info.rand_a);
    println!("  {:<12}  {}", "rand_b", info.rand_b);

    // ── Bulk & monotonicity ──────────────────────────────────────────────────
    println!("\n── Bulk generation (10): monotonicity check ────────────────────────");
    let batch = generate_bulk(10);
    for u in &batch {
        println!("  {u}");
    }

    let mut sorted = batch.clone();
    sorted.sort();
    println!("\n  Sorted == generated order? {}", sorted == batch);

    // ── High-volume monotonicity stress test ─────────────────────────────────
    println!("\n── Stress test: 100_000 UUIDs, all unique, lexically ordered ────────");
    let big = generate_bulk(100_000);
    println!("  Unique?  {}", big.iter().collect::<HashSet<_>>().len() == big.len());
    println!("  Sorted?  {}", big.windows(2).all(|pair| pair[0] <= pair[1]));

    // ── Thread-safety test ───────────────────────────────────────────────────
    println!("\n── Thread-safety: 4 threads × 5_000 UUIDs ──────────────────────────");
    let buckets: Vec<Vec<String>> = thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| (0..5_000).map(|_| generate()).collect::<Vec<String>>()))
            .collect();

        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker thread panicked"))
            .collect()
    });

    let every: Vec<String> = buckets.into_iter().flatten().collect();
    println!("  Total:   {}", every.len());
    println!(
        "  Unique?  {}",
        every.iter().collect::<HashSet<_>>().len() == every.len()
    );

    // ── Validation ───────────────────────────────────────────────────────────
    println!("\n── Validation ───────────────────────────────────────────────────────");
    let generated = generate();
    let examples = [
        (generated.as_str(), true),
        ("00000000-0000-7000-8000-000000000000", true),    // minimal valid v7
        ("ffffffff-ffff-7fff-bfff-ffffffffffff", true),    // max timestamp, year 10889
        ("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", false),   // v1
        ("550e8400-e29b-41d4-a716-446655440000", false),   // v4
        ("not-a-uuid", false),
        ("", false),
    ];
    for (u, expected) in examples {
        let result = is_valid(u);
        let status = if result == expected { "✓" } else { "✗" };
        let shown = format!("{u:?}");
        println!(
            "  {status}  is_valid({:<45}) => {result}",
            &shown[..shown.len().min(45)]
        );
    }

    // ── RFC 9562 Appendix A.6 test vector ────────────────────────────────────
    println!("\n── RFC 9562 Appendix A.6 test vector ───────────────────────────────");
    // From the RFC: 017F22E2-79B0-7CC3-98C4-DC0C0C07398F, whose
    // unix_ts_ms = 0x017F22E279B0 = 1645557742000 (2022-02-22T19:22:22Z, printed
    // there as 2:22:22 PM GMT-05:00)
    let tv = decode("017f22e2-79b0-7cc3-98c4-dc0c0c07398f").expect("the A.6 vector must decode");
    println!("  UUID:        {}", tv.uuid);
    println!("  unix_ts_ms:  {}  (expected: 1645557742000)", tv.unix_ts_ms);
    println!("  timestamp:   {}", utc_string(tv.timestamp));
    println!("  version:     {}  (expected: 7)", tv.version);
    println!("  variant:     {}  (expected: 0b10)", tv.variant);
    println!("  rand_a:      0x{:X}", tv.rand_a);
    println!("  rand_b:      0x{:X}", tv.rand_b);

    println!("\n{bar}");
}
