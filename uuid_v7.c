/* =============================================================================
 * UUIDv7: C implementation of RFC 9562, Section 5.7
 * https://www.rfc-editor.org/rfc/rfc9562#section-5.7
 * https://datatracker.ietf.org/doc/html/rfc9562
 * https://en.wikipedia.org/wiki/Universally_unique_identifier
 *
 * Sibling implementations (uuid_v7.rb, uuid_v7.py, uuid_v7.js, uuid_v7.lua,
 * uuid_v7.rs) share the same field layout and monotonicity contract. No build
 * system and no libraries beyond libc:
 *
 *   cc -std=c11 -O2 -pthread uuid_v7.c -o uuid_v7_c && ./uuid_v7_c
 *
 * Five language traits shape this implementation:
 *   * No 128-bit integer in ISO C, so the value is a pair of uint64_t. The
 *     split at the variant boundary is exact, so both halves keep whole fields
 *     (`uuidv7_assemble`).
 *   * No exceptions, so `uuidv7_decode` returns a status code and fills a
 *     caller-provided struct (`uuidv7_status`, `uuidv7_decode`).
 *   * No managed strings, so every producer writes into a caller-provided
 *     buffer of UUIDV7_SIZE bytes and nothing here allocates.
 *   * No portable mutex: C11 <threads.h> is optional and Apple's libc omits it
 *     (__STDC_NO_THREADS__), so the lock is POSIX pthreads.
 *   * No regex, no CSPRNG, and no hash table in the standard library, so the
 *     format check is hand-rolled (`uuidv7_parse`), entropy is /dev/urandom
 *     (`uuidv7_rand_bits`), and the demo checks uniqueness with qsort.
 *
 * Together with /dev/urandom and clock_gettime, the pthreads lock makes this,
 * like uuid_v7.rs, a POSIX-only sibling.
 *
 * 128-bit field layout (big-endian, MSB first):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           unix_ts_ms                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          unix_ts_ms           |  ver  |        rand_a         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |var|                         rand_b                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           rand_b                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Field       Bits    Position        Description
 * ─────────────────────────────────────────────────────────────────
 * unix_ts_ms  48      [127..80]  Unix epoch timestamp (milliseconds)
 * ver          4      [79..76]   Version = 0b0111 (7)
 * rand_a      12      [75..64]   Random data / monotonic counter
 * var          2      [63..62]   Variant = 0b10 (RFC 4122 / 9562)
 * rand_b      62      [61..0]    Cryptographically random data
 * =============================================================================
 */

/* clock_gettime and pthreads are POSIX, which -std=c11 alone hides. Declaring
 * the feature level here keeps the documented compile line free of -D flags. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define UUIDV7_VERSION 0x7u  /* 4-bit version field value */
#define UUIDV7_VARIANT 0x2u  /* 2-bit variant field value (0b10, MSBs of octet 8) */

#define UUIDV7_RAND_A_BITS 12u
#define UUIDV7_RAND_B_BITS 62u
#define UUIDV7_MAX_RAND_A  0xFFFu                              /* 12 bits */
#define UUIDV7_MAX_RAND_B  ((UINT64_C(1) << UUIDV7_RAND_B_BITS) - 1) /* 62 bits */

#define UUIDV7_MASK_48 UINT64_C(0xFFFFFFFFFFFF)  /* unix_ts_ms, and rand_b's low half */

/* RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", so 36 characters plus
 * the terminator. Every function that produces a UUID writes exactly this many
 * bytes, and the caller owns the storage. */
#define UUIDV7_LEN  36u
#define UUIDV7_SIZE 37u

/* Hex digits per group, the shape a regex would spell as 8-4-4-4-12. */
#define UUIDV7_GROUPS 5u

/* ── Types ───────────────────────────────────────────────────────────────── */

/* A buffer big enough for one UUID string, terminator included.
 *
 * Nothing here allocates, so this names the storage every producer expects the
 * caller to own. It is a convenience, not a requirement: any `char[37]` works.
 */
typedef char uuidv7_str[UUIDV7_SIZE];

/* Outcome of a decode. C has no exceptions, so the three failures the siblings
 * raise become return values; uuidv7_strerror renders them with the same
 * wording those exception messages use. */
typedef enum {
    UUIDV7_OK = 0,
    UUIDV7_ERR_FORMAT = -1,  /* not 8-4-4-4-12 hex digits */
    UUIDV7_ERR_VERSION = -2, /* well-formed, but version != 7 */
    UUIDV7_ERR_VARIANT = -3, /* well-formed, but variant bits != 0b10 */
    UUIDV7_ERR_ARG = -4      /* caller passed a bad argument (see generate_bulk) */
} uuidv7_status;

/* The fields of a UUIDv7, as filled in by uuidv7_decode.
 *
 * Member names are the RFC's own, so they stay snake_case, as in every sibling.
 * The others return a map or a struct; C gets a plain struct the caller owns,
 * which is why decode takes it as an out-parameter instead of returning it. */
typedef struct {
    char uuid[UUIDV7_SIZE]; /* canonical lowercase UUID string */
    unsigned version;       /* must be 7 */
    char variant[5];        /* e.g. "0b10" */
    uint64_t unix_ts_ms;    /* Unix timestamp in milliseconds */
    struct tm timestamp;    /* UTC calendar time reconstructed from unix_ts_ms */
    uint16_t rand_a;        /* 12-bit rand_a field value */
    uint64_t rand_b;        /* 62-bit rand_b field value */
} uuidv7_decoded;

/* Thread-safe UUIDv7 generator.
 *
 * Method 2 (monotonic counter) of RFC 9562 §6.2: rand_a is a counter re-seeded
 * on each new millisecond, giving strict lexicographic ordering even within a
 * single millisecond; rand_b is always fresh random data. On counter overflow
 * (> 0xFFF) the timestamp is bumped 1 ms, the "counter rollover" that same
 * section permits.
 *
 *   uuidv7_generator gen;
 *   char out[UUIDV7_SIZE];
 *   uuidv7_generator_init(&gen);
 *   uuidv7_generator_generate(&gen, out);
 *
 * A generator with static storage can skip the init call and use
 * UUIDV7_GENERATOR_INIT instead, which is how the shared default one below is
 * ready before main runs, matching the siblings' load-time instances. */
typedef struct {
    pthread_mutex_t mutex;
    uint64_t last_ms; /* last timestamp used */
    uint16_t seq;     /* rand_a counter within a millisecond */
} uuidv7_generator;

#define UUIDV7_GENERATOR_INIT { PTHREAD_MUTEX_INITIALIZER, 0, 0 }

/* ── Entropy source ──────────────────────────────────────────────────────── */

/* libc has no CSPRNG in ISO C, and the ones that exist are per-platform
 * (arc4random_buf on BSD, getrandom on Linux), so entropy comes straight from
 * /dev/urandom: a CSPRNG, matching Ruby's SecureRandom, Python's os.urandom,
 * JavaScript's Web Crypto, and the same device uuid_v7.rs reads.
 *
 * As in every sibling, there is no fallback: rand() is not cryptographically
 * secure, so a missing device aborts the process instead of degrading silently.
 * Aborting is what a void-returning C API has in place of Rust's panic; a
 * library that must survive it should call this differently, not weaken the
 * generator.
 *
 * Draws come from a pool rather than one read per call: a read(2) of 8 bytes
 * measured ~1190 ns against ~31 ns amortized over a 4096-byte block. All six
 * siblings pool for that reason, and all six owe the same two answers:
 *
 *   * fork() duplicates the pool, so parent and child would be served the same
 *     bytes and emit identical UUIDs. That is not hypothetical here: an earlier
 *     version of this file read through a FILE *, whose stdio buffer did exactly
 *     that, and parent and child produced byte-identical UUIDs on every run.
 *     The pid is compared on every draw, at ~3 ns, and an inherited pool is
 *     dropped. Reading the fd directly also keeps stdio from adding a second
 *     buffer with no such guard.
 *   * the pool holds entropy not yet used, so bytes are zeroed as they are
 *     handed out, keeping the resident window to what is still unread.
 *
 * The pool is _Thread_local, so concurrent draws need no lock of their own and
 * two threads can never be served the same bytes. */
#define UUIDV7_POOL_LEN 4096

static int uuidv7_urandom_fd = -1;
static pthread_once_t uuidv7_urandom_once = PTHREAD_ONCE_INIT;

static _Thread_local unsigned char uuidv7_pool[UUIDV7_POOL_LEN];
static _Thread_local size_t uuidv7_pool_off = UUIDV7_POOL_LEN;
static _Thread_local pid_t uuidv7_pool_pid = 0;

static void uuidv7_urandom_open(void)
{
    uuidv7_urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
}

/* Refills the pool, or aborts. Short reads and EINTR are retried; anything else
 * is the no-CSPRNG case. */
static void uuidv7_pool_refill(void)
{
    pthread_once(&uuidv7_urandom_once, uuidv7_urandom_open);

    size_t filled = 0;
    while (filled < UUIDV7_POOL_LEN) {
        ssize_t got = uuidv7_urandom_fd < 0
                    ? -1
                    : read(uuidv7_urandom_fd, uuidv7_pool + filled,
                           UUIDV7_POOL_LEN - filled);

        if (got > 0) {
            filled += (size_t)got;
        } else if (!(got < 0 && errno == EINTR)) {
            fputs("uuid_v7: cannot read /dev/urandom, and there is no non-CSPRNG "
                  "fallback\n", stderr);
            abort();
        }
    }

    uuidv7_pool_off = 0;
}

/* Returns `bits` random bits. Every caller asks for a power-of-two range, so
 * masking suffices, with no modulo bias to correct. */
static uint64_t uuidv7_rand_bits(unsigned bits)
{
    pid_t self = getpid();
    if (self != uuidv7_pool_pid) {
        uuidv7_pool_pid = self;
        uuidv7_pool_off = UUIDV7_POOL_LEN;   /* drop whatever fork() handed us */
    }

    if (uuidv7_pool_off + 8 > UUIDV7_POOL_LEN) {
        uuidv7_pool_refill();
    }

    unsigned char *p = uuidv7_pool + uuidv7_pool_off;

    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }

    memset(p, 0, 8);
    uuidv7_pool_off += 8;

    return v & ((UINT64_C(1) << bits) - 1);
}

/* ── Clock ───────────────────────────────────────────────────────────────── */

/* Current Unix timestamp in whole milliseconds. ISO C offers only time() at
 * one-second resolution and the optional timespec_get, so this uses POSIX
 * clock_gettime, the same wall clock the Ruby sibling asks for by name. */
static uint64_t uuidv7_current_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fputs("uuid_v7: clock_gettime(CLOCK_REALTIME) failed\n", stderr);
        abort();
    }

    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ── Assembly ────────────────────────────────────────────────────────────── */

/* Packs all fields and writes the UUID string into `out`.
 *
 * Ruby, Python, JavaScript, and Rust build one 128-bit integer; ISO C has no
 * such type (__int128 is a compiler extension, absent on MSVC), and Lua works
 * around the same gap per hex group. C splits the value in two uint64_t
 * instead, and the split is exact: the variant sits at the octet-8 boundary,
 * which is also the halfway point, so each half holds whole fields.
 *
 * Positions below count 127 as the MSB, the opposite of the RFC-style ruler in
 * the file header, which numbers bits from 0 left to right:
 *
 *   hi = [127..64]   unix_ts_ms (48) | ver (4) | rand_a (12)
 *   lo = [63..0]     var (2) | rand_b (62)
 *
 * Only rand_b straddles a hex group, its top 14 bits sharing group 4 with the
 * variant, exactly as in uuid_v7.lua:
 *
 *   group 1 (8 hex)  hi[63..32]   unix_ts_ms[47..16]
 *   group 2 (4 hex)  hi[31..16]   unix_ts_ms[15..0]
 *   group 3 (4 hex)  hi[15..0]    ver + rand_a
 *   group 4 (4 hex)  lo[63..48]   var + rand_b[61..48]
 *   group 5 (12 hex) lo[47..0]    rand_b[47..0]
 *
 * Every field is masked to its width first, so a wider argument truncates
 * instead of overflowing into its neighbour.
 */
static void uuidv7_assemble(uint64_t unix_ts_ms, uint16_t rand_a, uint64_t rand_b,
                            char out[UUIDV7_SIZE])
{
    uint64_t hi = ((unix_ts_ms & UUIDV7_MASK_48) << 16)
                | ((uint64_t)UUIDV7_VERSION << 12)
                | (uint64_t)(rand_a & UUIDV7_MAX_RAND_A);

    uint64_t lo = ((uint64_t)UUIDV7_VARIANT << 62) | (rand_b & UUIDV7_MAX_RAND_B);

    snprintf(out, UUIDV7_SIZE,
             "%08" PRIx32 "-%04" PRIx32 "-%04" PRIx32 "-%04" PRIx32 "-%012" PRIx64,
             (uint32_t)(hi >> 32),
             (uint32_t)((hi >> 16) & 0xFFFF),
             (uint32_t)(hi & 0xFFFF),
             (uint32_t)(lo >> 48),
             lo & UUIDV7_MASK_48);
}

/* ── Generator ───────────────────────────────────────────────────────────── */

/* Initialize a generator. Only needed for automatic or allocated storage;
 * static ones use UUIDV7_GENERATOR_INIT. */
void uuidv7_generator_init(uuidv7_generator *gen)
{
    pthread_mutex_init(&gen->mutex, NULL);
    gen->last_ms = 0;
    gen->seq = 0;
}

/* Advances internal state and returns the three field values through
 * out-parameters. MUST be called with gen->mutex held. */
static void uuidv7_next_state(uuidv7_generator *gen, uint64_t *ms, uint16_t *seq,
                              uint64_t *rand_b)
{
    uint64_t now = uuidv7_current_ms();

    if (now > gen->last_ms) {
        /* ── New millisecond: re-seed the counter ───────────────────────────
         * An 11-bit seed keeps the MSB free, leaving room for 2048 increments. */
        gen->seq = (uint16_t)uuidv7_rand_bits(UUIDV7_RAND_A_BITS - 1);
        gen->last_ms = now;
    } else {
        /* ── Same (or rare clock regression) millisecond: increment ───────── */
        gen->seq++;

        if (gen->seq > UUIDV7_MAX_RAND_A) {
            /* Counter exhausted, so bump the virtual clock by 1 ms (RFC 9562 §6.2) */
            gen->last_ms++;
            gen->seq = (uint16_t)uuidv7_rand_bits(UUIDV7_RAND_A_BITS - 1);
        }

        now = gen->last_ms;
    }

    *ms = now;
    *seq = gen->seq;
    *rand_b = uuidv7_rand_bits(UUIDV7_RAND_B_BITS);
}

/* Generate a UUIDv7, monotonic within 1 ms, into `out` (UUIDV7_SIZE bytes). */
void uuidv7_generator_generate(uuidv7_generator *gen, char out[UUIDV7_SIZE])
{
    uint64_t ms, rand_b;
    uint16_t seq;

    /* The bit-packing happens after the unlock, as in the siblings. */
    pthread_mutex_lock(&gen->mutex);
    uuidv7_next_state(gen, &ms, &seq, &rand_b);
    pthread_mutex_unlock(&gen->mutex);

    uuidv7_assemble(ms, seq, rand_b, out);
}

/* Generate a UUIDv7 by Method 1, with fully random rand_a and rand_b. Simpler,
 * but NOT monotonic within a millisecond. Touches no shared state, hence no
 * lock, so the generator argument is there only for API symmetry. */
void uuidv7_generator_generate_random(uuidv7_generator *gen, char out[UUIDV7_SIZE])
{
    (void)gen;

    uuidv7_assemble(uuidv7_current_ms(),
                    (uint16_t)uuidv7_rand_bits(UUIDV7_RAND_A_BITS),
                    uuidv7_rand_bits(UUIDV7_RAND_B_BITS),
                    out);
}

/* Generate `n` monotonically ordered UUIDv7s into `out[0..n-1]`.
 *
 * Returns UUIDV7_OK, or UUIDV7_ERR_ARG when n is zero or out is NULL. The
 * siblings also reject negative and non-integer arguments; size_t rules those
 * out at compile time, so zero is all that is left to check. */
uuidv7_status uuidv7_generator_generate_bulk(uuidv7_generator *gen, size_t n,
                                             char out[][UUIDV7_SIZE])
{
    if (n == 0 || out == NULL) {
        return UUIDV7_ERR_ARG;
    }

    for (size_t i = 0; i < n; i++) {
        uuidv7_generator_generate(gen, out[i]);
    }

    return UUIDV7_OK;
}

/* ── Decoder ─────────────────────────────────────────────────────────────── */

/* Value of one hex digit, or -1.
 *
 * Spelled out rather than using isxdigit/strtoull, because the <ctype.h>
 * predicates are locale-dependent and take an int that must be an unsigned char,
 * and because strtoull would accept leading whitespace, a sign, and a 0x prefix
 * that this format forbids. Accepting both letter cases matches the siblings'
 * case-insensitive patterns. */
static int uuidv7_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parses the canonical form into the two halves, returning false if the shape is
 * wrong. This is the format check the siblings delegate to a regex: the C
 * standard library has none, so the group widths are walked digit by digit.
 *
 * uuidv7_hex_value rejects '\0' like any other non-digit, so a short string
 * fails before this reads past its terminator, and the check after the loop
 * rejects anything trailing, a newline included. */
static bool uuidv7_parse(const char *uuid, uint64_t *hi, uint64_t *lo)
{
    static const unsigned widths[UUIDV7_GROUPS] = { 8, 4, 4, 4, 12 };
    uint64_t groups[UUIDV7_GROUPS] = { 0 };
    size_t i = 0;

    if (uuid == NULL) {
        return false;
    }

    for (unsigned g = 0; g < UUIDV7_GROUPS; g++) {
        if (g > 0) {
            if (uuid[i] != '-') return false;
            i++;
        }

        for (unsigned d = 0; d < widths[g]; d++) {
            int value = uuidv7_hex_value(uuid[i]);
            if (value < 0) return false;
            groups[g] = (groups[g] << 4) | (uint64_t)value;
            i++;
        }
    }

    if (uuid[i] != '\0') {
        return false;
    }

    *hi = groups[0] << 32 | groups[1] << 16 | groups[2];
    *lo = groups[3] << 48 | groups[4];

    return true;
}

/* Decodes a UUIDv7 string into its constituent fields.
 *
 * `uuid` may be in any letter case; `out` may be NULL, which checks validity
 * and discards the fields, and is exactly what uuidv7_is_valid does.
 *
 * Returns UUIDV7_OK, or UUIDV7_ERR_FORMAT / _VERSION / _VARIANT for the three
 * conditions the siblings raise on, and nothing else: a well-formed UUIDv7
 * always decodes.
 *
 * out->timestamp comes from gmtime_r, which covers the whole 48-bit field on a
 * 64-bit time_t (the maximum, 10889-08-02, was checked). Where time_t is 32
 * bits, gmtime_r can fail; the member is then zeroed rather than failing the
 * decode, since the UUID itself is still valid. The Python sibling returns None
 * in the same situation, for a narrower range. */
uuidv7_status uuidv7_decode(const char *uuid, uuidv7_decoded *out)
{
    uint64_t hi, lo;

    if (!uuidv7_parse(uuid, &hi, &lo)) {
        return UUIDV7_ERR_FORMAT;
    }

    unsigned version = (unsigned)((hi >> 12) & 0xF);
    unsigned variant = (unsigned)((lo >> 62) & 0x3);

    if (version != UUIDV7_VERSION) {
        return UUIDV7_ERR_VERSION;
    }

    if (variant != UUIDV7_VARIANT) {
        return UUIDV7_ERR_VARIANT;
    }

    if (out == NULL) {
        return UUIDV7_OK;
    }

    for (size_t i = 0; i < UUIDV7_LEN; i++) {
        char c = uuid[i];
        out->uuid[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    out->uuid[UUIDV7_LEN] = '\0';

    out->version = version;
    snprintf(out->variant, sizeof out->variant, "0b%u%u", variant >> 1, variant & 1);

    out->unix_ts_ms = hi >> 16;
    out->rand_a = (uint16_t)(hi & UUIDV7_MAX_RAND_A);
    out->rand_b = lo & UUIDV7_MAX_RAND_B;

    time_t seconds = (time_t)(out->unix_ts_ms / 1000);
    if (gmtime_r(&seconds, &out->timestamp) == NULL) {
        memset(&out->timestamp, 0, sizeof out->timestamp);
    }

    return UUIDV7_OK;
}

/* True if `uuid` is a well-formed UUIDv7. */
bool uuidv7_is_valid(const char *uuid)
{
    return uuidv7_decode(uuid, NULL) == UUIDV7_OK;
}

/* Message for a status code.
 *
 * Not extra API: this is where the siblings' exception messages live, the same
 * role uuid_v7.rs gives Display for DecodeError. The wording matches theirs,
 * minus the offending value, which a return code cannot carry. */
const char *uuidv7_strerror(uuidv7_status status)
{
    switch (status) {
    case UUIDV7_OK:          return "ok";
    case UUIDV7_ERR_FORMAT:  return "Invalid UUID format";
    case UUIDV7_ERR_VERSION: return "Not a UUIDv7 (version field is not 7)";
    case UUIDV7_ERR_VARIANT: return "Invalid variant bits (expected 0b10)";
    case UUIDV7_ERR_ARG:     return "n must be a positive integer";
    }

    return "unknown status";
}

/* ── Module-level convenience API ────────────────────────────────────────── */

/* Shared, thread-safe default generator, ready before main runs. Process-global,
 * so its counter is shared by all callers; declare your own generator for an
 * independent sequence. */
static uuidv7_generator uuidv7_default_generator = UUIDV7_GENERATOR_INIT;

/* Monotonic UUIDv7 from the shared default generator. Thread-safe. */
void uuidv7_generate(char out[UUIDV7_SIZE])
{
    uuidv7_generator_generate(&uuidv7_default_generator, out);
}

/* UUIDv7 with fully random rand_a and rand_b (Method 1). */
void uuidv7_generate_random(char out[UUIDV7_SIZE])
{
    uuidv7_generator_generate_random(&uuidv7_default_generator, out);
}

/* `n` monotonically ordered UUIDv7s from the default generator. */
uuidv7_status uuidv7_generate_bulk(size_t n, char out[][UUIDV7_SIZE])
{
    return uuidv7_generator_generate_bulk(&uuidv7_default_generator, n, out);
}

/* =============================================================================
 * Self-contained test / demo
 * (build and run with: cc -std=c11 -O2 -pthread uuid_v7.c -o uuid_v7_c && ./uuid_v7_c)
 * =============================================================================
 *
 * C is compiled, so there is no run-time equivalent of Ruby's
 * `__FILE__ == $PROGRAM_NAME`, and like uuid_v7.rs the switch happens at build
 * time: compiling this file as-is produces the demo, while -DUUIDV7_NO_MAIN
 * leaves only the API, to be linked into another program or #included by it.
 */
#ifndef UUIDV7_NO_MAIN

#define DEMO_BULK    10u
#define DEMO_STRESS  100000u
#define DEMO_THREADS 4u
#define DEMO_PER_THREAD 5000u

/* Formats a decoded timestamp as "YYYY-MM-DD HH:MM:SS.mmm UTC".
 *
 * struct tm has no sub-second member, so the milliseconds come from
 * unix_ts_ms, just as uuid_v7.lua composes its own string. This is the C
 * counterpart of JavaScript's toISOString call and Rust's utc_string. */
static void demo_format_time(const uuidv7_decoded *d, char *buf, size_t size)
{
    char stamp[40];

    if (strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &d->timestamp) == 0) {
        snprintf(buf, size, "(not representable as a calendar time)");
        return;
    }

    snprintf(buf, size, "%s.%03u UTC", stamp, (unsigned)(d->unix_ts_ms % 1000));
}

static int demo_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* True if no string repeats. The C standard library has no hash table, so this
 * sorts a copy and compares neighbours, where Ruby uses a Set, Python and
 * JavaScript a set, Lua a table, and Rust a HashSet. */
static bool demo_all_unique(const uuidv7_str *list, size_t n)
{
    uuidv7_str *copy = malloc(n * sizeof *copy);
    if (copy == NULL) {
        fputs("demo: out of memory\n", stderr);
        exit(EXIT_FAILURE);
    }

    memcpy(copy, list, n * sizeof *copy);
    qsort(copy, n, sizeof *copy, demo_cmp);

    bool unique = true;
    for (size_t i = 1; i < n; i++) {
        if (strcmp(copy[i - 1], copy[i]) == 0) {
            unique = false;
            break;
        }
    }

    free(copy);
    return unique;
}

static bool demo_is_ordered(const uuidv7_str *list, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        if (strcmp(list[i - 1], list[i]) > 0) return false;
    }
    return true;
}

struct demo_worker {
    size_t count;
    uuidv7_str *out;
};

static void *demo_worker_run(void *raw)
{
    struct demo_worker *work = raw;

    for (size_t i = 0; i < work->count; i++) {
        uuidv7_generate(work->out[i]);
    }

    return NULL;
}

int main(void)
{
    char bar[69];
    memset(bar, '=', sizeof bar - 1);
    bar[sizeof bar - 1] = '\0';

    printf("%s\n", bar);
    printf("  UUIDv7: RFC 9562 C Implementation\n");
    printf("%s\n", bar);

    /* ── Basic generation ────────────────────────────────────────────────── */
    printf("\n── Single UUID (monotonic) ──────────────────────────────────────────\n");
    uuidv7_str uuid;
    uuidv7_generate(uuid);
    printf("  %s\n", uuid);

    printf("\n── Single UUID (random Method 1) ───────────────────────────────────\n");
    uuidv7_str random_uuid;
    uuidv7_generate_random(random_uuid);
    printf("  %s\n", random_uuid);

    /* ── Decode ──────────────────────────────────────────────────────────── */
    printf("\n── Decode ───────────────────────────────────────────────────────────\n");
    uuidv7_decoded info;
    uuidv7_status status = uuidv7_decode(uuid, &info);
    if (status != UUIDV7_OK) {
        fprintf(stderr, "demo: a just-generated UUID must decode: %s\n",
                uuidv7_strerror(status));
        return EXIT_FAILURE;
    }

    char when[64];
    demo_format_time(&info, when, sizeof when);
    printf("  %-12s  %s\n", "uuid", info.uuid);
    printf("  %-12s  %u\n", "version", info.version);
    printf("  %-12s  %s\n", "variant", info.variant);
    printf("  %-12s  %" PRIu64 "\n", "unix_ts_ms", info.unix_ts_ms);
    printf("  %-12s  %s\n", "timestamp", when);
    printf("  %-12s  %u\n", "rand_a", info.rand_a);
    printf("  %-12s  %" PRIu64 "\n", "rand_b", info.rand_b);

    /* ── Bulk & monotonicity ─────────────────────────────────────────────── */
    printf("\n── Bulk generation (10): monotonicity check ────────────────────────\n");
    uuidv7_str batch[DEMO_BULK];
    uuidv7_generate_bulk(DEMO_BULK, batch);
    for (size_t i = 0; i < DEMO_BULK; i++) {
        printf("  %s\n", batch[i]);
    }

    uuidv7_str sorted[DEMO_BULK];
    memcpy(sorted, batch, sizeof batch);
    qsort(sorted, DEMO_BULK, sizeof *sorted, demo_cmp);
    printf("\n  Sorted == generated order? %s\n",
           memcmp(sorted, batch, sizeof batch) == 0 ? "true" : "false");

    /* ── High-volume monotonicity stress test ────────────────────────────── */
    printf("\n── Stress test: 100_000 UUIDs, all unique, lexically ordered ────────\n");
    uuidv7_str *big = malloc(DEMO_STRESS * sizeof *big);
    if (big == NULL) {
        fputs("demo: out of memory\n", stderr);
        return EXIT_FAILURE;
    }

    uuidv7_generate_bulk(DEMO_STRESS, big);
    printf("  Unique?  %s\n", demo_all_unique(big, DEMO_STRESS) ? "true" : "false");
    printf("  Sorted?  %s\n", demo_is_ordered(big, DEMO_STRESS) ? "true" : "false");
    free(big);

    /* ── Thread-safety test ──────────────────────────────────────────────── */
    printf("\n── Thread-safety: 4 threads × 5_000 UUIDs ──────────────────────────\n");
    size_t total = (size_t)DEMO_THREADS * DEMO_PER_THREAD;
    uuidv7_str *every = malloc(total * sizeof *every);
    if (every == NULL) {
        fputs("demo: out of memory\n", stderr);
        return EXIT_FAILURE;
    }

    pthread_t threads[DEMO_THREADS];
    struct demo_worker work[DEMO_THREADS];
    for (size_t t = 0; t < DEMO_THREADS; t++) {
        work[t].count = DEMO_PER_THREAD;
        work[t].out = every + t * DEMO_PER_THREAD;
        pthread_create(&threads[t], NULL, demo_worker_run, &work[t]);
    }
    for (size_t t = 0; t < DEMO_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    printf("  Total:   %zu\n", total);
    printf("  Unique?  %s\n", demo_all_unique(every, total) ? "true" : "false");
    free(every);

    /* ── Validation ──────────────────────────────────────────────────────── */
    printf("\n── Validation ───────────────────────────────────────────────────────\n");
    uuidv7_str generated;
    uuidv7_generate(generated);

    struct { const char *uuid; bool expected; } examples[] = {
        { generated,                              true  },
        { "00000000-0000-7000-8000-000000000000", true  },  /* minimal valid v7 */
        { "ffffffff-ffff-7fff-bfff-ffffffffffff", true  },  /* max timestamp, year 10889 */
        { "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", false },  /* v1 */
        { "550e8400-e29b-41d4-a716-446655440000", false },  /* v4 */
        { "not-a-uuid",                           false },
        { "",                                     false },
    };

    for (size_t i = 0; i < sizeof examples / sizeof *examples; i++) {
        bool result = uuidv7_is_valid(examples[i].uuid);
        char shown[48];
        snprintf(shown, sizeof shown, "\"%s\"", examples[i].uuid);
        printf("  %s  uuidv7_is_valid(%-45s) => %s\n",
               result == examples[i].expected ? "✓" : "✗",
               shown, result ? "true" : "false");
    }

    /* ── RFC 9562 Appendix A.6 test vector ───────────────────────────────── */
    printf("\n── RFC 9562 Appendix A.6 test vector ───────────────────────────────\n");
    /* The RFC provides:  017F22E2-79B0-7CC3-98C4-DC0C0C07398F
     * unix_ts_ms = 0x017F22E279B0 = 1645557742000  (2022-02-22T19:22:22.000Z, i.e. 2:22:22 PM GMT-05:00) */
    uuidv7_decoded tv;
    if (uuidv7_decode("017f22e2-79b0-7cc3-98c4-dc0c0c07398f", &tv) != UUIDV7_OK) {
        fputs("demo: the A.6 vector must decode\n", stderr);
        return EXIT_FAILURE;
    }

    demo_format_time(&tv, when, sizeof when);
    printf("  UUID:        %s\n", tv.uuid);
    printf("  unix_ts_ms:  %" PRIu64 "  (expected: 1645557742000)\n", tv.unix_ts_ms);
    printf("  timestamp:   %s\n", when);
    printf("  version:     %u  (expected: 7)\n", tv.version);
    printf("  variant:     %s  (expected: 0b10)\n", tv.variant);
    printf("  rand_a:      0x%" PRIX16 "\n", tv.rand_a);
    printf("  rand_b:      0x%" PRIX64 "\n", tv.rand_b);

    printf("\n%s\n", bar);
    return EXIT_SUCCESS;
}

#endif /* UUIDV7_NO_MAIN */
