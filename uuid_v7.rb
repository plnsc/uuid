# frozen_string_literal: true

# =============================================================================
# UUIDv7 — Ruby implementation of RFC 9562, Section 5.7
# https://www.rfc-editor.org/rfc/rfc9562#section-5.7
# https://datatracker.ietf.org/doc/html/rfc9562
# https://en.wikipedia.org/wiki/Universally_unique_identifier
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

require 'securerandom'

module UUIDv7
  # ── Constants ───────────────────────────────────────────────────────────────

  VERSION     = 0x7            # 4-bit version field value
  VARIANT     = 0b10           # 2-bit variant field value (MSBs of octet 8)

  RAND_A_BITS = 12
  RAND_B_BITS = 62
  MAX_RAND_A  = (1 << RAND_A_BITS) - 1   # 0xFFF
  MAX_RAND_B  = (1 << RAND_B_BITS) - 1   # 0x3FFF_FFFF_FFFF_FFFF

  # RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  UUID_REGEX = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i.freeze

  # ── Generator ───────────────────────────────────────────────────────────────

  # Thread-safe UUIDv7 generator.
  #
  # Method 2 (monotonic counter) of RFC 9562 §6.2: rand_a is a counter re-seeded
  # on each new millisecond, giving strict lexicographic ordering even within a
  # single millisecond; rand_b is always fresh random data. On counter overflow
  # (> 0xFFF) the timestamp is bumped 1 ms — the "counter rollover" that same
  # section permits.
  #
  #   gen = UUIDv7::Generator.new
  #   gen.generate  # => "018f2e39-59b7-7e82-9c3a-4d5b9e2f1a60"
  class Generator
    def initialize
      @mutex   = Mutex.new
      @last_ms = 0     # last timestamp used
      @seq     = 0     # rand_a counter within a millisecond
    end

    # Generate a UUIDv7, monotonic within 1 ms.
    #
    # @return [String] lowercase UUID string
    def generate
      ms, seq, rand_b = @mutex.synchronize { next_state }
      assemble(ms, seq, rand_b)
    end

    # Generate a UUIDv7 by Method 1 — fully random rand_a and rand_b. Simpler,
    # but NOT monotonic within a millisecond.
    #
    # @return [String]
    def generate_random
      ms     = current_ms
      rand_a = SecureRandom.random_number(MAX_RAND_A + 1)
      rand_b = SecureRandom.random_number(MAX_RAND_B + 1)
      assemble(ms, rand_a, rand_b)
    end

    # Generate +n+ monotonically ordered UUIDv7s.
    #
    # @param n [Integer] number of UUIDs to generate (must be positive)
    # @return [Array<String>]
    def generate_bulk(n)
      raise ArgumentError, "n must be a positive integer" unless n.is_a?(Integer) && n > 0

      Array.new(n) { generate }
    end

    private

    # Current Unix timestamp in whole milliseconds.
    def current_ms
      Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)
    end

    # Advances internal state and returns [ms, seq, rand_b].
    # MUST be called inside @mutex.synchronize.
    def next_state
      ms = current_ms

      if ms > @last_ms
        # ── New millisecond: re-seed the counter ────────────────────────────
        # An 11-bit seed keeps the MSB free, leaving room for 2048 increments.
        @seq     = SecureRandom.random_number(1 << (RAND_A_BITS - 1))
        @last_ms = ms
      else
        # ── Same (or rare clock regression) millisecond: increment ──────────
        @seq += 1

        if @seq > MAX_RAND_A
          # Counter exhausted — bump the virtual clock by 1 ms (RFC 9562 §6.2)
          @last_ms += 1
          @seq      = SecureRandom.random_number(1 << (RAND_A_BITS - 1))
        end

        ms = @last_ms
      end

      rand_b = SecureRandom.random_number(MAX_RAND_B + 1)
      [ms, @seq, rand_b]
    end

    # Packs all fields into a 128-bit integer and formats the UUID string.
    #
    # Positions below count 127 as the MSB — the opposite of the RFC-style
    # ruler in the file header, which numbers bits from 0 left to right:
    #
    #   [127..80]  unix_ts_ms   (48 bits)
    #   [79..76]   ver          ( 4 bits)  → 0b0111
    #   [75..64]   rand_a       (12 bits)
    #   [63..62]   var          ( 2 bits)  → 0b10
    #   [61..0]    rand_b       (62 bits)
    #
    # @param unix_ts_ms [Integer] 48-bit millisecond timestamp
    # @param rand_a     [Integer] 12-bit value (counter or random)
    # @param rand_b     [Integer] 62-bit random value
    # @return [String] formatted UUID
    def assemble(unix_ts_ms, rand_a, rand_b)
      n = (unix_ts_ms            << 80) |
          (VERSION                << 76) |
          ((rand_a & MAX_RAND_A)  << 64) |
          (VARIANT                << 62) |
          (rand_b  & MAX_RAND_B)

      hex = format('%032x', n)
      "#{hex[0, 8]}-#{hex[8, 4]}-#{hex[12, 4]}-#{hex[16, 4]}-#{hex[20, 12]}"
    end
  end

  # ── Decoder ─────────────────────────────────────────────────────────────────

  # Decodes a UUIDv7 string into its constituent fields.
  #
  # @param uuid [String] UUID string, any letter case
  # @return [Hash] with keys:
  #   :uuid        [String]  canonical lowercase UUID string
  #   :version     [Integer] must be 7
  #   :variant     [String]  e.g. "0b10"
  #   :unix_ts_ms  [Integer] Unix timestamp in milliseconds
  #   :timestamp   [Time]    UTC Time object reconstructed from unix_ts_ms
  #   :rand_a      [Integer] 12-bit rand_a field value
  #   :rand_b      [Integer] 62-bit rand_b field value
  # @raise [ArgumentError] if the format, version, or variant is invalid
  def self.decode(uuid)
    raise ArgumentError, "Invalid UUID format: #{uuid.inspect}" \
      unless uuid.match?(UUID_REGEX)

    n = uuid.delete('-').to_i(16)

    version = (n >> 76) & 0xF
    variant = (n >> 62) & 0x3

    raise ArgumentError, "Not a UUIDv7 (version field = #{version}, expected 7)" \
      unless version == VERSION

    raise ArgumentError, "Invalid variant bits (got 0b#{variant.to_s(2).rjust(2, '0')}, expected 0b10)" \
      unless variant == VARIANT

    unix_ts_ms = (n >> 80) & 0xFFFF_FFFF_FFFF
    rand_a     = (n >> 64) & MAX_RAND_A
    rand_b     = n & MAX_RAND_B

    {
      uuid:       uuid.downcase,
      version:    version,
      variant:    format('0b%02b', variant),
      unix_ts_ms: unix_ts_ms,
      timestamp:  Time.at(Rational(unix_ts_ms, 1000)).utc,
      rand_a:     rand_a,
      rand_b:     rand_b
    }
  end

  # True if +uuid+ is a well-formed UUIDv7.
  #
  # @param uuid [String]
  # @return [Boolean]
  def self.valid?(uuid)
    decode(uuid)
    true
  rescue ArgumentError
    false
  end

  # ── Module-level convenience API ────────────────────────────────────────────

  # Shared, thread-safe default generator (created eagerly at load time).
  @default_generator = Generator.new

  class << self
    # Monotonic UUIDv7 from the shared default generator. Thread-safe.
    #
    # @return [String]
    def generate
      @default_generator.generate
    end

    # UUIDv7 with fully random rand_a and rand_b (Method 1).
    #
    # @return [String]
    def generate_random
      @default_generator.generate_random
    end

    # +n+ monotonically ordered UUIDv7s from the default generator.
    #
    # @param n [Integer]
    # @return [Array<String>]
    def generate_bulk(n)
      @default_generator.generate_bulk(n)
    end
  end
end

# =============================================================================
# Self-contained test / demo (run with: ruby uuid_v7.rb)
# =============================================================================
if __FILE__ == $PROGRAM_NAME
  require 'set'

  puts "=" * 68
  puts "  UUIDv7 — RFC 9562 Ruby Implementation"
  puts "=" * 68

  # ── Basic generation ─────────────────────────────────────────────────────
  puts "\n── Single UUID (monotonic) ──────────────────────────────────────────"
  uuid = UUIDv7.generate
  puts "  #{uuid}"

  puts "\n── Single UUID (random Method 1) ───────────────────────────────────"
  puts "  #{UUIDv7.generate_random}"

  # ── Decode ───────────────────────────────────────────────────────────────
  puts "\n── Decode ───────────────────────────────────────────────────────────"
  info = UUIDv7.decode(uuid)
  info.each { |k, v| puts "  %-12s  %s" % [k, v] }

  # ── Bulk & monotonicity ───────────────────────────────────────────────────
  puts "\n── Bulk generation (10) — monotonicity check ────────────────────────"
  batch = UUIDv7.generate_bulk(10)
  batch.each { |u| puts "  #{u}" }
  sorted = batch.sort
  puts "\n  Sorted == generated order? #{sorted == batch}"

  # ── High-volume monotonicity stress test ─────────────────────────────────
  puts "\n── Stress test: 100_000 UUIDs, all unique, lexically ordered ────────"
  big = UUIDv7.generate_bulk(100_000)
  puts "  Unique?  #{big.uniq.size == big.size}"
  puts "  Sorted?  #{big.each_cons(2).all? { |a, b| a <= b }}"

  # ── Thread-safety test ───────────────────────────────────────────────────
  puts "\n── Thread-safety: 4 threads × 5_000 UUIDs ──────────────────────────"
  results = Array.new(4) { [] }
  threads = results.map do |bucket|
    Thread.new { 5_000.times { bucket << UUIDv7.generate } }
  end
  threads.each(&:join)
  all = results.flatten
  puts "  Total:   #{all.size}"
  puts "  Unique?  #{all.uniq.size == all.size}"

  # ── Validation ───────────────────────────────────────────────────────────
  puts "\n── Validation ───────────────────────────────────────────────────────"
  examples = {
    UUIDv7.generate                             => true,
    "00000000-0000-7000-8000-000000000000"      => true,   # minimal valid v7
    "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"      => false,  # v1
    "550e8400-e29b-41d4-a716-446655440000"      => false,  # v4
    "not-a-uuid"                                => false,
    ""                                          => false,
  }
  examples.each do |u, expected|
    result = UUIDv7.valid?(u)
    status = result == expected ? "✓" : "✗"
    puts "  #{status}  valid?(#{u.inspect[0, 45].ljust(45)}) => #{result}"
  end

  # ── RFC 9562 Appendix A.6 test vector ─────────────────────────────────────
  puts "\n── RFC 9562 Appendix A.6 test vector ───────────────────────────────"
  # The RFC provides:  017F22E2-79B0-7CC3-98C4-DC0C0C07398F
  # unix_ts_ms = 0x017F22E279B0 = 1645557742000  (2022-02-22T19:22:22.000Z, i.e. 2:22:22 PM GMT-05:00)
  test_vec = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
  tv = UUIDv7.decode(test_vec)
  puts "  UUID:        #{tv[:uuid]}"
  puts "  unix_ts_ms:  #{tv[:unix_ts_ms]}  (expected: 1645557742000)"
  puts "  timestamp:   #{tv[:timestamp]}"
  puts "  version:     #{tv[:version]}  (expected: 7)"
  puts "  variant:     #{tv[:variant]}  (expected: 0b10)"
  puts "  rand_a:      0x#{tv[:rand_a].to_s(16).upcase}"
  puts "  rand_b:      0x#{tv[:rand_b].to_s(16).upcase}"

  puts "\n" + "=" * 68
end
