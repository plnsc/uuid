#!/usr/bin/env lua
-- =============================================================================
-- UUIDv7: Lua implementation of RFC 9562, Section 5.7
-- https://www.rfc-editor.org/rfc/rfc9562#section-5.7
-- https://datatracker.ietf.org/doc/html/rfc9562
-- https://en.wikipedia.org/wiki/Universally_unique_identifier
--
-- Port of uuid_v7.rb / uuid_v7.py, with the same field layout and
-- monotonicity contract. Requires Lua 5.3+ (64-bit integers and bitwise operators).
--
-- Three language limits force a divergence from the Ruby and Python ports:
--   * No 128-bit integers, so the UUID is assembled per hex group (`assemble`).
--   * No millisecond wall clock in the stdlib, so `current_ms` probes for
--     luaposix / luasocket, else interpolates.
--   * No preemptive threads, so no mutex (`Generator`).
--
-- 128-bit field layout (big-endian, MSB first):
--
--  0                   1                   2                   3
--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                           unix_ts_ms                          |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |          unix_ts_ms           |  ver  |        rand_a         |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |var|                         rand_b                            |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- |                           rand_b                              |
-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Field       Bits    Position        Description
-- ─────────────────────────────────────────────────────────────────
-- unix_ts_ms  48      [127..80]  Unix epoch timestamp (milliseconds)
-- ver          4      [79..76]   Version = 0b0111 (7)
-- rand_a      12      [75..64]   Random data / monotonic counter
-- var          2      [63..62]   Variant = 0b10 (RFC 4122 / 9562)
-- rand_b      62      [61..0]    Cryptographically random data
-- =============================================================================

local modname = ...

local M = {}

-- ── Constants ────────────────────────────────────────────────────────────────

M.VERSION = 0x7            -- 4-bit version field value
M.VARIANT = 0x2            -- 2-bit variant field value (0b10, MSBs of octet 8)

M.RAND_A_BITS = 12
M.RAND_B_BITS = 62
M.MAX_RAND_A = (1 << M.RAND_A_BITS) - 1   -- 0xFFF
M.MAX_RAND_B = (1 << M.RAND_B_BITS) - 1   -- 0x3FFF_FFFF_FFFF_FFFF

local VERSION, VARIANT = M.VERSION, M.VARIANT
local RAND_A_BITS      = M.RAND_A_BITS
local MAX_RAND_A       = M.MAX_RAND_A
local MAX_RAND_B       = M.MAX_RAND_B

local MASK_48 = 0xFFFFFFFFFFFF   -- unix_ts_ms, and the low half of rand_b
local MASK_14 = 0x3FFF           -- the part of rand_b sharing a group with var

-- RFC 9562 §4: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
-- Lua patterns lack alternation and {n} repetition, so the shape is spelled
-- out. %x matches both cases, making this case-insensitive.
M.UUID_PATTERN =
  "^(%x%x%x%x%x%x%x%x)%-(%x%x%x%x)%-(%x%x%x%x)%-(%x%x%x%x)%-(%x%x%x%x%x%x%x%x%x%x%x%x)$"

local UUID_PATTERN = M.UUID_PATTERN

-- ── Entropy source ───────────────────────────────────────────────────────────

-- Prefer /dev/urandom, a CSPRNG matching Ruby's SecureRandom and Python's
-- secrets. math.random is NOT cryptographically secure and is used only when
-- /dev/urandom cannot be opened; M.entropy_source reports which is live.
local urandom = io.open("/dev/urandom", "rb")

M.entropy_source = urandom and "/dev/urandom" or "math.random (NOT a CSPRNG)"

-- Returns `nbits` random bits as a non-negative integer. Every caller asks
-- for a power-of-two range, so masking suffices, with no modulo bias to correct.
local function rand_bits(nbits)
  local mask = (1 << nbits) - 1

  if urandom then
    local bytes = urandom:read(8)
    if bytes and #bytes == 8 then
      return string.unpack("<I8", bytes) & mask
    end
    -- Read failed mid-run: give up and fall through to math.random.
    urandom:close()
    urandom = nil
    M.entropy_source = "math.random (NOT a CSPRNG)"
  end

  return math.random(0, mask)
end

-- ── Clock ────────────────────────────────────────────────────────────────────

-- os.time has one-second resolution, too coarse for UUIDv7. Use a real
-- millisecond clock when one is installed; otherwise interpolate within the
-- current second via os.clock, re-anchoring on every os.time tick so drift
-- stays under one second.
--
-- Ordering never depends on this, since the generator never emits a timestamp below
-- the last one used. Only *accuracy* degrades; M.clock_source reports which
-- path is live.
local current_ms

do
  local ok_posix, ptime = pcall(require, "posix.sys.time")
  local ok_socket, socket = pcall(require, "socket")

  if ok_posix and ptime and ptime.gettimeofday then
    M.clock_source = "posix.sys.time.gettimeofday"
    current_ms = function()
      local tv = ptime.gettimeofday()
      return tv.tv_sec * 1000 + tv.tv_usec // 1000
    end
  elseif ok_socket and socket and socket.gettime then
    M.clock_source = "socket.gettime"
    current_ms = function()
      return math.floor(socket.gettime() * 1000)
    end
  else
    M.clock_source = "os.time + os.clock interpolation (ms is approximate)"

    local anchor_s     = os.time()
    local anchor_clock = os.clock()

    current_ms = function()
      local s = os.time()

      if s > anchor_s then
        anchor_s     = s
        anchor_clock = os.clock()
        return s * 1000
      end

      -- os.clock measures CPU time, so it may outrun or lag wall time;
      -- clamping keeps the result inside the second os.time reported.
      local delta = math.floor((os.clock() - anchor_clock) * 1000)
      if delta < 0 then delta = 0 elseif delta > 999 then delta = 999 end
      return anchor_s * 1000 + delta
    end
  end
end

M.current_ms = current_ms

-- ── Assembly ─────────────────────────────────────────────────────────────────

-- Packs all fields and formats the UUID string.
--
-- Ruby and Python build one 128-bit integer; Lua integers are 64-bit, so the
-- value is emitted group by group. Groups align with field boundaries except
-- rand_b, whose top 14 bits share group 4 with the variant:
--
--   group 1 (8 hex)  unix_ts_ms[47..16]
--   group 2 (4 hex)  unix_ts_ms[15..0]
--   group 3 (4 hex)  ver (1 hex) + rand_a (3 hex)
--   group 4 (4 hex)  var (2 bits) + rand_b[61..48] (14 bits)
--   group 5 (12 hex) rand_b[47..0]
--
-- @param unix_ts_ms integer 48-bit millisecond timestamp
-- @param rand_a     integer 12-bit value (counter or random)
-- @param rand_b     integer 62-bit random value
-- @return string formatted UUID
local function assemble(unix_ts_ms, rand_a, rand_b)
  local ts = string.format("%012x", unix_ts_ms & MASK_48)

  local group4 = (VARIANT << 14) | ((rand_b >> 48) & MASK_14)
  local group5 = rand_b & MASK_48

  return string.format("%s-%s-%x%03x-%04x-%012x",
    ts:sub(1, 8), ts:sub(9, 12),
    VERSION, rand_a & MAX_RAND_A,
    group4, group5)
end

-- ── Generator ────────────────────────────────────────────────────────────────

-- UUIDv7 generator.
--
-- Method 2 (monotonic counter) of RFC 9562 §6.2: rand_a is a counter re-seeded
-- on each new millisecond, giving strict lexicographic ordering even within a
-- single millisecond; rand_b is always fresh random data. On counter overflow
-- (> 0xFFF) the timestamp is bumped 1 ms, the "counter rollover" that same
-- section permits.
--
-- No mutex, unlike the Ruby and Python ports: standard Lua has no preemptive
-- threads, and next_state never yields, so no coroutine can interleave it. A
-- preemptive host (OS threads sharing one lua_State) would need external
-- locking.
--
--   local gen = uuid_v7.Generator.new()
--   gen:generate()  -- => "018f2e39-59b7-7e82-9c3a-4d5b9e2f1a60"
local Generator = {}
Generator.__index = Generator

function Generator.new()
  return setmetatable({
    last_ms = 0,   -- last timestamp used
    seq     = 0,   -- rand_a counter within a millisecond
  }, Generator)
end

-- Advances internal state and returns ms, seq, rand_b.
function Generator:next_state()
  local ms = current_ms()

  if ms > self.last_ms then
    -- ── New millisecond: re-seed the counter ─────────────────────────────
    -- An 11-bit seed keeps the MSB free, leaving room for 2048 increments.
    self.seq     = rand_bits(RAND_A_BITS - 1)
    self.last_ms = ms
  else
    -- ── Same (or rare clock regression) millisecond: increment ───────────
    self.seq = self.seq + 1

    if self.seq > MAX_RAND_A then
      -- Counter exhausted, so bump the virtual clock by 1 ms (RFC 9562 §6.2)
      self.last_ms = self.last_ms + 1
      self.seq     = rand_bits(RAND_A_BITS - 1)
    end

    ms = self.last_ms
  end

  return ms, self.seq, rand_bits(M.RAND_B_BITS)
end

-- Generate a UUIDv7, monotonic within 1 ms.
--
-- @return string lowercase UUID string
function Generator:generate()
  return assemble(self:next_state())
end

-- Generate a UUIDv7 by Method 1, with fully random rand_a and rand_b. Simpler,
-- but NOT monotonic within a millisecond.
--
-- @return string
function Generator:generate_random()
  return assemble(current_ms(), rand_bits(RAND_A_BITS), rand_bits(M.RAND_B_BITS))
end

-- Generate `n` monotonically ordered UUIDv7s.
--
-- @param n integer number of UUIDs to generate (must be positive)
-- @return table array of strings
-- @raise if `n` is not a positive integer
function Generator:generate_bulk(n)
  if math.type(n) ~= "integer" or n <= 0 then
    error("n must be a positive integer", 2)
  end

  local out = table.create and table.create(n) or {}
  for i = 1, n do
    out[i] = self:generate()
  end
  return out
end

M.Generator = Generator

-- ── Decoder ──────────────────────────────────────────────────────────────────

-- Decodes a UUIDv7 string into its constituent fields.
--
-- @param uuid string UUID string, any letter case
-- @return table with keys:
--   uuid        string  canonical lowercase UUID string
--   version     integer must be 7
--   variant     string  e.g. "0b10"
--   unix_ts_ms  integer Unix timestamp in milliseconds
--   timestamp   string  UTC timestamp reconstructed from unix_ts_ms
--   rand_a      integer 12-bit rand_a field value
--   rand_b      integer 62-bit rand_b field value
-- @raise if the format, version, or variant is invalid
function M.decode(uuid)
  if type(uuid) ~= "string" then
    error(string.format("Invalid UUID format: %s", tostring(uuid)), 2)
  end

  local g1, g2, g3, g4, g5 = uuid:match(UUID_PATTERN)
  if not g1 then
    error(string.format("Invalid UUID format: %q", uuid), 2)
  end

  local version = tonumber(g3:sub(1, 1), 16)
  local group4  = tonumber(g4, 16)
  local variant = group4 >> 14

  if version ~= VERSION then
    error(string.format("Not a UUIDv7 (version field = %d, expected 7)", version), 2)
  end

  if variant ~= VARIANT then
    error(string.format("Invalid variant bits (got 0b%s, expected 0b10)",
      (variant & 2 == 2 and "1" or "0") .. (variant & 1)), 2)
  end

  local unix_ts_ms = tonumber(g1 .. g2, 16)
  local rand_a     = tonumber(g3:sub(2, 4), 16)
  local rand_b     = ((group4 & MASK_14) << 48) | tonumber(g5, 16)

  return {
    uuid       = uuid:lower(),
    version    = version,
    variant    = string.format("0b%s%s", variant >> 1, variant & 1),
    unix_ts_ms = unix_ts_ms,
    timestamp  = string.format("%s.%03d UTC",
                   os.date("!%Y-%m-%d %H:%M:%S", unix_ts_ms // 1000),
                   unix_ts_ms % 1000),
    rand_a     = rand_a,
    rand_b     = rand_b,
  }
end

-- True if `uuid` is a well-formed UUIDv7.
--
-- @param uuid string
-- @return boolean
function M.is_valid(uuid)
  return (pcall(M.decode, uuid))
end

-- ── Module-level convenience API ─────────────────────────────────────────────

-- Shared default generator, created at load time.
local default_generator = Generator.new()

M.default_generator = default_generator

-- Monotonic UUIDv7 from the shared default generator.
--
-- @return string
function M.generate()
  return default_generator:generate()
end

-- UUIDv7 with fully random rand_a and rand_b (Method 1).
--
-- @return string
function M.generate_random()
  return default_generator:generate_random()
end

-- `n` monotonically ordered UUIDv7s from the default generator.
--
-- @param n integer
-- @return table array of strings
function M.generate_bulk(n)
  return default_generator:generate_bulk(n)
end

-- =============================================================================
-- Self-contained test / demo (run with: lua uuid_v7.lua)
-- =============================================================================
if modname == nil then
  local function rule(title)
    local line = title .. " " .. string.rep("─", math.max(0, 66 - #title))
    print("\n── " .. line)
  end

  print(string.rep("=", 68))
  print("  UUIDv7: RFC 9562 Lua Implementation")
  print(string.rep("=", 68))
  print("  entropy: " .. M.entropy_source)
  print("  clock:   " .. M.clock_source)

  -- ── Basic generation ─────────────────────────────────────────────────────
  rule("Single UUID (monotonic)")
  local uuid = M.generate()
  print("  " .. uuid)

  rule("Single UUID (random Method 1)")
  print("  " .. M.generate_random())

  -- ── Decode ───────────────────────────────────────────────────────────────
  rule("Decode")
  local info = M.decode(uuid)
  for _, k in ipairs({ "uuid", "version", "variant", "unix_ts_ms",
                       "timestamp", "rand_a", "rand_b" }) do
    print(string.format("  %-12s  %s", k, info[k]))
  end

  -- ── Bulk & monotonicity ──────────────────────────────────────────────────
  rule("Bulk generation (10): monotonicity check")
  local batch = M.generate_bulk(10)
  for _, u in ipairs(batch) do print("  " .. u) end

  local sorted = table.move(batch, 1, #batch, 1, {})
  table.sort(sorted)
  local same = true
  for i = 1, #batch do
    if sorted[i] ~= batch[i] then same = false break end
  end
  print("\n  Sorted == generated order? " .. tostring(same))

  -- ── High-volume monotonicity stress test ─────────────────────────────────
  rule("Stress test: 100_000 UUIDs, all unique, lexically ordered")
  local big = M.generate_bulk(100000)

  local seen, unique = {}, true
  for _, u in ipairs(big) do
    if seen[u] then unique = false break end
    seen[u] = true
  end

  local ordered = true
  for i = 2, #big do
    if big[i - 1] > big[i] then ordered = false break end
  end

  print("  Unique?  " .. tostring(unique))
  print("  Sorted?  " .. tostring(ordered))

  -- ── Coroutine interleaving test ──────────────────────────────────────────
  -- Standard Lua has no preemptive threads, so this stands in for the ports'
  -- thread-safety test: four coroutines resumed round-robin, interleaving
  -- their calls into the shared generator.
  rule("Coroutine interleaving: 4 coroutines × 5_000 UUIDs")
  local buckets = {}
  local workers = {}
  for i = 1, 4 do
    buckets[i] = {}
    workers[i] = coroutine.create(function()
      for _ = 1, 5000 do
        buckets[i][#buckets[i] + 1] = M.generate()
        coroutine.yield()
      end
    end)
  end

  local running = true
  while running do
    running = false
    for _, co in ipairs(workers) do
      if coroutine.status(co) ~= "dead" then
        assert(coroutine.resume(co))
        running = true
      end
    end
  end

  local every, all_unique = {}, true
  local seen2 = {}
  for _, bucket in ipairs(buckets) do
    for _, u in ipairs(bucket) do
      every[#every + 1] = u
      if seen2[u] then all_unique = false end
      seen2[u] = true
    end
  end
  print("  Total:   " .. #every)
  print("  Unique?  " .. tostring(all_unique))

  -- ── Validation ───────────────────────────────────────────────────────────
  rule("Validation")
  local examples = {
    { M.generate(),                          true  },
    { "00000000-0000-7000-8000-000000000000", true  },  -- minimal valid v7
    { "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", false },  -- v1
    { "550e8400-e29b-41d4-a716-446655440000", false },  -- v4
    { "not-a-uuid",                           false },
    { "",                                     false },
  }
  for _, case in ipairs(examples) do
    local u, expected = case[1], case[2]
    local result = M.is_valid(u)
    local status = result == expected and "✓" or "✗"
    print(string.format("  %s  is_valid(%-45s) => %s",
      status, string.format("%q", u):sub(1, 45), tostring(result)))
  end

  -- ── RFC 9562 Appendix A.6 test vector ────────────────────────────────────
  rule("RFC 9562 Appendix A.6 test vector")
  -- The RFC provides:  017F22E2-79B0-7CC3-98C4-DC0C0C07398F
  -- unix_ts_ms = 0x017F22E279B0 = 1645557742000  (2022-02-22T19:22:22.000Z, i.e. 2:22:22 PM GMT-05:00)
  local tv = M.decode("017f22e2-79b0-7cc3-98c4-dc0c0c07398f")
  print("  UUID:        " .. tv.uuid)
  print("  unix_ts_ms:  " .. tv.unix_ts_ms .. "  (expected: 1645557742000)")
  print("  timestamp:   " .. tv.timestamp)
  print("  version:     " .. tv.version .. "  (expected: 7)")
  print("  variant:     " .. tv.variant .. "  (expected: 0b10)")
  print(string.format("  rand_a:      0x%X", tv.rand_a))
  print(string.format("  rand_b:      0x%X", tv.rand_b))

  print("\n" .. string.rep("=", 68))
end

return M
