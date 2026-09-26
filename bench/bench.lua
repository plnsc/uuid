#!/usr/bin/env lua
-- Lua driver for the cross-implementation benchmark.
--
--   lua bench/bench.lua <op> <n>
--
-- Prints "<op> <ns per op> <checksum>". Timing happens inside the process, so
-- startup is excluded, and the corpus for the read operations is built before the
-- clock starts. The checksum exists only so no operation can be optimized away.
--
-- The clock is os.clock, which is CPU time: standard Lua has no monotonic wall
-- clock, the same gap uuid_v7.lua works around for timestamps. For this workload
-- the two track each other, since nothing here blocks, but it is the one column
-- of the table not measured on a wall clock. bench/run.sh drives this; see
-- bench/README.md for the rules.

local here = arg[0]:match("(.*/)") or "./"
package.path = here .. "../?.lua;" .. package.path

local u = require("uuid_v7")

local op = arg[1]
local n = math.tointeger(tonumber(arg[2]))
local warmup = math.max(n // 10, 1)
local clock = os.clock

local corpus = {}
for i = 1, 1024 do corpus[i] = u.generate() end

local total, t0, t1 = 0, nil, nil

if op == "generate" then
  for _ = 1, warmup do u.generate() end
  t0 = clock()
  for _ = 1, n do total = total + #u.generate() end
  t1 = clock()
elseif op == "generate_random" then
  for _ = 1, warmup do u.generate_random() end
  t0 = clock()
  for _ = 1, n do total = total + #u.generate_random() end
  t1 = clock()
elseif op == "decode" then
  for i = 1, warmup do u.decode(corpus[(i & 1023) + 1]) end
  t0 = clock()
  for i = 1, n do total = total + u.decode(corpus[(i & 1023) + 1]).rand_a end
  t1 = clock()
elseif op == "predicate" then
  for i = 1, warmup do u.is_valid(corpus[(i & 1023) + 1]) end
  t0 = clock()
  for i = 1, n do
    if u.is_valid(corpus[(i & 1023) + 1]) then total = total + 1 end
  end
  t1 = clock()
else
  io.stderr:write("unknown op: " .. tostring(op) .. "\n")
  os.exit(1)
end

print(string.format("%s %.1f %d", op, (t1 - t0) * 1e9 / n, total))
