# frozen_string_literal: true

# Ruby driver for the cross-implementation benchmark.
#
#   ruby bench/bench.rb <op> <n>
#
# Prints "<op> <ns per op> <checksum>". Timing is inside the process, so startup
# is excluded, and the corpus for the read operations is built before the clock
# starts. The checksum only keeps operations from being optimized away.
# bench/run.sh drives this; the rules are in bench/README.md.

require_relative '../uuid_v7'

op = ARGV[0]
n  = Integer(ARGV[1])
warmup = [n / 10, 1].max

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

corpus = Array.new(1024) { UUIDv7.generate }
sum = 0

case op
when 'generate'
  warmup.times { UUIDv7.generate }
  t0 = now
  n.times { sum += UUIDv7.generate.length }
  t1 = now
when 'generate_random'
  warmup.times { UUIDv7.generate_random }
  t0 = now
  n.times { sum += UUIDv7.generate_random.length }
  t1 = now
when 'decode'
  warmup.times { |i| UUIDv7.decode(corpus[i & 1023]) }
  t0 = now
  n.times { |i| sum += UUIDv7.decode(corpus[i & 1023])[:rand_a] }
  t1 = now
when 'predicate'
  warmup.times { |i| UUIDv7.valid?(corpus[i & 1023]) }
  t0 = now
  n.times { |i| sum += 1 if UUIDv7.valid?(corpus[i & 1023]) }
  t1 = now
else
  abort "unknown op: #{op}"
end

printf("%s %.1f %d\n", op, (t1 - t0) * 1e9 / n, sum)
