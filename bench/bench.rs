// Rust driver for the cross-implementation benchmark.
//
//   rustc --edition 2021 -O bench/bench.rs -o bench/bench_rs && bench/bench_rs <op> <n>
//
// Prints "<op> <ns per op> <checksum>". Timing is inside the process, and the
// corpus for the read operations is built before the clock starts. `black_box`
// keeps the optimizer from removing calls whose results go unused, which at -O it
// would. bench/run.sh drives this; the rules are in bench/README.md.

#[path = "../uuid_v7.rs"]
mod uuid_v7;

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let op = args[1].as_str();
    let n: usize = args[2].parse().expect("n must be a positive integer");
    let warmup = (n / 10).max(1);

    let corpus: Vec<String> = (0..1024).map(|_| uuid_v7::generate()).collect();
    let mut total: u64 = 0;
    let (t0, t1);

    match op {
        "generate" => {
            for _ in 0..warmup {
                black_box(uuid_v7::generate());
            }
            t0 = Instant::now();
            for _ in 0..n {
                total += black_box(uuid_v7::generate()).len() as u64;
            }
            t1 = Instant::now();
        }
        "generate_random" => {
            for _ in 0..warmup {
                black_box(uuid_v7::generate_random());
            }
            t0 = Instant::now();
            for _ in 0..n {
                total += black_box(uuid_v7::generate_random()).len() as u64;
            }
            t1 = Instant::now();
        }
        "decode" => {
            for i in 0..warmup {
                black_box(uuid_v7::decode(&corpus[i & 1023]).expect("corpus decodes"));
            }
            t0 = Instant::now();
            for i in 0..n {
                let d = black_box(uuid_v7::decode(&corpus[i & 1023]).expect("corpus decodes"));
                total += d.rand_a as u64;
            }
            t1 = Instant::now();
        }
        "predicate" => {
            for i in 0..warmup {
                black_box(uuid_v7::is_valid(&corpus[i & 1023]));
            }
            t0 = Instant::now();
            for i in 0..n {
                total += black_box(uuid_v7::is_valid(&corpus[i & 1023])) as u64;
            }
            t1 = Instant::now();
        }
        other => {
            eprintln!("unknown op: {other}");
            std::process::exit(1);
        }
    }

    let ns = t1.duration_since(t0).as_nanos() as f64 / n as f64;
    println!("{op} {ns:.1} {total}");
}
