/* C driver for the cross-implementation benchmark.
 *
 *   cc -std=c11 -O2 -pthread bench/bench.c -o bench/bench_c && bench/bench_c <op> <n>
 *
 * Prints "<op> <ns per op> <checksum>". Timing is inside the process, and the
 * corpus for the read operations is built before the clock starts. The checksum
 * is written through a volatile, so -O2 cannot drop the loops whose results would
 * go unused. bench/run.sh drives this; the rules are in bench/README.md.
 */

#define UUIDV7_NO_MAIN
#include "../uuid_v7.c"

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fputs("usage: bench_c <op> <n>\n", stderr);
        return EXIT_FAILURE;
    }

    const char *op = argv[1];
    size_t n = strtoull(argv[2], NULL, 10);
    size_t warmup = n / 10 > 0 ? n / 10 : 1;

    static uuidv7_str corpus[1024];
    for (size_t i = 0; i < 1024; i++) {
        uuidv7_generate(corpus[i]);
    }

    volatile uint64_t sink = 0;
    uint64_t total = 0;
    double t0 = 0, t1 = 0;
    uuidv7_str scratch;
    uuidv7_decoded decoded;

    if (strcmp(op, "generate") == 0) {
        for (size_t i = 0; i < warmup; i++) uuidv7_generate(scratch);
        t0 = now_ns();
        for (size_t i = 0; i < n; i++) {
            uuidv7_generate(scratch);
            total += strlen(scratch);
        }
        t1 = now_ns();
    } else if (strcmp(op, "generate_random") == 0) {
        for (size_t i = 0; i < warmup; i++) uuidv7_generate_random(scratch);
        t0 = now_ns();
        for (size_t i = 0; i < n; i++) {
            uuidv7_generate_random(scratch);
            total += strlen(scratch);
        }
        t1 = now_ns();
    } else if (strcmp(op, "decode") == 0) {
        for (size_t i = 0; i < warmup; i++) uuidv7_decode(corpus[i & 1023], &decoded);
        t0 = now_ns();
        for (size_t i = 0; i < n; i++) {
            uuidv7_decode(corpus[i & 1023], &decoded);
            total += decoded.rand_a;
        }
        t1 = now_ns();
    } else if (strcmp(op, "predicate") == 0) {
        for (size_t i = 0; i < warmup; i++) uuidv7_is_valid(corpus[i & 1023]);
        t0 = now_ns();
        for (size_t i = 0; i < n; i++) {
            total += uuidv7_is_valid(corpus[i & 1023]) ? 1u : 0u;
        }
        t1 = now_ns();
    } else {
        fprintf(stderr, "unknown op: %s\n", op);
        return EXIT_FAILURE;
    }

    sink = total;
    printf("%s %.1f %" PRIu64 "\n", op, (t1 - t0) / (double)n, sink);
    return EXIT_SUCCESS;
}
