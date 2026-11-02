/* c_dispatch/bench_e2e.c
 * ═══════════════════════════════════════════════════════════════════
 * End-to-End TLS 1.3 Hybrid PQC Benchmark
 * Adaptive Dispatch Runtime — Network Handshake Edition
 *
 * Runs real TCP handshakes against the dispatch server, measuring
 * client-side crypto latency across three client dispatch modes:
 *
 *   1. Strict_Sequential  — sequential execution on client (server: sequential)
 *   2. Strict_Parallel    — parallel execution on client (server: sequential)
 *   3. Adaptive_Switch    — auto dispatch on client (router decides per-handshake)
 *
 * Server Execution: Always Sequential
 *
 * Timing: clock_gettime(CLOCK_MONOTONIC) — starts AFTER TCP connect,
 *         ends after receiving ServerFinished.
 *
 * Statistics: qsort → percentile extraction → Markdown table.
 * Output: Mean, p50, p95, p99 tail latencies (ms).
 *
 * Usage: ./bench_e2e [--host <ip>] [--runs <N>] [--kdf <sha256|blake3>]
 * ═══════════════════════════════════════════════════════════════════
 */

#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "include/algo_config.h"
#include "include/dispatcher.h"
#include "include/engine.h"
#include "include/telemetry.h"
#include "include/key_pool.h"

#define SERVER_PORT 4444

/* Defined in client.c */
extern int g_client_use_key_pool;
extern double g_last_ch_prep_ms;
double execute_dispatch_handshake(const char *host,
                                  const AlgoCombo *combo,
                                  const char *kdf_type,
                                  const char *dispatch_mode,
                                  DispatchRoute local_route);
int  client_worker_init(void);
void client_worker_shutdown(void);

/* ═══════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════ */

static const char *g_host        = "127.0.0.1";
static int         g_runs        = 1000;
static const char *g_kdf         = "sha256";
static int         g_precompute  = 0;

/* ═══════════════════════════════════════════════════════════════════
 * Benchmark modes
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum {
    MODE_STRICT_SEQUENTIAL,
    MODE_STRICT_PARALLEL,
    MODE_ADAPTIVE_SWITCH
} BenchMode;

static const char *mode_label(BenchMode m)
{
    switch (m) {
        case MODE_STRICT_SEQUENTIAL: return "Strict_Sequential";
        case MODE_STRICT_PARALLEL:   return "Strict_Parallel";
        case MODE_ADAPTIVE_SWITCH:   return "Adaptive_Switch";
        default:                     return "Unknown";
    }
}

/* dispatch_mode string sent to the server — server always executes sequentially */
static const char *mode_wire(BenchMode m)
{
    (void)m;
    return "sequential";
}

/* local route used by the client */
static DispatchRoute mode_local_route(BenchMode m, const AlgoCombo *combo)
{
    switch (m) {
        case MODE_STRICT_SEQUENTIAL: return ROUTE_SEQUENTIAL;
        case MODE_STRICT_PARALLEL:   return ROUTE_PARALLEL;
        case MODE_ADAPTIVE_SWITCH:   return adaptive_dispatch(combo);
        default:                     return ROUTE_SEQUENTIAL;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Statistics
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    double mean_ms;
    double p50_ms;
    double p95_ms;
    double p99_ms;
} LatencyStats;

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

static void compute_stats(double *samples, int n, LatencyStats *out)
{
    qsort(samples, (size_t)n, sizeof(double), cmp_double);

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += samples[i];

    out->mean_ms = sum / n;
    out->p50_ms  = samples[(int)((n - 1) * 0.50)];
    out->p95_ms  = samples[(int)((n - 1) * 0.95)];
    out->p99_ms  = samples[(int)((n - 1) * 0.99)];
}

/* ═══════════════════════════════════════════════════════════════════
 * Run a single benchmark track
 * ═══════════════════════════════════════════════════════════════════ */

static int run_bench(const AlgoCombo *combo, BenchMode mode,
                     double *samples, int n_iter)
{
    const char *wire_mode   = mode_wire(mode);
    DispatchRoute loc_route = mode_local_route(mode, combo);

    for (int i = 0; i < n_iter; i++) {
        double ms = execute_dispatch_handshake(g_host, combo, g_kdf,
                                               wire_mode, loc_route);
        if (ms < 0.0) {
            fprintf(stderr, "[!] Handshake failed: %s | mode=%s | iter=%d\n",
                    combo->label, mode_label(mode), i);
            return -1;
        }
        samples[i] = ms;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Export results to JSON (fprintf, no cJSON)
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *combo_label;
    const char *mode_label;
    LatencyStats stats;
} BenchResult;

static void export_results(const char *path,
                           const BenchResult *results, int n)
{
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("export_results"); return; }

    fprintf(fp, "[\n");
    for (int i = 0; i < n; i++) {
        fprintf(fp, "  {\n");
        fprintf(fp, "    \"cipher_suite\": \"%s\",\n", results[i].combo_label);
        fprintf(fp, "    \"mode\": \"%s\",\n", results[i].mode_label);
        fprintf(fp, "    \"mean_ms\": %.6f,\n", results[i].stats.mean_ms);
        fprintf(fp, "    \"p50_ms\": %.6f,\n", results[i].stats.p50_ms);
        fprintf(fp, "    \"p95_ms\": %.6f,\n", results[i].stats.p95_ms);
        fprintf(fp, "    \"p99_ms\": %.6f\n", results[i].stats.p99_ms);
        fprintf(fp, "  }%s\n", (i < n - 1) ? "," : "");
    }
    fprintf(fp, "]\n");
    fclose(fp);
    printf("[✔] Results exported → %s\n\n", path);
}

/* ═══════════════════════════════════════════════════════════════════
 * CLI argument parser
 * ═══════════════════════════════════════════════════════════════════ */

static void parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            g_host = argv[++i];
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            g_runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--kdf") == 0 && i + 1 < argc)
            g_kdf = argv[++i];
        else if (strcmp(argv[i], "--precompute") == 0)
            g_precompute = 1;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    parse_args(argc, argv);

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  End-to-End TLS 1.3 Hybrid PQC Benchmark\n");
    printf("  Adaptive Dispatch Runtime — Network Handshake Edition\n");
    printf("  Server Execution: Always Sequential\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Server:     %s:%d\n", g_host, SERVER_PORT);
    printf("  Iterations: %d\n", g_runs);
    printf("  KDF:        %s\n", g_kdf);
    printf("  Key Pool:   %s\n", g_precompute ? "ENABLED (pre-computed ephemeral key pool)" : "DISABLED (on-demand generation)");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /* Initialize pre-computed key pool if requested */
    if (g_precompute) {
        if (key_pool_init(32) != 0) {
            fprintf(stderr, "[!] Failed to initialize client key pool\n");
            return 1;
        }
        g_client_use_key_pool = 1;
        printf("[Client] Pre-computed key pool active (capacity: 32 per curve)\n");
    }

    /* Boot-time profiler (for adaptive routing decisions) */
    host_profile_init();
    client_worker_init();
    const HostProfile *hp = get_host_profile();
    printf("[Client] Hostname: %s | Cores: %d logical, %d physical | Sync Latency: %.2f µs | Load: %.2f | VM: %s\n\n",
           hp->hostname, hp->logical_cores, hp->physical_cores,
           (double)hp->sync_overhead_ns / 1000.0, hp->load_1min,
           hp->is_virtualized ? "YES" : "NO");

    /* Collect hybrid cipher suites */
    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID)
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
    }

    double *samples = malloc(sizeof(double) * (size_t)g_runs);
    if (!samples) { fprintf(stderr, "OOM\n"); return 1; }

    BenchMode modes[] = {
        MODE_STRICT_SEQUENTIAL,
        MODE_STRICT_PARALLEL,
        MODE_ADAPTIVE_SWITCH
    };
    int n_modes = 3;

    int max_results = n_hybrids * n_modes;
    BenchResult *all_results = calloc((size_t)max_results, sizeof(BenchResult));
    int result_idx = 0;

    for (int ci = 0; ci < n_hybrids; ci++) {
        const AlgoCombo *combo = hybrids[ci];
        DispatchRoute adaptive_route = adaptive_dispatch(combo);

        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  Cipher Suite:     %s\n", combo->label);
        printf("  KDF:              %s\n", g_kdf);
        printf("  Adaptive Route:   %s\n", route_name(adaptive_route));
        printf("  Iterations:       %d\n", g_runs);
        printf("═══════════════════════════════════════════════════════════════\n\n");

        LatencyStats stats[3];

        for (int mi = 0; mi < n_modes; mi++) {
            printf("  [%s] Running %d handshakes... ",
                   mode_label(modes[mi]), g_runs);
            fflush(stdout);

            if (run_bench(combo, modes[mi], samples, g_runs) != 0) {
                printf("FAILED\n");
                stats[mi] = (LatencyStats){0};
                continue;
            }

            compute_stats(samples, g_runs, &stats[mi]);
            printf("done (mean: %.4f ms)\n", stats[mi].mean_ms);

            if (result_idx < max_results) {
                all_results[result_idx].combo_label = combo->label;
                all_results[result_idx].mode_label  = mode_label(modes[mi]);
                all_results[result_idx].stats       = stats[mi];
                result_idx++;
            }
        }

        /* Markdown table */
        printf("\n### %s — E2E Latency Distribution (ms)\n\n", combo->label);
        printf("| Mode               | Mean       | p50        "
               "| p95        | p99        |\n");
        printf("|:-------------------|:-----------|:-----------"
               "|:-----------|:-----------|\n");
        for (int mi = 0; mi < n_modes; mi++) {
            printf("| %-18s | %10.4f | %10.4f | %10.4f | %10.4f |\n",
                   mode_label(modes[mi]),
                   stats[mi].mean_ms, stats[mi].p50_ms,
                   stats[mi].p95_ms,  stats[mi].p99_ms);
        }
        printf("\n");
    }

    export_results("e2e_benchmark_results.json", all_results, result_idx);

    if (g_precompute) {
        key_pool_destroy();
    }
    client_worker_shutdown();
    free(all_results);
    free(samples);

    printf("[✔] End-to-end benchmark complete.\n\n");
    return 0;
}
