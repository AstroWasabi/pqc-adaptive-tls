/* c_dispatch/benchmark_suite.c
 * Phase 5: Verification & Benchmarking Artifact
 *
 * Executes 1,000 iterations for each hybrid cipher suite across three
 * explicitly forced modes:
 *
 *   1. Strict_Sequential  — always execute_sequential()
 *   2. Strict_Parallel    — always execute_parallel_optimized()
 *   3. Adaptive_Switch    — dispatch_execute() (router decides)
 *
 * Timing: clock_gettime(CLOCK_MONOTONIC) for nanosecond precision.
 * Stats:  qsort → percentile extraction → Markdown table output.
 * Output: Mean, p50, p95, p99 tail latencies (milliseconds).
 *
 * Also runs verify_affinity() to prove core-pinning logic is active
 * by printing Thread IDs and their OS CPU core assignments.
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

/* ═══════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════ */

#define NUM_ITERATIONS  1000

/* ═══════════════════════════════════════════════════════════════════
 * Benchmark Modes
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum {
    MODE_STRICT_SEQUENTIAL,
    MODE_STRICT_PARALLEL,
    MODE_ADAPTIVE_SWITCH
} BenchMode;

static const char *mode_name(BenchMode m)
{
    switch (m) {
        case MODE_STRICT_SEQUENTIAL: return "Strict_Sequential";
        case MODE_STRICT_PARALLEL:   return "Strict_Parallel";
        case MODE_ADAPTIVE_SWITCH:   return "Adaptive_Switch";
        default:                     return "Unknown";
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
    /* qsort for ordered percentile extraction */
    qsort(samples, (size_t)n, sizeof(double), cmp_double);

    double sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += samples[i];

    out->mean_ms = sum / n;
    out->p50_ms  = samples[(int)((n - 1) * 0.50)];
    out->p95_ms  = samples[(int)((n - 1) * 0.95)];
    out->p99_ms  = samples[(int)((n - 1) * 0.99)];
}

/* ═══════════════════════════════════════════════════════════════════
 * Timing helper
 * ═══════════════════════════════════════════════════════════════════ */

static inline double timespec_diff_ms(const struct timespec *t0,
                                      const struct timespec *t1)
{
    return (t1->tv_sec - t0->tv_sec) * 1000.0 +
           (t1->tv_nsec - t0->tv_nsec) / 1e6;
}

/* ═══════════════════════════════════════════════════════════════════
 * Single-mode benchmark runner
 * ═══════════════════════════════════════════════════════════════════ */

static int run_bench(const AlgoCombo *combo, BenchMode mode,
                     HandshakeRole role, double *samples, int n_iter)
{
    for (int i = 0; i < n_iter; i++) {
        SharedCryptoResult result;
        struct timespec t0, t1;
        int rc;

        clock_gettime(CLOCK_MONOTONIC, &t0);

        switch (mode) {
            case MODE_STRICT_SEQUENTIAL:
                rc = execute_sequential(combo, role, &result);
                break;
            case MODE_STRICT_PARALLEL:
                rc = execute_parallel_optimized(combo, role, &result);
                break;
            case MODE_ADAPTIVE_SWITCH:
                rc = dispatch_execute(combo, role, &result);
                break;
            default:
                rc = -1;
                break;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (rc != 0) {
            fprintf(stderr, "[!] Execution failed: %s | mode=%s | iter=%d\n",
                    combo->label, mode_name(mode), i);
            return -1;
        }

        samples[i] = timespec_diff_ms(&t0, &t1);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Live affinity verification during parallel execution
 *
 * Dispatches a real parallel job and probes both threads with
 * sched_getcpu() during the execution window.
 * ═══════════════════════════════════════════════════════════════════ */

static void run_affinity_verification(const AlgoCombo *combo)
{
    printf("─── Live Affinity Verification (during parallel exec) ──────\n");

    /* Run a few parallel iterations to let the OS settle */
    for (int i = 0; i < 5; i++) {
        SharedCryptoResult result;
        execute_parallel_optimized(combo, ROLE_SERVER, &result);
    }

    /* Now probe */
    AffinityProbe probe;
    if (verify_affinity(&probe) == 0) {
        printf("  Main Thread   → TID: %-8ld  CPU Core: %d\n",
               probe.main_thread_tid, probe.main_thread_cpu);
        printf("  Worker Thread → TID: %-8ld  CPU Core: %d\n",
               probe.worker_thread_tid, probe.worker_thread_cpu);

        if (probe.main_thread_cpu == 0 && probe.worker_thread_cpu == 1) {
            printf("  Status:         ✔ VERIFIED — Core 0 ↔ Core 1 pinning active\n");
        } else if (probe.main_thread_cpu != probe.worker_thread_cpu) {
            printf("  Status:         ✔ SEPARATED — Threads on distinct cores "
                   "(Core %d ↔ Core %d)\n",
                   probe.main_thread_cpu, probe.worker_thread_cpu);
        } else {
            printf("  Status:         ⚠ SHARED — Both threads on Core %d "
                   "(insufficient cores or OS override)\n",
                   probe.main_thread_cpu);
        }
    } else {
        printf("  [!] Affinity probe failed (engine not initialised?)\n");
    }
    printf("────────────────────────────────────────────────────────────\n\n");
}

/* ═══════════════════════════════════════════════════════════════════
 * Export benchmark results to JSON (fprintf, no cJSON)
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *combo_label;
    const char *mode_label;
    LatencyStats stats;
} BenchResult;

static void export_results_json(const char *filepath,
                                const BenchResult *results, int n_results)
{
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("export_results_json: fopen");
        return;
    }

    fprintf(fp, "[\n");
    for (int i = 0; i < n_results; i++) {
        fprintf(fp, "  {\n");
        fprintf(fp, "    \"cipher_suite\": \"%s\",\n", results[i].combo_label);
        fprintf(fp, "    \"mode\": \"%s\",\n", results[i].mode_label);
        fprintf(fp, "    \"mean_ms\": %.6f,\n", results[i].stats.mean_ms);
        fprintf(fp, "    \"p50_ms\": %.6f,\n", results[i].stats.p50_ms);
        fprintf(fp, "    \"p95_ms\": %.6f,\n", results[i].stats.p95_ms);
        fprintf(fp, "    \"p99_ms\": %.6f\n", results[i].stats.p99_ms);
        fprintf(fp, "  }%s\n", (i < n_results - 1) ? "," : "");
    }
    fprintf(fp, "]\n");

    fclose(fp);
    printf("[✔] Results exported → %s\n\n", filepath);
}

/* ═══════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Adaptive Dispatch Runtime — TLS 1.3 Hybrid PQC Benchmark\n");
    printf("  Micro-Architectural Variance Analysis Suite\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");

    /* ─── Phase 1: Boot-Time Hardware Profiler ─── */
    host_profile_init();
    host_profile_export_json("host_profile.json");

    const HostProfile *hp = get_host_profile();
    char feat_buf[64], sync_buf[64], load_buf[64];
    snprintf(feat_buf, sizeof(feat_buf), "AVX2=%s AVX-512=%s",
             hp->has_avx2 ? "YES" : "NO", hp->has_avx512 ? "YES" : "NO");
    snprintf(sync_buf, sizeof(sync_buf), "%.2f µs (measured)",
             (double)hp->sync_overhead_ns / 1000.0);
    snprintf(load_buf, sizeof(load_buf), "%.2f (%.1f%% per core)",
             hp->load_1min, hp->load_per_core * 100.0);

    printf("┌─── Boot-Time Hardware Profile ────────────────────────────┐\n");
    printf("│  Hostname:       %-40s│\n", hp->hostname);
    printf("│  Vendor:         %-40s│\n", hp->sys_vendor);
    printf("│  Virtualized:    %-40s│\n",
           hp->is_virtualized ? "YES (hypervisor detected)" : "NO (bare metal)");
    printf("│  Cores:          %d logical / %-26d│\n", hp->logical_cores, hp->physical_cores);
    printf("│  CPU Features:   %-40s│\n", feat_buf);
    printf("│  Sync Latency:   %-40s│\n", sync_buf);
    printf("│  System Load:    %-40s│\n", load_buf);
    printf("│  Timestamp:      %-40s│\n", hp->boot_timestamp);
    printf("│  Exported:       %-40s│\n", "host_profile.json");
    printf("└───────────────────────────────────────────────────────────┘\n");
    printf("\n");

    /* ─── Phase 3: Initialize Execution Engine ─── */
    if (engine_init() != 0) {
        fprintf(stderr, "FATAL: engine_init() failed\n");
        return 1;
    }
    printf("[Engine] Pre-warmed worker pool initialised (Core 1 pinned)\n\n");

    /* ─── Phase 5: Affinity Verification ─── */
    AffinityProbe boot_probe;
    if (verify_affinity(&boot_probe) == 0) {
        printf("┌─── Core Affinity Verification (boot-time) ───────────────┐\n");
        printf("│  Main Thread   → TID: %-6ld  CPU Core: %-17d│\n",
               boot_probe.main_thread_tid, boot_probe.main_thread_cpu);
        printf("│  Worker Thread → TID: %-6ld  CPU Core: %-17d│\n",
               boot_probe.worker_thread_tid, boot_probe.worker_thread_cpu);
        printf("│  Pinning:        %-40s│\n",
               (boot_probe.main_thread_cpu == 0 &&
                boot_probe.worker_thread_cpu == 1)
                   ? "✔ VERIFIED (Core 0 ↔ Core 1)"
                   : "⚠ Partial (OS may override)");
        printf("└───────────────────────────────────────────────────────────┘\n");
        printf("\n");
    }

    /* ─── Collect hybrid cipher suites ─── */
    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID)
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
    }

    double *samples = malloc(sizeof(double) * NUM_ITERATIONS);
    if (!samples) {
        fprintf(stderr, "FATAL: OOM\n");
        return 1;
    }

    BenchMode modes[] = {
        MODE_STRICT_SEQUENTIAL,
        MODE_STRICT_PARALLEL,
        MODE_ADAPTIVE_SWITCH
    };
    int n_modes = 3;

    /* Storage for JSON export */
    int max_results = n_hybrids * n_modes;
    BenchResult *all_results = calloc((size_t)max_results, sizeof(BenchResult));
    int result_idx = 0;

    /* ─── Run benchmarks per cipher suite ─── */
    for (int ci = 0; ci < n_hybrids; ci++) {
        const AlgoCombo *combo = hybrids[ci];
        DispatchRoute adaptive_route = adaptive_dispatch(combo);

        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  Cipher Suite:    %s\n", combo->label);
        printf("  Adaptive Route:  %s\n", route_name(adaptive_route));
        printf("  Iterations:      %d\n", NUM_ITERATIONS);
        printf("  Role:            SERVER (ECDH_Derive || ML_KEM_Encapsulate)\n");
        printf("═══════════════════════════════════════════════════════════════\n\n");

        LatencyStats stats[3];

        for (int mi = 0; mi < n_modes; mi++) {
            printf("  [%s] Running %d iterations... ",
                   mode_name(modes[mi]), NUM_ITERATIONS);
            fflush(stdout);

            if (run_bench(combo, modes[mi], ROLE_SERVER,
                          samples, NUM_ITERATIONS) != 0) {
                printf("FAILED\n");
                stats[mi] = (LatencyStats){0};
                continue;
            }

            compute_stats(samples, NUM_ITERATIONS, &stats[mi]);
            printf("done (mean: %.4f ms)\n", stats[mi].mean_ms);

            /* Save for JSON export */
            if (result_idx < max_results) {
                all_results[result_idx].combo_label = combo->label;
                all_results[result_idx].mode_label  = mode_name(modes[mi]);
                all_results[result_idx].stats       = stats[mi];
                result_idx++;
            }
        }

        /* ── Markdown Table ── */
        printf("\n");
        printf("### %s — Latency Distribution (ms)\n\n", combo->label);
        printf("| Mode               | Mean       | p50        "
               "| p95        | p99        |\n");
        printf("|:-------------------|:-----------|:-----------"
               "|:-----------|:-----------|\n");
        for (int mi = 0; mi < n_modes; mi++) {
            printf("| %-18s | %10.4f | %10.4f | %10.4f | %10.4f |\n",
                   mode_name(modes[mi]),
                   stats[mi].mean_ms, stats[mi].p50_ms,
                   stats[mi].p95_ms,  stats[mi].p99_ms);
        }
        printf("\n");

        /* ── Live affinity verification for this suite ── */
        run_affinity_verification(combo);
    }

    /* ─── Export all results to JSON ─── */
    export_results_json("benchmark_results.json", all_results, result_idx);

    free(all_results);
    free(samples);

    /* ─── Cleanup ─── */
    engine_shutdown();
    printf("[Engine] Worker pool shut down\n");
    printf("[✔] Adaptive Dispatch Runtime — Benchmark suite complete.\n\n");

    return 0;
}
