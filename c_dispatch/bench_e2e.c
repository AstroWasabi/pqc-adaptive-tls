/* c_dispatch/bench_e2e.c
 * ═══════════════════════════════════════════════════════════════════
 * End-to-End TLS 1.3 Hybrid PQC Benchmark (Wire Framing V2)
 *
 * Evaluates:
 *   - Phase A: ClientHello Prep Latency (ch_prep_ms)
 *   - Phase B: In-Flight Crypto Latency (post_sh_ms)
 *   - Wire/Server Component (wire_ms)
 *   - Total End-to-End Handshake Latency (total_ms)
 *
 * Supports batch-safe pre-warmed dual key pools, untimed connection
 * warmups, per-batch JSON output, and raw per-handshake CSV export
 * for rigorous Master's thesis statistical aggregation.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "include/algo_config.h"
#include "include/dispatcher.h"
#include "include/engine.h"
#include "include/key_pool.h"
#include "include/telemetry.h"

extern int g_client_use_key_pool;
extern int g_server_port;

typedef struct {
    double ch_prep_ms;
    double post_sh_ms;
    double total_ms;
    int    pool_hit;
    int    ok;
} HandshakeTiming;

int execute_dispatch_handshake_v2(const char *host,
                                  const AlgoCombo *combo,
                                  const char *kdf_type,
                                  DispatchRoute local_route,
                                  HandshakeTiming *out_timing);

static const char *g_host        = "127.0.0.1";
static int         g_runs        = 200;
static int         g_warmup      = 5;
static size_t      g_capacity    = 0; /* 0 = auto-size to cover full batch + margin */
static const char *g_kdf         = "sha256";
static int         g_precompute  = 0;
static int         g_filter_mode = -1;
static const char *g_out_json    = NULL;
static const char *g_raw_csv     = NULL;

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

static DispatchRoute mode_local_route(BenchMode m, const AlgoCombo *combo)
{
    switch (m) {
        case MODE_STRICT_SEQUENTIAL: return ROUTE_SEQUENTIAL;
        case MODE_STRICT_PARALLEL:   return ROUTE_PARALLEL;
        case MODE_ADAPTIVE_SWITCH:   return adaptive_dispatch(combo);
        default:                     return ROUTE_SEQUENTIAL;
    }
}

typedef struct {
    double mean_ms;
    double stddev_ms;
    double p50_ms;
    double p95_ms;
    double p99_ms;
} LatencyStats;

typedef struct {
    const char  *combo_label;
    const char  *mode_label;
    const char  *selected_route;
    int          valid_runs;
    LatencyStats ch_prep;
    LatencyStats post_sh;
    LatencyStats wire;
    LatencyStats total;
    double       pool_hit_rate;
} BenchResultV2;

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

static void compute_stats(const double *raw_samples, int n, LatencyStats *out)
{
    memset(out, 0, sizeof(*out));
    if (n <= 0) return;

    double *sorted = malloc(sizeof(double) * (size_t)n);
    if (!sorted) return;
    memcpy(sorted, raw_samples, sizeof(double) * (size_t)n);
    qsort(sorted, (size_t)n, sizeof(double), cmp_double);

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += sorted[i];
    double mean = sum / n;

    double var_sum = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = sorted[i] - mean;
        var_sum += diff * diff;
    }

    out->mean_ms   = mean;
    out->stddev_ms = (n > 1) ? sqrt(var_sum / (n - 1)) : 0.0;
    out->p50_ms    = sorted[(int)((n - 1) * 0.50)];
    out->p95_ms    = sorted[(int)((n - 1) * 0.95)];
    out->p99_ms    = sorted[(int)((n - 1) * 0.99)];

    free(sorted);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("  --host <IP>          Server IP address (default: 127.0.0.1)\n");
    printf("  --port <PORT>        Server port (default: 4444)\n");
    printf("  --runs <N>           Measured handshakes per mode/suite (default: 200)\n");
    printf("  --warmup <W>         Untimed warmup handshakes per mode/suite (default: 5)\n");
    printf("  --precompute         Enable client dual ephemeral key pool (EC + PQC)\n");
    printf("  --capacity <C>       Client pool slots per suite (default: auto-sized for full batch)\n");
    printf("  --kdf <sha256|blake3>Session key KDF combiner (default: sha256)\n");
    printf("  --seq | --par | --adaFilter to a single dispatch mode\n");
    printf("  --out <FILE.json>    Output summary JSON path\n");
    printf("  --raw-csv <FILE.csv> Output per-handshake raw CSV path\n");
    printf("  --help, -h           Show this help message\n");
}

static void parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            g_host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_server_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            g_runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc)
            g_warmup = atoi(argv[++i]);
        else if (strcmp(argv[i], "--capacity") == 0 && i + 1 < argc)
            g_capacity = (size_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--kdf") == 0 && i + 1 < argc)
            g_kdf = argv[++i];
        else if (strcmp(argv[i], "--precompute") == 0)
            g_precompute = 1;
        else if (strcmp(argv[i], "--seq") == 0)
            g_filter_mode = MODE_STRICT_SEQUENTIAL;
        else if (strcmp(argv[i], "--par") == 0)
            g_filter_mode = MODE_STRICT_PARALLEL;
        else if (strcmp(argv[i], "--ada") == 0)
            g_filter_mode = MODE_ADAPTIVE_SWITCH;
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            g_out_json = argv[++i];
        else if (strcmp(argv[i], "--raw-csv") == 0 && i + 1 < argc)
            g_raw_csv = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
    }
    if (g_runs < 1) g_runs = 1;
    if (g_warmup < 0) g_warmup = 0;
}

static void export_results_json(const char *path, const BenchResultV2 *res, int n)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("export_results_json: fopen");
        return;
    }

    fprintf(fp, "[\n");
    for (int i = 0; i < n; i++) {
        fprintf(fp, "  {\n");
        fprintf(fp, "    \"cipher_suite\": \"%s\",\n", res[i].combo_label);
        fprintf(fp, "    \"mode\": \"%s\",\n", res[i].mode_label);
        fprintf(fp, "    \"selected_route\": \"%s\",\n", res[i].selected_route);
        fprintf(fp, "    \"valid_runs\": %d,\n", res[i].valid_runs);
        fprintf(fp, "    \"pool_hit_rate\": %.2f,\n", res[i].pool_hit_rate);
        fprintf(fp, "    \"ch_prep_p50_ms\": %.6f,\n", res[i].ch_prep.p50_ms);
        fprintf(fp, "    \"ch_prep_p95_ms\": %.6f,\n", res[i].ch_prep.p95_ms);
        fprintf(fp, "    \"ch_prep_p99_ms\": %.6f,\n", res[i].ch_prep.p99_ms);
        fprintf(fp, "    \"ch_prep_mean_ms\": %.6f,\n", res[i].ch_prep.mean_ms);
        fprintf(fp, "    \"ch_prep_stddev_ms\": %.6f,\n", res[i].ch_prep.stddev_ms);
        fprintf(fp, "    \"post_sh_p50_ms\": %.6f,\n", res[i].post_sh.p50_ms);
        fprintf(fp, "    \"post_sh_p95_ms\": %.6f,\n", res[i].post_sh.p95_ms);
        fprintf(fp, "    \"post_sh_p99_ms\": %.6f,\n", res[i].post_sh.p99_ms);
        fprintf(fp, "    \"post_sh_mean_ms\": %.6f,\n", res[i].post_sh.mean_ms);
        fprintf(fp, "    \"post_sh_stddev_ms\": %.6f,\n", res[i].post_sh.stddev_ms);
        fprintf(fp, "    \"wire_p50_ms\": %.6f,\n", res[i].wire.p50_ms);
        fprintf(fp, "    \"wire_mean_ms\": %.6f,\n", res[i].wire.mean_ms);
        fprintf(fp, "    \"wire_stddev_ms\": %.6f,\n", res[i].wire.stddev_ms);
        fprintf(fp, "    \"total_p50_ms\": %.6f,\n", res[i].total.p50_ms);
        fprintf(fp, "    \"total_p95_ms\": %.6f,\n", res[i].total.p95_ms);
        fprintf(fp, "    \"total_p99_ms\": %.6f,\n", res[i].total.p99_ms);
        fprintf(fp, "    \"total_mean_ms\": %.6f,\n", res[i].total.mean_ms);
        fprintf(fp, "    \"total_stddev_ms\": %.6f\n", res[i].total.stddev_ms);
        fprintf(fp, "  }%s\n", (i < n - 1) ? "," : "");
    }
    fprintf(fp, "]\n");
    fclose(fp);
    printf("[✔] Summary JSON exported -> %s\n", path);
}

int main(int argc, char *argv[])
{
    parse_args(argc, argv);

    /* Initialize Hardware Telemetry & Worker Engine */
    host_profile_init();
    host_profile_export_json("host_profile.json");
    const HostProfile *hp = get_host_profile();
    engine_init();

    BenchMode all_modes[] = {
        MODE_STRICT_SEQUENTIAL,
        MODE_STRICT_PARALLEL,
        MODE_ADAPTIVE_SWITCH
    };
    BenchMode modes[3];
    int n_modes = 0;
    if (g_filter_mode >= 0) {
        modes[n_modes++] = (BenchMode)g_filter_mode;
    } else {
        for (int i = 0; i < 3; i++) modes[n_modes++] = all_modes[i];
    }

    size_t effective_cap = g_capacity;
    if (g_precompute && effective_cap == 0) {
        /* Auto-size pool to cover all warmups + measured runs across active modes + 32 spare
         * so 100% of handshakes hit pre-warmed RAM with zero mid-batch refill contention. */
        effective_cap = (size_t)(n_modes * (g_runs + g_warmup)) + 32;
    }

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  TLS 1.3 Hybrid PQC Benchmark V2 (Dual Keypool & Two-Phase)\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Client Host: %s (%s, %d logical / %d physical cores%s)\n",
           hp->hostname,
           hp->is_virtualized ? hp->sys_vendor : "Bare Metal",
           hp->logical_cores, hp->physical_cores,
           hp->has_avx2 ? ", AVX2" : "");
    printf("  Server Host: %s:%d\n", g_host, g_server_port);
    printf("  Iterations:  %d (+ %d warmup/mode)\n", g_runs, g_warmup);
    printf("  KDF:         %s\n", g_kdf);
    printf("  Dual Pool:   %s\n", g_precompute ? "ENABLED (EC + PQC Precomputed)" : "DISABLED (Inline Keygen)");
    if (g_precompute) {
        printf("  Pool Cap:    %zu shares/suite (100%% pre-warmed)\n", effective_cap);
    }
    printf("═══════════════════════════════════════════════════════════════\n\n");

    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID) {
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
        }
    }

    if (g_precompute) {
        if (key_pool_init(hybrids, n_hybrids, effective_cap) != 0) {
            fprintf(stderr, "Failed to initialize dual key pool!\n");
            return 1;
        }
        g_client_use_key_pool = 1;
        printf("[✔] Client Dual Key Pool Ready (%zu capacity per suite)\n\n", effective_cap);
    }

    FILE *csv_fp = NULL;
    if (g_raw_csv) {
        csv_fp = fopen(g_raw_csv, "w");
        if (!csv_fp) {
            perror("raw_csv: fopen");
        } else {
            fprintf(csv_fp, "cipher_suite,mode,selected_route,iter,ch_prep_ms,post_sh_ms,wire_ms,total_ms,pool_hit\n");
        }
    }

    double *s_ch   = malloc(sizeof(double) * (size_t)g_runs);
    double *s_post = malloc(sizeof(double) * (size_t)g_runs);
    double *s_wire = malloc(sizeof(double) * (size_t)g_runs);
    double *s_tot  = malloc(sizeof(double) * (size_t)g_runs);

    BenchResultV2 *results = calloc((size_t)(n_hybrids * n_modes), sizeof(BenchResultV2));
    int res_idx = 0;

    for (int ci = 0; ci < n_hybrids; ci++) {
        const AlgoCombo *combo = hybrids[ci];
        printf("───────────────────────────────────────────────────────────────\n");
        printf("  Cipher Suite: %s\n", combo->label);
        printf("───────────────────────────────────────────────────────────────\n");

        for (int mi = 0; mi < n_modes; mi++) {
            BenchMode m = modes[mi];
            DispatchRoute preview_route = mode_local_route(m, combo);

            printf("  [%-17s -> %-10s] Running %d handshakes... ",
                   mode_label(m), route_name(preview_route), g_runs);
            fflush(stdout);

            /* Untimed connection/cache warmups */
            for (int w = 0; w < g_warmup; w++) {
                HandshakeTiming wt;
                DispatchRoute w_route = mode_local_route(m, combo);
                (void)execute_dispatch_handshake_v2(g_host, combo, g_kdf, w_route, &wt);
            }

            int pool_hits = 0;
            int valid_runs = 0;
            int par_count = 0;

            for (int i = 0; i < g_runs; i++) {
                HandshakeTiming t;
                DispatchRoute loc_route = mode_local_route(m, combo);
                if (execute_dispatch_handshake_v2(g_host, combo, g_kdf, loc_route, &t) == 0 && t.ok) {
                    double w_ms = t.total_ms - (t.ch_prep_ms + t.post_sh_ms);
                    if (w_ms < 0.0) w_ms = 0.0;

                    s_ch[valid_runs]   = t.ch_prep_ms;
                    s_post[valid_runs] = t.post_sh_ms;
                    s_wire[valid_runs] = w_ms;
                    s_tot[valid_runs]  = t.total_ms;
                    if (t.pool_hit) pool_hits++;
                    if (loc_route == ROUTE_PARALLEL) par_count++;

                    if (csv_fp) {
                        fprintf(csv_fp, "\"%s\",%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%d\n",
                                combo->label, mode_label(m), route_name(loc_route),
                                valid_runs + 1, t.ch_prep_ms, t.post_sh_ms, w_ms,
                                t.total_ms, t.pool_hit);
                    }
                    valid_runs++;
                }
            }

            if (valid_runs == 0) {
                printf("FAILED\n\n");
                continue;
            }

            BenchResultV2 *r = &results[res_idx++];
            r->combo_label    = combo->label;
            r->mode_label     = mode_label(m);
            r->selected_route = (par_count * 2 >= valid_runs) ? "Parallel" : "Sequential";
            r->valid_runs     = valid_runs;
            r->pool_hit_rate  = ((double)pool_hits / valid_runs) * 100.0;
            compute_stats(s_ch,   valid_runs, &r->ch_prep);
            compute_stats(s_post, valid_runs, &r->post_sh);
            compute_stats(s_wire, valid_runs, &r->wire);
            compute_stats(s_tot,  valid_runs, &r->total);

            printf("done (%d/%d)\n", valid_runs, g_runs);
            printf("    Phase A (CH Prep):  p50 = %7.4f ms | p95 = %7.4f ms | mean = %7.4f ± %.4f ms (Hit: %.1f%%)\n",
                   r->ch_prep.p50_ms, r->ch_prep.p95_ms, r->ch_prep.mean_ms, r->ch_prep.stddev_ms, r->pool_hit_rate);
            printf("    Phase B (Post-SH):  p50 = %7.4f ms | p95 = %7.4f ms | mean = %7.4f ± %.4f ms\n",
                   r->post_sh.p50_ms, r->post_sh.p95_ms, r->post_sh.mean_ms, r->post_sh.stddev_ms);
            printf("    Total (With Wire):  p50 = %7.4f ms | p95 = %7.4f ms | mean = %7.4f ± %.4f ms\n\n",
                   r->total.p50_ms, r->total.p95_ms, r->total.mean_ms, r->total.stddev_ms);
        }
    }

    if (csv_fp) {
        fclose(csv_fp);
        printf("[✔] Raw per-handshake CSV exported -> %s\n", g_raw_csv);
    }

    char default_out[64];
    const char *final_json = g_out_json;
    if (!final_json) {
        snprintf(default_out, sizeof(default_out), "e2e_results_%s.json",
                 g_precompute ? "precomputed" : "baseline");
        final_json = default_out;
    }
    export_results_json(final_json, results, res_idx);
    printf("\n");

    if (g_precompute) key_pool_destroy();
    engine_shutdown();

    free(s_ch);
    free(s_post);
    free(s_wire);
    free(s_tot);
    free(results);

    printf("[✔] Benchmark completed successfully.\n");
    return 0;
}
