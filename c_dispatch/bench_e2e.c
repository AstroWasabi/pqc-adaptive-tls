/* c_dispatch/bench_e2e.c
 * ═══════════════════════════════════════════════════════════════════
 * End-to-End TLS 1.3 Hybrid PQC Benchmark (Wire Framing V2)
 *
 * Evaluates:
 *   - Phase A: ClientHello Prep Latency (ch_prep_ms)
 *   - Phase B: In-Flight Crypto Latency (post_sh_ms)
 *   - Total End-to-End Handshake Latency (total_ms)
 *
 * Isolates cryptographic gains from network jitter!
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
#include "include/telemetry.h"
#include "include/key_pool.h"

extern int g_client_use_key_pool;

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
static int         g_runs        = 500;
static const char *g_kdf         = "sha256";
static int         g_precompute  = 0;
static int         g_filter_mode = -1;

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
    double p50_ms;
    double p95_ms;
    double p99_ms;
} LatencyStats;

typedef struct {
    const char  *combo_label;
    const char  *mode_label;
    LatencyStats ch_prep;
    LatencyStats post_sh;
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
        else if (strcmp(argv[i], "--seq") == 0)
            g_filter_mode = MODE_STRICT_SEQUENTIAL;
        else if (strcmp(argv[i], "--par") == 0)
            g_filter_mode = MODE_STRICT_PARALLEL;
        else if (strcmp(argv[i], "--ada") == 0)
            g_filter_mode = MODE_ADAPTIVE_SWITCH;
    }
}

static void export_results_json(const char *path, const BenchResultV2 *res, int n)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return;

    fprintf(fp, "[\n");
    for (int i = 0; i < n; i++) {
        fprintf(fp, "  {\n");
        fprintf(fp, "    \"cipher_suite\": \"%s\",\n", res[i].combo_label);
        fprintf(fp, "    \"mode\": \"%s\",\n", res[i].mode_label);
        fprintf(fp, "    \"pool_hit_rate\": %.2f,\n", res[i].pool_hit_rate);
        fprintf(fp, "    \"ch_prep_p50_ms\": %.6f,\n", res[i].ch_prep.p50_ms);
        fprintf(fp, "    \"ch_prep_mean_ms\": %.6f,\n", res[i].ch_prep.mean_ms);
        fprintf(fp, "    \"post_sh_p50_ms\": %.6f,\n", res[i].post_sh.p50_ms);
        fprintf(fp, "    \"post_sh_mean_ms\": %.6f,\n", res[i].post_sh.mean_ms);
        fprintf(fp, "    \"total_p50_ms\": %.6f,\n", res[i].total.p50_ms);
        fprintf(fp, "    \"total_mean_ms\": %.6f,\n", res[i].total.mean_ms);
        fprintf(fp, "    \"total_p99_ms\": %.6f\n", res[i].total.p99_ms);
        fprintf(fp, "  }%s\n", (i < n - 1) ? "," : "");
    }
    fprintf(fp, "]\n");
    fclose(fp);
    printf("[✔] Results exported -> %s\n\n", path);
}

int main(int argc, char *argv[])
{
    parse_args(argc, argv);

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  TLS 1.3 Hybrid PQC Benchmark V2 (Dual Keypool & Two-Phase)\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Server Host: %s:4444\n", g_host);
    printf("  Iterations:  %d\n", g_runs);
    printf("  KDF:         %s\n", g_kdf);
    printf("  Dual Pool:   %s\n", g_precompute ? "ENABLED (EC + PQC Precomputed)" : "DISABLED (Inline Keygen)");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID) {
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
        }
    }

    if (g_precompute) {
        if (key_pool_init(hybrids, n_hybrids, 32) != 0) {
            fprintf(stderr, "Failed to initialize dual key pool!\n");
            return 1;
        }
        g_client_use_key_pool = 1;
        printf("[*] Dual Ephemeral Key Pool Active (32 capacity per hybrid suite)\n\n");
    }

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

    double *s_ch   = malloc(sizeof(double) * (size_t)g_runs);
    double *s_post = malloc(sizeof(double) * (size_t)g_runs);
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
            DispatchRoute loc_route = mode_local_route(m, combo);

            printf("  [%-17s] Running %d handshakes... ", mode_label(m), g_runs);
            fflush(stdout);

            int pool_hits = 0;
            int valid_runs = 0;

            for (int i = 0; i < g_runs; i++) {
                HandshakeTiming t;
                if (execute_dispatch_handshake_v2(g_host, combo, g_kdf, loc_route, &t) == 0 && t.ok) {
                    s_ch[valid_runs]   = t.ch_prep_ms;
                    s_post[valid_runs] = t.post_sh_ms;
                    s_tot[valid_runs]  = t.total_ms;
                    if (t.pool_hit) pool_hits++;
                    valid_runs++;
                }
            }

            if (valid_runs == 0) {
                printf("FAILED\n");
                continue;
            }

            BenchResultV2 *r = &results[res_idx++];
            r->combo_label = combo->label;
            r->mode_label = mode_label(m);
            r->pool_hit_rate = ((double)pool_hits / valid_runs) * 100.0;
            compute_stats(s_ch, valid_runs, &r->ch_prep);
            compute_stats(s_post, valid_runs, &r->post_sh);
            compute_stats(s_tot, valid_runs, &r->total);

            printf("done\n");
            printf("    Phase A (CH Prep):  p50 = %7.4f ms | mean = %7.4f ms (Hit: %.1f%%)\n",
                   r->ch_prep.p50_ms, r->ch_prep.mean_ms, r->pool_hit_rate);
            printf("    Phase B (Post-SH):  p50 = %7.4f ms | mean = %7.4f ms\n",
                   r->post_sh.p50_ms, r->post_sh.mean_ms);
            printf("    Total (With Wire):  p50 = %7.4f ms | mean = %7.4f ms\n\n",
                   r->total.p50_ms, r->total.mean_ms);
        }
    }

    char out_path[64];
    snprintf(out_path, sizeof(out_path), "e2e_results_%s.json",
             g_precompute ? "precomputed" : "baseline");
    export_results_json(out_path, results, res_idx);

    if (g_precompute) key_pool_destroy();
    engine_shutdown();

    free(s_ch);
    free(s_post);
    free(s_tot);
    free(results);

    printf("[✔] Benchmark completed successfully.\n");
    return 0;
}
