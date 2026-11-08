/* c_dispatch/benchmark_suite.c
 * Local Client-Side Hybrid PQC Benchmark
 *
 * Microbenchmarks Phase A (Keygen) and Phase B (Finish)
 * across Strict_Sequential, Strict_Parallel, and Adaptive_Switch.
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
#include "include/crypto_engine.h"
#include <oqs/oqs.h>

#define NUM_ITERATIONS 500

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

static inline double timespec_diff_ms(const struct timespec *t0,
                                      const struct timespec *t1)
{
    return (t1->tv_sec - t0->tv_sec) * 1000.0 +
           (t1->tv_nsec - t0->tv_nsec) / 1e6;
}

static DispatchRoute resolve_route(BenchMode mode, const AlgoCombo *combo)
{
    switch (mode) {
        case MODE_STRICT_SEQUENTIAL: return ROUTE_SEQUENTIAL;
        case MODE_STRICT_PARALLEL:   return ROUTE_PARALLEL;
        case MODE_ADAPTIVE_SWITCH:   return adaptive_dispatch(combo);
        default:                     return ROUTE_SEQUENTIAL;
    }
}

int main(void)
{
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  Hybrid PQC Local Client Microbenchmark Suite                \n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    engine_init();
    host_profile_init();

    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID) {
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
        }
    }

    BenchMode modes[] = {
        MODE_STRICT_SEQUENTIAL,
        MODE_STRICT_PARALLEL,
        MODE_ADAPTIVE_SWITCH
    };
    int n_modes = 3;

    double *samples = malloc(sizeof(double) * NUM_ITERATIONS);

    for (int ci = 0; ci < n_hybrids; ci++) {
        const AlgoCombo *combo = hybrids[ci];
        printf("───────────────────────────────────────────────────────────────\n");
        printf("  Suite: %s\n", combo->label);
        printf("───────────────────────────────────────────────────────────────\n");

        /* Pre-generate mock server response for Phase B testing */
        EVP_PKEY *srv_priv = crypto_generate_keypair(combo->classical_curve);
        uint8_t srv_pub[300];
        size_t srv_pub_len = 0;
        if (combo->classical_curve == CURVE_X25519)
            crypto_export_x25519_pub_raw(srv_priv, srv_pub, &srv_pub_len);
        else
            crypto_export_ec_pub_der(srv_priv, srv_pub, &srv_pub_len);

        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        uint8_t *fake_pk = malloc(kem->length_public_key);
        uint8_t *fake_sk = malloc(kem->length_secret_key);
        uint8_t *mock_ct = malloc(kem->length_ciphertext);
        uint8_t *mock_ss = malloc(kem->length_shared_secret);
        OQS_KEM_keypair(kem, fake_pk, fake_sk);
        OQS_KEM_encaps(kem, mock_ct, mock_ss, fake_pk);

        for (int mi = 0; mi < n_modes; mi++) {
            BenchMode m = modes[mi];
            DispatchRoute r = resolve_route(m, combo);

            for (int it = 0; it < NUM_ITERATIONS; it++) {
                ClientKeyShare ks;
                int fell_back = 0;

                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);

                /* Phase A: Keygen */
                engine_client_keygen(combo, r, &ks, &fell_back);

                /* Phase B: Finish */
                SharedCryptoResult cr;
                engine_client_finish(combo, r, &ks, srv_pub, srv_pub_len,
                                     mock_ct, kem->length_ciphertext, &cr);

                clock_gettime(CLOCK_MONOTONIC, &t1);
                samples[it] = timespec_diff_ms(&t0, &t1);

                client_key_share_free(&ks);
            }

            LatencyStats st;
            compute_stats(samples, NUM_ITERATIONS, &st);
            printf("  [%-17s] mean = %7.4f ms | p50 = %7.4f ms | p95 = %7.4f ms | p99 = %7.4f ms\n",
                   mode_name(m), st.mean_ms, st.p50_ms, st.p95_ms, st.p99_ms);
        }

        EVP_PKEY_free(srv_priv);
        free(fake_pk);
        free(fake_sk);
        free(mock_ct);
        free(mock_ss);
        OQS_KEM_free(kem);
        printf("\n");
    }

    free(samples);
    engine_shutdown();
    return 0;
}
