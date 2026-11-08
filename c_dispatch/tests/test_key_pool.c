/* c_dispatch/tests/test_key_pool.c
 * ═══════════════════════════════════════════════════════════════════
 * Standalone Unit Verification for Dual Key Share Pool (EC + PQC)
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/key_pool.h"
#include "../include/algo_config.h"
#include "../include/crypto_engine.h"

static inline double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

int main(void)
{
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Dual Ephemeral Key Pool (EC + PQC) Unit Verification \n");
    printf("═══════════════════════════════════════════════════════\n\n");

    const AlgoCombo *hybrids[NUM_ALGO_COMBOS];
    int n_hybrids = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID) {
            hybrids[n_hybrids++] = &ALGORITHM_COMBOS[i];
        }
    }

    printf("Initializing key pool with capacity 16 per hybrid suite...\n");
    if (key_pool_init(hybrids, n_hybrids, 16) != 0) {
        fprintf(stderr, "Failed to init key pool\n");
        return 1;
    }

    usleep(50000); /* 50ms wait for background worker */

    for (int i = 0; i < n_hybrids; i++) {
        const AlgoCombo *combo = hybrids[i];
        printf("\n=== Testing Suite: %s ===\n", combo->label);

        /* 1. On-Demand Inline Keygen */
        double t0 = now_us();
        ClientKeyShare inline_share;
        int dummy = 0;
        key_pool_pop(NULL, &inline_share, &dummy); /* Forces inline */
        double t1 = now_us();
        double inline_us = t1 - t0;
        client_key_share_free(&inline_share);

        /* 2. Pre-computed Pool Pop */
        t0 = now_us();
        ClientKeyShare pool_share;
        int hit = 0;
        int rc = key_pool_pop(combo, &pool_share, &hit);
        t1 = now_us();
        double pop_us = t1 - t0;

        if (rc == 0 && hit && pool_share.ec_priv && pool_share.kem_pk && pool_share.kem_sk) {
            printf("  [PASS] Successfully popped dual share from pool!\n");
            printf("         EC pub bytes:  %zu\n", pool_share.ec_pub_len);
            printf("         KEM pk bytes: %zu | sk bytes: %zu\n",
                   pool_share.kem_pk_len, pool_share.kem_sk_len);
            printf("         Inline Generation: %8.2f µs\n", inline_us);
            printf("         Pool Pop Latency:  %8.2f µs\n", pop_us);
            printf("         Initialization Speedup: %.1fx faster\n",
                   inline_us / (pop_us > 0.1 ? pop_us : 0.1));
        } else {
            printf("  [FAIL] Dual keypool pop failed!\n");
        }
        client_key_share_free(&pool_share);
    }

    key_pool_destroy();
    printf("\n[✔] Key Pool shutdown complete.\n");
    return 0;
}
