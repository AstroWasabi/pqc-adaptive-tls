/* c_dispatch/test_key_pool.c
 * ═══════════════════════════════════════════════════════════════════
 * Standalone Unit & Verification Test for Client Pre-Computed Key Pool
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/key_pool.h"
#include "../include/crypto_engine.h"

static inline double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void test_curve(int curve_id, const char *curve_name)
{
    printf("\n=== Testing %s (Curve ID: %d) ===\n", curve_name, curve_id);

    /* 1. Measure On-Demand Generation */
    double t0 = now_us();
    EVP_PKEY *inline_key = crypto_generate_keypair(curve_id);
    uint8_t inline_pub[KEY_POOL_MAX_PUB_BYTES];
    size_t inline_pub_len = 0;
    if (curve_id == CURVE_X25519) {
        crypto_export_x25519_pub_raw(inline_key, inline_pub, &inline_pub_len);
    } else {
        crypto_export_ec_pub_der(inline_key, inline_pub, &inline_pub_len);
    }
    double t1 = now_us();
    double inline_us = t1 - t0;
    EVP_PKEY_free(inline_key);

    /* 2. Measure Pre-computed Pool Pop */
    t0 = now_us();
    EVP_PKEY *popped_key = NULL;
    uint8_t popped_pub[KEY_POOL_MAX_PUB_BYTES];
    size_t popped_pub_len = 0;
    int rc = key_pool_pop(curve_id, &popped_key, popped_pub, &popped_pub_len);
    t1 = now_us();
    double pop_us = t1 - t0;

    if (rc != 0 || !popped_key) {
        printf("  [FAIL] Failed to pop key from pool!\n");
        return;
    }

    printf("  On-Demand Generation:   %8.2f µs\n", inline_us);
    printf("  Pre-computed Pool Pop: %8.2f µs\n", pop_us);
    printf("  Speedup / Savings:     %8.2f µs (%.1fx faster)\n",
           inline_us - pop_us, inline_us / (pop_us > 0.1 ? pop_us : 0.1));

    /* 3. Cryptographic Correctness Check */
    EVP_PKEY *peer_key = crypto_generate_keypair(curve_id);
    uint8_t sec1[64] = {0}, sec2[64] = {0};
    size_t sec1_len = sizeof(sec1), sec2_len = sizeof(sec2);

    crypto_derive_ecdh_secret(popped_key, peer_key, sec1, &sec1_len);
    crypto_derive_ecdh_secret(peer_key, popped_key, sec2, &sec2_len);

    if (sec1_len > 0 && sec1_len == sec2_len && memcmp(sec1, sec2, sec1_len) == 0) {
        printf("  [PASS] ECDH Shared Secret Verification Succeeded (len=%zu bytes)\n", sec1_len);
    } else {
        printf("  [FAIL] Cryptographic ECDH verification failed!\n");
    }

    EVP_PKEY_free(popped_key);
    EVP_PKEY_free(peer_key);
}

int main(void)
{
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Client Pre-Computed Ephemeral Key Pool Verification  \n");
    printf("═══════════════════════════════════════════════════════\n");

    printf("\nInitializing key pool with capacity 16 per curve...\n");
    if (key_pool_init(16) != 0) {
        fprintf(stderr, "Failed to initialize key pool\n");
        return 1;
    }

    /* Allow background replenishment worker to fill slots */
    usleep(50000); /* 50 ms */

    size_t avail = 0, cap = 0;
    for (int cid = 1; cid <= 3; cid++) {
        key_pool_stats(cid, &avail, &cap);
        printf("  Curve %d Inventory: %zu / %zu slots ready\n", cid, avail, cap);
    }

    test_curve(CURVE_X25519, "X25519");
    test_curve(CURVE_P256,   "SecP256r1");
    test_curve(CURVE_P384,   "SecP384r1");

    /* Burst Consumption Test */
    printf("\n── Burst Consumption Test (50 consecutive pops) ────────\n");
    double burst_start = now_us();
    int success_count = 0;
    for (int i = 0; i < 50; i++) {
        EVP_PKEY *k = NULL;
        uint8_t pub[KEY_POOL_MAX_PUB_BYTES];
        size_t pub_len = 0;
        if (key_pool_pop(CURVE_P256, &k, pub, &pub_len) == 0) {
            success_count++;
            EVP_PKEY_free(k);
        }
    }
    double burst_end = now_us();
    printf("  Successfully popped %d / 50 keys in %.2f µs (avg: %.2f µs/pop)\n",
           success_count, burst_end - burst_start, (burst_end - burst_start) / 50.0);

    /* Check replenishment recovery */
    usleep(50000);
    key_pool_stats(CURVE_P256, &avail, &cap);
    printf("  Replenished Inventory after burst: %zu / %zu slots available\n", avail, cap);

    key_pool_destroy();
    printf("\n[✔] Key Pool Shutdown and clean complete.\n");
    return 0;
}
