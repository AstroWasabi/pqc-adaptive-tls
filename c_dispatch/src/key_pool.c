/* c_dispatch/src/key_pool.c
 * ═══════════════════════════════════════════════════════════════════
 * Client-Side Pre-Computed Dual Key Share Pool (EC + PQC)
 *
 * Pre-generates and serializes BOTH:
 *   1. Classical Ephemeral Keypair (X25519, SecP256r1, SecP384r1)
 *   2. Post-Quantum KEM Keypair (ML-KEM, FrodoKEM-1344, BIKE-L5)
 *
 * Reduces ClientHello construction delay from ~3.5 ms to < 5 µs.
 * ═══════════════════════════════════════════════════════════════════
 */

#include "../include/key_pool.h"
#include "../include/crypto_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>

#define MAX_POOLS 8

typedef struct {
    ComboKeyRing rings[MAX_POOLS];
    int          num_rings;
    pthread_t    worker_thread;
    pthread_mutex_t worker_mutex;
    pthread_cond_t  refill_cond;
    int          running;
    int          initialized;
    size_t       capacity;
    unsigned long total_popped;
    unsigned long total_replenished;
} GlobalKeyPool;

static GlobalKeyPool g_pool;

void client_key_share_free(ClientKeyShare *ks)
{
    if (!ks) return;
    if (ks->ec_priv) {
        EVP_PKEY_free(ks->ec_priv);
        ks->ec_priv = NULL;
    }
    if (ks->kem_sk) {
        OQS_MEM_secure_free(ks->kem_sk, ks->kem_sk_len);
        ks->kem_sk = NULL;
    }
    if (ks->kem_pk) {
        free(ks->kem_pk);
        ks->kem_pk = NULL;
    }
    ks->ec_pub_len = 0;
    ks->kem_pk_len = 0;
    ks->kem_sk_len = 0;
}

/* Synchronous generation of a single dual key share */
static int generate_single_share(const AlgoCombo *combo, ClientKeyShare *out)
{
    memset(out, 0, sizeof(*out));
    out->combo_id = combo->id;

    /* 1. Classical Keypair */
    if (combo->classical_curve != CURVE_NONE) {
        out->ec_priv = crypto_generate_keypair(combo->classical_curve);
        if (!out->ec_priv) goto fail;

        if (combo->classical_curve == CURVE_X25519) {
            if (crypto_export_x25519_pub_raw(out->ec_priv, out->ec_pub, &out->ec_pub_len) != 0)
                goto fail;
        } else {
            if (crypto_export_ec_pub_der(out->ec_priv, out->ec_pub, &out->ec_pub_len) != 0)
                goto fail;
        }
    }

    /* 2. Post-Quantum KEM Keypair */
    if (combo->pqc_name) {
        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        if (!kem) goto fail;

        out->kem_pk_len = kem->length_public_key;
        out->kem_sk_len = kem->length_secret_key;
        out->kem_pk = malloc(out->kem_pk_len);
        out->kem_sk = malloc(out->kem_sk_len);

        if (!out->kem_pk || !out->kem_sk) {
            OQS_KEM_free(kem);
            goto fail;
        }

        if (OQS_KEM_keypair(kem, out->kem_pk, out->kem_sk) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            goto fail;
        }
        OQS_KEM_free(kem);
    }

    return 0;

fail:
    client_key_share_free(out);
    return -1;
}

/* Background worker thread loop */
static void *key_pool_worker_loop(void *arg)
{
    GlobalKeyPool *p = (GlobalKeyPool *)arg;

    while (1) {
        pthread_mutex_lock(&p->worker_mutex);
        while (p->running) {
            int need_refill = 0;
            for (int r = 0; r < p->num_rings; r++) {
                ComboKeyRing *ring = &p->rings[r];
                pthread_mutex_lock(&ring->lock);
                if (ring->count < ring->capacity) {
                    need_refill = 1;
                    pthread_mutex_unlock(&ring->lock);
                    break;
                }
                pthread_mutex_unlock(&ring->lock);
            }
            if (need_refill) break;
            pthread_cond_wait(&p->refill_cond, &p->worker_mutex);
        }

        if (!p->running) {
            pthread_mutex_unlock(&p->worker_mutex);
            break;
        }
        pthread_mutex_unlock(&p->worker_mutex);

        /* Replenish slots across rings */
        for (int r = 0; r < p->num_rings && p->running; r++) {
            ComboKeyRing *ring = &p->rings[r];

            while (p->running) {
                pthread_mutex_lock(&ring->lock);
                if (ring->count >= ring->capacity) {
                    pthread_mutex_unlock(&ring->lock);
                    break;
                }
                pthread_mutex_unlock(&ring->lock);

                ClientKeyShare share;
                if (generate_single_share(ring->combo, &share) != 0) {
                    usleep(1000);
                    continue;
                }

                pthread_mutex_lock(&ring->lock);
                if (ring->count < ring->capacity) {
                    ring->slots[ring->tail] = share;
                    ring->tail = (ring->tail + 1) % ring->capacity;
                    ring->count++;
                    p->total_replenished++;
                    pthread_mutex_unlock(&ring->lock);
                } else {
                    pthread_mutex_unlock(&ring->lock);
                    client_key_share_free(&share);
                    break;
                }
            }
        }
    }
    return NULL;
}

int key_pool_init(const AlgoCombo *const *combos, int n_combos, size_t capacity)
{
    if (g_pool.initialized) return 0;
    if (n_combos <= 0 || n_combos > MAX_POOLS) return -1;
    if (capacity == 0) capacity = KEY_POOL_DEFAULT_CAPACITY;

    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.capacity = capacity;
    g_pool.num_rings = n_combos;

    pthread_mutex_init(&g_pool.worker_mutex, NULL);
    pthread_cond_init(&g_pool.refill_cond, NULL);

    for (int i = 0; i < n_combos; i++) {
        ComboKeyRing *ring = &g_pool.rings[i];
        ring->combo = combos[i];
        ring->capacity = capacity;
        ring->head = 0;
        ring->tail = 0;
        ring->count = 0;
        pthread_mutex_init(&ring->lock, NULL);

        ring->slots = calloc(ring->capacity, sizeof(ClientKeyShare));
        if (!ring->slots) {
            key_pool_destroy();
            return -1;
        }

        /* Synchronously pre-fill 4 slots per combo to ensure instant readiness */
        size_t warm = (capacity >= 4) ? 4 : capacity;
        for (size_t s = 0; s < warm; s++) {
            ClientKeyShare share;
            if (generate_single_share(ring->combo, &share) == 0) {
                ring->slots[ring->tail] = share;
                ring->tail = (ring->tail + 1) % ring->capacity;
                ring->count++;
                g_pool.total_replenished++;
            }
        }
    }

    g_pool.running = 1;
    if (pthread_create(&g_pool.worker_thread, NULL, key_pool_worker_loop, &g_pool) != 0) {
        key_pool_destroy();
        return -1;
    }

    g_pool.initialized = 1;
    return 0;
}

int key_pool_pop(const AlgoCombo *combo, ClientKeyShare *out_share, int *out_hit)
{
    if (!combo || !out_share) return -1;
    memset(out_share, 0, sizeof(*out_share));

    if (!g_pool.initialized) {
        if (out_hit) *out_hit = 0;
        return generate_single_share(combo, out_share);
    }

    ComboKeyRing *target_ring = NULL;
    for (int r = 0; r < g_pool.num_rings; r++) {
        if (g_pool.rings[r].combo->id == combo->id) {
            target_ring = &g_pool.rings[r];
            break;
        }
    }

    if (!target_ring) {
        if (out_hit) *out_hit = 0;
        return generate_single_share(combo, out_share);
    }

    pthread_mutex_lock(&target_ring->lock);
    if (target_ring->count > 0) {
        *out_share = target_ring->slots[target_ring->head];
        memset(&target_ring->slots[target_ring->head], 0, sizeof(ClientKeyShare));
        target_ring->head = (target_ring->head + 1) % target_ring->capacity;
        target_ring->count--;
        g_pool.total_popped++;

        if (target_ring->count < (target_ring->capacity / 2)) {
            pthread_mutex_lock(&g_pool.worker_mutex);
            pthread_cond_signal(&g_pool.refill_cond);
            pthread_mutex_unlock(&g_pool.worker_mutex);
        }

        pthread_mutex_unlock(&target_ring->lock);
        if (out_hit) *out_hit = 1;
        return 0;
    }

    /* Pool miss - signal background worker and generate inline */
    pthread_mutex_unlock(&target_ring->lock);
    pthread_mutex_lock(&g_pool.worker_mutex);
    pthread_cond_signal(&g_pool.refill_cond);
    pthread_mutex_unlock(&g_pool.worker_mutex);

    if (out_hit) *out_hit = 0;
    return generate_single_share(combo, out_share);
}

void key_pool_get_stats(const AlgoCombo *combo, KeyPoolStats *out_stats)
{
    if (!out_stats) return;
    memset(out_stats, 0, sizeof(*out_stats));
    if (!g_pool.initialized || !combo) return;

    for (int r = 0; r < g_pool.num_rings; r++) {
        ComboKeyRing *ring = &g_pool.rings[r];
        if (ring->combo->id == combo->id) {
            pthread_mutex_lock(&ring->lock);
            out_stats->available = ring->count;
            out_stats->capacity = ring->capacity;
            out_stats->replenished = g_pool.total_replenished;
            out_stats->hits = g_pool.total_popped;
            pthread_mutex_unlock(&ring->lock);
            break;
        }
    }
}

void key_pool_destroy(void)
{
    if (!g_pool.initialized && !g_pool.running) return;

    pthread_mutex_lock(&g_pool.worker_mutex);
    g_pool.running = 0;
    pthread_cond_signal(&g_pool.refill_cond);
    pthread_mutex_unlock(&g_pool.worker_mutex);

    if (g_pool.worker_thread) {
        pthread_join(g_pool.worker_thread, NULL);
    }

    for (int r = 0; r < g_pool.num_rings; r++) {
        ComboKeyRing *ring = &g_pool.rings[r];
        pthread_mutex_lock(&ring->lock);
        if (ring->slots) {
            for (size_t s = 0; s < ring->capacity; s++) {
                client_key_share_free(&ring->slots[s]);
            }
            free(ring->slots);
            ring->slots = NULL;
        }
        pthread_mutex_unlock(&ring->lock);
        pthread_mutex_destroy(&ring->lock);
    }

    pthread_mutex_destroy(&g_pool.worker_mutex);
    pthread_cond_destroy(&g_pool.refill_cond);
    g_pool.initialized = 0;
}
