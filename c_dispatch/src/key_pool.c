/* c_dispatch/src/key_pool.c
 * ═══════════════════════════════════════════════════════════════════
 * Client-Side Pre-Computed Ephemeral Key Pool
 *
 * Provides instant (< 5 µs) retrieval of ephemeral keypairs and
 * wire-ready public keys. Replenishes key inventory in a background
 * thread so the TLS handshake critical path never blocks on scalar
 * curve multiplication.
 * ═══════════════════════════════════════════════════════════════════
 */

#include "../include/key_pool.h"
#include "../include/crypto_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>

static KeyPool g_client_key_pool;

/* Helper to export public key based on curve type */
static int export_pub_key(int curve_id, EVP_PKEY *pkey, uint8_t *out_buf, size_t *out_len)
{
    if (curve_id == CURVE_X25519) {
        return crypto_export_x25519_pub_raw(pkey, out_buf, out_len);
    } else {
        return crypto_export_ec_pub_der(pkey, out_buf, out_len);
    }
}

/* Background Replenishment Worker Loop */
static void *key_pool_worker_loop(void *arg)
{
    KeyPool *pool = (KeyPool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->worker_mutex);
        while (pool->running) {
            /* Check if any active ring needs replenishment */
            int need_refill = 0;
            for (int cid = 1; cid <= 3; cid++) {
                KeyRing *ring = &pool->rings[cid];
                pthread_mutex_lock(&ring->lock);
                if (ring->count < ring->capacity) {
                    need_refill = 1;
                    pthread_mutex_unlock(&ring->lock);
                    break;
                }
                pthread_mutex_unlock(&ring->lock);
            }

            if (need_refill) {
                break; /* Proceed to replenish */
            }

            /* Wait until notified by key_pool_pop() or shutdown */
            pthread_cond_wait(&pool->refill_cond, &pool->worker_mutex);
        }

        if (!pool->running) {
            pthread_mutex_unlock(&pool->worker_mutex);
            break;
        }
        pthread_mutex_unlock(&pool->worker_mutex);

        /* Replenish slots for all curves */
        for (int cid = 1; cid <= 3; cid++) {
            KeyRing *ring = &pool->rings[cid];

            while (pool->running) {
                pthread_mutex_lock(&ring->lock);
                if (ring->count >= ring->capacity) {
                    pthread_mutex_unlock(&ring->lock);
                    break; /* This ring is full */
                }
                pthread_mutex_unlock(&ring->lock);

                /* Generate outside the lock to minimize contention */
                EVP_PKEY *pkey = crypto_generate_keypair(cid);
                if (!pkey) {
                    usleep(1000);
                    continue;
                }

                uint8_t pub_buf[KEY_POOL_MAX_PUB_BYTES];
                size_t pub_len = 0;
                if (export_pub_key(cid, pkey, pub_buf, &pub_len) != 0) {
                    EVP_PKEY_free(pkey);
                    continue;
                }

                /* Enqueue slot into ring buffer */
                pthread_mutex_lock(&ring->lock);
                if (ring->count < ring->capacity) {
                    KeySlot *slot = &ring->slots[ring->tail];
                    slot->c_priv = pkey;
                    slot->pub_len = pub_len;
                    slot->curve_id = cid;
                    memcpy(slot->pub_buf, pub_buf, pub_len);

                    ring->tail = (ring->tail + 1) % ring->capacity;
                    ring->count++;
                    pool->total_replenished++;
                    pthread_mutex_unlock(&ring->lock);
                } else {
                    /* Filled while we were generating */
                    pthread_mutex_unlock(&ring->lock);
                    EVP_PKEY_free(pkey);
                    break;
                }
            }
        }
    }

    return NULL;
}

int key_pool_init(size_t capacity_per_curve)
{
    if (g_client_key_pool.initialized) {
        return 0;
    }

    memset(&g_client_key_pool, 0, sizeof(g_client_key_pool));
    if (capacity_per_curve == 0) {
        capacity_per_curve = KEY_POOL_DEFAULT_CAPACITY;
    }
    g_client_key_pool.capacity_per_curve = capacity_per_curve;

    pthread_mutex_init(&g_client_key_pool.worker_mutex, NULL);
    pthread_cond_init(&g_client_key_pool.refill_cond, NULL);

    /* Initialize rings for CURVE_X25519 (1), CURVE_P256 (2), CURVE_P384 (3) */
    for (int cid = 1; cid <= 3; cid++) {
        KeyRing *ring = &g_client_key_pool.rings[cid];
        ring->curve_id = cid;
        ring->capacity = capacity_per_curve;
        ring->head = 0;
        ring->tail = 0;
        ring->count = 0;
        pthread_mutex_init(&ring->lock, NULL);

        ring->slots = calloc(ring->capacity, sizeof(KeySlot));
        if (!ring->slots) {
            key_pool_destroy();
            return -1;
        }

        /* Initial synchronous pre-fill of at least 4 key shares per curve */
        size_t warm_count = (capacity_per_curve >= 4) ? 4 : capacity_per_curve;
        for (size_t i = 0; i < warm_count; i++) {
            EVP_PKEY *pkey = crypto_generate_keypair(cid);
            if (pkey) {
                KeySlot *slot = &ring->slots[ring->tail];
                slot->c_priv = pkey;
                slot->curve_id = cid;
                if (export_pub_key(cid, pkey, slot->pub_buf, &slot->pub_len) == 0) {
                    ring->tail = (ring->tail + 1) % ring->capacity;
                    ring->count++;
                    g_client_key_pool.total_replenished++;
                } else {
                    EVP_PKEY_free(pkey);
                }
            }
        }
    }

    g_client_key_pool.running = 1;
    if (pthread_create(&g_client_key_pool.worker_thread, NULL, key_pool_worker_loop, &g_client_key_pool) != 0) {
        key_pool_destroy();
        return -1;
    }

    g_client_key_pool.initialized = 1;
    return 0;
}

int key_pool_pop(int curve_id, EVP_PKEY **out_priv, uint8_t *out_pub, size_t *out_pub_len)
{
    if (curve_id < 1 || curve_id > 3) {
        return -1;
    }

    if (!g_client_key_pool.initialized) {
        /* Fallback if pool not initialized */
        EVP_PKEY *pkey = crypto_generate_keypair(curve_id);
        if (!pkey) return -1;
        if (export_pub_key(curve_id, pkey, out_pub, out_pub_len) != 0) {
            EVP_PKEY_free(pkey);
            return -1;
        }
        *out_priv = pkey;
        return 0;
    }

    KeyRing *ring = &g_client_key_pool.rings[curve_id];
    pthread_mutex_lock(&ring->lock);

    if (ring->count > 0) {
        KeySlot *slot = &ring->slots[ring->head];
        *out_priv = slot->c_priv;
        *out_pub_len = slot->pub_len;
        memcpy(out_pub, slot->pub_buf, slot->pub_len);

        /* Securely wipe slot memory to guarantee PFS */
        OPENSSL_cleanse(slot->pub_buf, sizeof(slot->pub_buf));
        slot->c_priv = NULL;
        slot->pub_len = 0;

        ring->head = (ring->head + 1) % ring->capacity;
        ring->count--;
        g_client_key_pool.total_popped++;

        /* Trigger background replenishment if count drops below half */
        if (ring->count < (ring->capacity / 2)) {
            pthread_mutex_lock(&g_client_key_pool.worker_mutex);
            pthread_cond_signal(&g_client_key_pool.refill_cond);
            pthread_mutex_unlock(&g_client_key_pool.worker_mutex);
        }

        pthread_mutex_unlock(&ring->lock);
        return 0;
    }

    /* Pool is empty: signal worker for emergency refill and do inline generation */
    pthread_mutex_unlock(&ring->lock);
    pthread_mutex_lock(&g_client_key_pool.worker_mutex);
    pthread_cond_signal(&g_client_key_pool.refill_cond);
    pthread_mutex_unlock(&g_client_key_pool.worker_mutex);

    EVP_PKEY *pkey = crypto_generate_keypair(curve_id);
    if (!pkey) return -1;
    if (export_pub_key(curve_id, pkey, out_pub, out_pub_len) != 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *out_priv = pkey;
    return 0;
}

void key_pool_stats(int curve_id, size_t *available, size_t *capacity)
{
    if (curve_id >= 1 && curve_id <= 3 && g_client_key_pool.initialized) {
        KeyRing *ring = &g_client_key_pool.rings[curve_id];
        pthread_mutex_lock(&ring->lock);
        if (available) *available = ring->count;
        if (capacity) *capacity = ring->capacity;
        pthread_mutex_unlock(&ring->lock);
    } else {
        if (available) *available = 0;
        if (capacity) *capacity = 0;
    }
}

void key_pool_destroy(void)
{
    if (!g_client_key_pool.initialized && !g_client_key_pool.running) {
        return;
    }

    /* Signal worker thread to stop */
    pthread_mutex_lock(&g_client_key_pool.worker_mutex);
    g_client_key_pool.running = 0;
    pthread_cond_signal(&g_client_key_pool.refill_cond);
    pthread_mutex_unlock(&g_client_key_pool.worker_mutex);

    if (g_client_key_pool.worker_thread) {
        pthread_join(g_client_key_pool.worker_thread, NULL);
    }

    /* Free all remaining slots across rings */
    for (int cid = 1; cid <= 3; cid++) {
        KeyRing *ring = &g_client_key_pool.rings[cid];
        pthread_mutex_lock(&ring->lock);
        if (ring->slots) {
            for (size_t i = 0; i < ring->capacity; i++) {
                if (ring->slots[i].c_priv) {
                    EVP_PKEY_free(ring->slots[i].c_priv);
                    ring->slots[i].c_priv = NULL;
                }
                OPENSSL_cleanse(ring->slots[i].pub_buf, sizeof(ring->slots[i].pub_buf));
            }
            free(ring->slots);
            ring->slots = NULL;
        }
        pthread_mutex_unlock(&ring->lock);
        pthread_mutex_destroy(&ring->lock);
    }

    pthread_mutex_destroy(&g_client_key_pool.worker_mutex);
    pthread_cond_destroy(&g_client_key_pool.refill_cond);

    g_client_key_pool.initialized = 0;
}
