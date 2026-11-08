/* c_dispatch/src/engine.c
 * ═══════════════════════════════════════════════════════════════════
 * Adaptive Execution Engine for Hybrid Post-Quantum TLS 1.3
 *
 * Implements two distinct critical path phases:
 *   Phase A: engine_client_keygen() -> Classical EC || PQC KEM Keygen
 *   Phase B: engine_client_finish() -> Classical ECDH Derive || KEM Decaps
 * ═══════════════════════════════════════════════════════════════════
 */

#include "../include/engine.h"
#include "../include/algo_config.h"
#include "../include/crypto_engine.h"
#include "../include/key_pool.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <oqs/oqs.h>

typedef enum {
    JOB_NONE,
    JOB_KEM_KEYGEN,
    JOB_KEM_DECAPS
} WorkerJobType;

typedef struct {
    pthread_t       thread;
    pthread_mutex_t mutex;
    pthread_cond_t  wake_cond;
    pthread_cond_t  done_cond;

    WorkerJobType   job_type;
    const char     *kem_name;

    /* Inputs/Outputs for KEM Keygen */
    uint8_t        *out_kem_pk;
    uint8_t        *out_kem_sk;
    size_t          kem_pk_len;
    size_t          kem_sk_len;

    /* Inputs/Outputs for KEM Decaps */
    const uint8_t  *in_ct;
    size_t          in_ct_len;
    const uint8_t  *in_sk;
    uint8_t         out_shared_secret[64];
    size_t          out_shared_secret_len;

    int             success;
    atomic_int      has_work;
    atomic_int      work_done;
    atomic_int      shutdown;

    int             worker_cpu;
    long            worker_tid;
} EngineWorkerPool;

static EngineWorkerPool g_engine_pool;
static int g_engine_initialized = 0;

static void *engine_worker_func(void *arg)
{
    EngineWorkerPool *pool = (EngineWorkerPool *)arg;

    /* Pin worker to Core 1 */
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus >= 2) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }
    pool->worker_tid = (long)syscall(SYS_gettid);
    pool->worker_cpu = sched_getcpu();

    while (1) {
        pthread_mutex_lock(&pool->mutex);
        while (!atomic_load(&pool->has_work) && !atomic_load(&pool->shutdown)) {
            pthread_cond_wait(&pool->wake_cond, &pool->mutex);
        }
        if (atomic_load(&pool->shutdown)) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        WorkerJobType job = pool->job_type;
        pool->success = 0;
        pthread_mutex_unlock(&pool->mutex);

        if (job == JOB_KEM_KEYGEN) {
            OQS_KEM *kem = OQS_KEM_new(pool->kem_name);
            if (kem) {
                if (OQS_KEM_keypair(kem, pool->out_kem_pk, pool->out_kem_sk) == OQS_SUCCESS) {
                    pool->success = 1;
                }
                OQS_KEM_free(kem);
            }
        } else if (job == JOB_KEM_DECAPS) {
            OQS_KEM *kem = OQS_KEM_new(pool->kem_name);
            if (kem) {
                if (OQS_KEM_decaps(kem, pool->out_shared_secret, pool->in_ct, pool->in_sk) == OQS_SUCCESS) {
                    pool->out_shared_secret_len = kem->length_shared_secret;
                    pool->success = 1;
                }
                OQS_KEM_free(kem);
            }
        }

        pool->worker_cpu = sched_getcpu();

        pthread_mutex_lock(&pool->mutex);
        atomic_store(&pool->has_work, 0);
        atomic_store(&pool->work_done, 1);
        pthread_cond_signal(&pool->done_cond);
        pthread_mutex_unlock(&pool->mutex);
    }
    return NULL;
}

int engine_init(void)
{
    if (g_engine_initialized) return 0;
    memset(&g_engine_pool, 0, sizeof(g_engine_pool));
    pthread_mutex_init(&g_engine_pool.mutex, NULL);
    pthread_cond_init(&g_engine_pool.wake_cond, NULL);
    pthread_cond_init(&g_engine_pool.done_cond, NULL);

    if (pthread_create(&g_engine_pool.thread, NULL, engine_worker_func, &g_engine_pool) != 0) {
        perror("engine_init: pthread_create");
        return -1;
    }
    usleep(5000); /* 5ms warmup */
    g_engine_initialized = 1;
    return 0;
}

void engine_shutdown(void)
{
    if (!g_engine_initialized) return;
    pthread_mutex_lock(&g_engine_pool.mutex);
    atomic_store(&g_engine_pool.shutdown, 1);
    pthread_cond_signal(&g_engine_pool.wake_cond);
    pthread_mutex_unlock(&g_engine_pool.mutex);

    pthread_join(g_engine_pool.thread, NULL);
    pthread_mutex_destroy(&g_engine_pool.mutex);
    pthread_cond_destroy(&g_engine_pool.wake_cond);
    pthread_cond_destroy(&g_engine_pool.done_cond);
    g_engine_initialized = 0;
}

int verify_affinity(AffinityProbe *probe)
{
    if (!g_engine_initialized || !probe) return -1;
    probe->main_thread_cpu = sched_getcpu();
    probe->main_thread_tid = (long)syscall(SYS_gettid);
    probe->worker_thread_cpu = g_engine_pool.worker_cpu;
    probe->worker_thread_tid = g_engine_pool.worker_tid;
    return 0;
}

/* -----------------------------------------------------------------------
 * Phase A: Client Keygen (Classical EC || PQC KEM)
 * ----------------------------------------------------------------------- */

int engine_client_keygen(const AlgoCombo *combo, DispatchRoute route,
                         ClientKeyShare *out_share, int *fell_back)
{
    if (fell_back) *fell_back = 0;
    memset(out_share, 0, sizeof(*out_share));
    out_share->combo_id = combo->id;

    if (!combo->pqc_name || combo->classical_curve == CURVE_NONE || route == ROUTE_SEQUENTIAL) {
        /* Sequential Keygen */
        if (combo->classical_curve != CURVE_NONE) {
            out_share->ec_priv = crypto_generate_keypair(combo->classical_curve);
            if (!out_share->ec_priv) return -1;
            if (combo->classical_curve == CURVE_X25519)
                crypto_export_x25519_pub_raw(out_share->ec_priv, out_share->ec_pub, &out_share->ec_pub_len);
            else
                crypto_export_ec_pub_der(out_share->ec_priv, out_share->ec_pub, &out_share->ec_pub_len);
        }
        if (combo->pqc_name) {
            OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
            if (!kem) return -1;
            out_share->kem_pk_len = kem->length_public_key;
            out_share->kem_sk_len = kem->length_secret_key;
            out_share->kem_pk = malloc(out_share->kem_pk_len);
            out_share->kem_sk = malloc(out_share->kem_sk_len);
            if (OQS_KEM_keypair(kem, out_share->kem_pk, out_share->kem_sk) != OQS_SUCCESS) {
                OQS_KEM_free(kem);
                client_key_share_free(out_share);
                return -1;
            }
            OQS_KEM_free(kem);
        }
        return 0;
    }

    /* Parallel Phase A: Dispatch KEM Keygen to Core 1, Main thread generates EC on Core 0 */
    if (!g_engine_initialized) engine_init();

    OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
    if (!kem) return -1;

    out_share->kem_pk_len = kem->length_public_key;
    out_share->kem_sk_len = kem->length_secret_key;
    out_share->kem_pk = malloc(out_share->kem_pk_len);
    out_share->kem_sk = malloc(out_share->kem_sk_len);
    OQS_KEM_free(kem);

    cpu_set_t orig_cpuset;
    int pinned = 0;
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus >= 2) {
        if (pthread_getaffinity_np(pthread_self(), sizeof(orig_cpuset), &orig_cpuset) == 0)
            pinned = 1;
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    pthread_mutex_lock(&g_engine_pool.mutex);
    g_engine_pool.job_type = JOB_KEM_KEYGEN;
    g_engine_pool.kem_name = combo->pqc_name;
    g_engine_pool.out_kem_pk = out_share->kem_pk;
    g_engine_pool.out_kem_sk = out_share->kem_sk;
    g_engine_pool.kem_pk_len = out_share->kem_pk_len;
    g_engine_pool.kem_sk_len = out_share->kem_sk_len;
    atomic_store(&g_engine_pool.work_done, 0);
    atomic_store(&g_engine_pool.has_work, 1);
    pthread_cond_signal(&g_engine_pool.wake_cond);
    pthread_mutex_unlock(&g_engine_pool.mutex);

    /* Main thread generates EC keypair */
    out_share->ec_priv = crypto_generate_keypair(combo->classical_curve);
    if (out_share->ec_priv) {
        if (combo->classical_curve == CURVE_X25519)
            crypto_export_x25519_pub_raw(out_share->ec_priv, out_share->ec_pub, &out_share->ec_pub_len);
        else
            crypto_export_ec_pub_der(out_share->ec_priv, out_share->ec_pub, &out_share->ec_pub_len);
    }

    pthread_mutex_lock(&g_engine_pool.mutex);
    while (!atomic_load(&g_engine_pool.work_done)) {
        pthread_cond_wait(&g_engine_pool.done_cond, &g_engine_pool.mutex);
    }
    int kem_ok = g_engine_pool.success;
    pthread_mutex_unlock(&g_engine_pool.mutex);

    if (pinned) {
        pthread_setaffinity_np(pthread_self(), sizeof(orig_cpuset), &orig_cpuset);
    }

    if (!out_share->ec_priv || !kem_ok) {
        client_key_share_free(out_share);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Phase B: Client Finish (Classical ECDH Derive || PQC KEM Decaps)
 * ----------------------------------------------------------------------- */

int engine_client_finish(const AlgoCombo *combo, DispatchRoute route,
                         const ClientKeyShare *ks,
                         const uint8_t *srv_pub, size_t srv_pub_len,
                         const uint8_t *ct, size_t ct_len,
                         SharedCryptoResult *out_result)
{
    memset(out_result, 0, sizeof(*out_result));

    /* Load Server Classical Public Key */
    EVP_PKEY *srv_key = NULL;
    if (combo->classical_curve != CURVE_NONE && srv_pub_len > 0) {
        if (combo->classical_curve == CURVE_X25519)
            srv_key = crypto_load_x25519_pub_raw(srv_pub, srv_pub_len);
        else
            srv_key = crypto_load_ec_pub_der(srv_pub, srv_pub_len);
        if (!srv_key) return -1;
    }

    if (!combo->pqc_name || !srv_key || route == ROUTE_SEQUENTIAL) {
        /* Sequential Phase B */
        if (srv_key) {
            out_result->ecdh_secret_len = sizeof(out_result->ecdh_secret);
            out_result->ecdh_ok = (crypto_derive_ecdh_secret(ks->ec_priv, srv_key,
                                                             out_result->ecdh_secret,
                                                             &out_result->ecdh_secret_len) == 0);
            EVP_PKEY_free(srv_key);
        }
        if (combo->pqc_name && ct && ct_len > 0) {
            OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
            if (kem) {
                if (OQS_KEM_decaps(kem, out_result->kem_shared_secret, ct, ks->kem_sk) == OQS_SUCCESS) {
                    out_result->kem_shared_secret_len = kem->length_shared_secret;
                    out_result->kem_ok = 1;
                }
                OQS_KEM_free(kem);
            }
        }
        return (out_result->ecdh_ok && out_result->kem_ok) ? 0 : -1;
    }

    /* Parallel Phase B: Core 1 decapsulates KEM, Core 0 derives ECDH */
    if (!g_engine_initialized) engine_init();

    cpu_set_t orig_cpuset;
    int pinned = 0;
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus >= 2) {
        if (pthread_getaffinity_np(pthread_self(), sizeof(orig_cpuset), &orig_cpuset) == 0)
            pinned = 1;
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    pthread_mutex_lock(&g_engine_pool.mutex);
    g_engine_pool.job_type = JOB_KEM_DECAPS;
    g_engine_pool.kem_name = combo->pqc_name;
    g_engine_pool.in_ct = ct;
    g_engine_pool.in_ct_len = ct_len;
    g_engine_pool.in_sk = ks->kem_sk;
    atomic_store(&g_engine_pool.work_done, 0);
    atomic_store(&g_engine_pool.has_work, 1);
    pthread_cond_signal(&g_engine_pool.wake_cond);
    pthread_mutex_unlock(&g_engine_pool.mutex);

    /* Main thread computes ECDH derive */
    out_result->ecdh_secret_len = sizeof(out_result->ecdh_secret);
    out_result->ecdh_ok = (crypto_derive_ecdh_secret(ks->ec_priv, srv_key,
                                                     out_result->ecdh_secret,
                                                     &out_result->ecdh_secret_len) == 0);
    EVP_PKEY_free(srv_key);

    pthread_mutex_lock(&g_engine_pool.mutex);
    while (!atomic_load(&g_engine_pool.work_done)) {
        pthread_cond_wait(&g_engine_pool.done_cond, &g_engine_pool.mutex);
    }
    out_result->kem_ok = g_engine_pool.success;
    if (out_result->kem_ok) {
        out_result->kem_shared_secret_len = g_engine_pool.out_shared_secret_len;
        memcpy(out_result->kem_shared_secret, g_engine_pool.out_shared_secret,
               out_result->kem_shared_secret_len);
    }
    pthread_mutex_unlock(&g_engine_pool.mutex);

    if (pinned) {
        pthread_setaffinity_np(pthread_self(), sizeof(orig_cpuset), &orig_cpuset);
    }

    return (out_result->ecdh_ok && out_result->kem_ok) ? 0 : -1;
}
