/* c_dispatch/src/engine.c
 * Phase 3: The Execution Engine
 *
 * Two execution strategies for TLS 1.3 Hybrid PQC key exchange:
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ execute_sequential()                                           │
 * │  Thread 0 ──► ECDH_Derive ──► ML_KEM_Op ──► done              │
 * │  (L1-hot, zero context switches)                               │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ execute_parallel_optimized()                                   │
 * │  Thread 0 (Core 0) ──► ECDH_Derive ──────────┐                │
 * │  Thread 1 (Core 1) ──► ML_KEM_Op ────────────┤► join results  │
 * │  (pre-warmed worker, pthread_cond_signal wake)                 │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Protocol Alignment (RFC 9954):
 *   Server: ECDH_Derive || ML_KEM_Encapsulate
 *   Client: ECDH_Derive || ML_KEM_Decapsulate
 */

#include "../include/engine.h"
#include "../include/algo_config.h"
#include "../include/crypto_engine.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <oqs/oqs.h>

/* ═══════════════════════════════════════════════════════════════════
 * Worker Pool — persistent, pre-warmed single-worker thread
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t wake_cond; /* main → worker: "work available"   */
  pthread_cond_t done_cond; /* worker → main: "work complete"    */

  /* ── Work descriptor (set by main thread before signalling) ── */
  const char *kem_alg_name; /* liboqs algorithm string          */
  HandshakeRole role;       /* CLIENT=decaps, SERVER=encaps      */

  /* ── KEM result (written by worker thread) ── */
  uint8_t kem_shared_secret[64];
  size_t kem_shared_secret_len;
  int kem_ok;

  /* ── Control flags (C11 atomics for lock-free reads) ── */
  atomic_int has_work;  /* 1 = work pending                  */
  atomic_int work_done; /* 1 = result ready                  */
  atomic_int shutdown;  /* 1 = terminate worker              */

  /* ── Affinity telemetry ── */
  int worker_cpu;  /* last sched_getcpu() on worker     */
  long worker_tid; /* OS thread ID (gettid)             */
} WorkerPool;

static WorkerPool g_pool;
static int g_engine_initialized = 0;

/* -----------------------------------------------------------------------
 * KEM operation — executed by the worker thread
 * Handles both Encapsulate (server) and Decapsulate (client) paths.
 * ----------------------------------------------------------------------- */

static void perform_kem_operation(WorkerPool *pool) {
  pool->kem_ok = 0;
  pool->kem_shared_secret_len = 0;

  OQS_KEM *kem = OQS_KEM_new(pool->kem_alg_name);
  if (!kem) {
    fprintf(stderr, "[engine/worker] OQS_KEM_new('%s') failed\n",
            pool->kem_alg_name);
    return;
  }

  uint8_t *pk = malloc(kem->length_public_key);
  uint8_t *sk = malloc(kem->length_secret_key);
  uint8_t *ct = malloc(kem->length_ciphertext);
  uint8_t *ss = malloc(kem->length_shared_secret);

  if (!pk || !sk || !ct || !ss)
    goto cleanup;

  /* Generate ML-KEM keypair */
  if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS)
    goto cleanup;

  if (pool->role == ROLE_SERVER) {
    /* ── Server path: ML_KEM_Encapsulate ──
     * Encapsulate using peer's public key to produce
     * (ciphertext, shared_secret). */
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS)
      goto cleanup;
  } else {
    /* ── Client path: ML_KEM_Decapsulate ──
     * Simulate receiving ciphertext from server (encaps first),
     * then decapsulate with our secret key. */
    uint8_t *ss_server = malloc(kem->length_shared_secret);
    if (!ss_server)
      goto cleanup;

    if (OQS_KEM_encaps(kem, ct, ss_server, pk) != OQS_SUCCESS) {
      free(ss_server);
      goto cleanup;
    }
    free(ss_server);

    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS)
      goto cleanup;
  }

  /* Copy shared secret to pool result */
  size_t copy_len = kem->length_shared_secret;
  if (copy_len > sizeof(pool->kem_shared_secret))
    copy_len = sizeof(pool->kem_shared_secret);
  memcpy(pool->kem_shared_secret, ss, copy_len);
  pool->kem_shared_secret_len = copy_len;
  pool->kem_ok = 1;

cleanup:
  free(pk);
  free(sk);
  free(ct);
  free(ss);
  OQS_KEM_free(kem);
}

/* -----------------------------------------------------------------------
 * Worker thread entry point
 * Pins itself to Core 1, then sleeps on condvar until work arrives.
 * ----------------------------------------------------------------------- */

static void *worker_thread_func(void *arg) {
  WorkerPool *pool = (WorkerPool *)arg;

  /* ── Pin worker to Core 1 ── */
  int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  if (n_cpus >= 2) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
      perror("[engine/worker] pthread_setaffinity_np(Core 1)");
    }
  }

  pool->worker_tid = (long)syscall(SYS_gettid);
  pool->worker_cpu = sched_getcpu();

  /* ── Event loop ── */
  while (1) {
    pthread_mutex_lock(&pool->mutex);
    while (!atomic_load(&pool->has_work) && !atomic_load(&pool->shutdown)) {
      pthread_cond_wait(&pool->wake_cond, &pool->mutex);
    }
    pthread_mutex_unlock(&pool->mutex);

    if (atomic_load(&pool->shutdown))
      break;

    /* Execute the KEM operation */
    perform_kem_operation(pool);

    /* Update affinity telemetry */
    pool->worker_cpu = sched_getcpu();

    /* Signal completion to main thread */
    pthread_mutex_lock(&pool->mutex);
    atomic_store(&pool->work_done, 1);
    atomic_store(&pool->has_work, 0);
    pthread_cond_signal(&pool->done_cond);
    pthread_mutex_unlock(&pool->mutex);
  }

  return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * ECDH helper — keygen + derive on the calling thread
 * ═══════════════════════════════════════════════════════════════════ */

static int perform_ecdh(int curve_id, uint8_t *secret, size_t *secret_len) {
  EVP_PKEY *our_key = crypto_generate_keypair(curve_id);
  EVP_PKEY *peer_key = crypto_generate_keypair(curve_id);

  if (!our_key || !peer_key) {
    if (our_key)
      EVP_PKEY_free(our_key);
    if (peer_key)
      EVP_PKEY_free(peer_key);
    return -1;
  }

  int rc = crypto_derive_ecdh_secret(our_key, peer_key, secret, secret_len);

  EVP_PKEY_free(our_key);
  EVP_PKEY_free(peer_key);
  return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * KEM helper — keygen + encaps/decaps on the calling thread
 * (used by the sequential path)
 * ═══════════════════════════════════════════════════════════════════ */

static int perform_kem_local(const char *kem_name, HandshakeRole role,
                             uint8_t *ss_out, size_t *ss_len) {
  OQS_KEM *kem = OQS_KEM_new(kem_name);
  if (!kem)
    return -1;

  uint8_t *pk = malloc(kem->length_public_key);
  uint8_t *sk = malloc(kem->length_secret_key);
  uint8_t *ct = malloc(kem->length_ciphertext);
  uint8_t *ss = malloc(kem->length_shared_secret);
  int rc = -1;

  if (!pk || !sk || !ct || !ss)
    goto done;

  if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS)
    goto done;

  if (role == ROLE_SERVER) {
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS)
      goto done;
  } else {
    /* Client: encaps (simulate server) then decaps */
    uint8_t *ss_tmp = malloc(kem->length_shared_secret);
    if (!ss_tmp)
      goto done;

    if (OQS_KEM_encaps(kem, ct, ss_tmp, pk) != OQS_SUCCESS) {
      free(ss_tmp);
      goto done;
    }
    free(ss_tmp);

    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS)
      goto done;
  }

  size_t copy_len = kem->length_shared_secret;
  if (copy_len > 64)
    copy_len = 64;
  memcpy(ss_out, ss, copy_len);
  *ss_len = copy_len;
  rc = 0;

done:
  free(pk);
  free(sk);
  free(ct);
  free(ss);
  OQS_KEM_free(kem);
  return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * Public API: Lifecycle
 * ═══════════════════════════════════════════════════════════════════ */

int engine_init(void) {
  if (g_engine_initialized)
    return 0;

  memset(&g_pool, 0, sizeof(g_pool));

  pthread_mutex_init(&g_pool.mutex, NULL);
  pthread_cond_init(&g_pool.wake_cond, NULL);
  pthread_cond_init(&g_pool.done_cond, NULL);

  atomic_store(&g_pool.has_work, 0);
  atomic_store(&g_pool.work_done, 0);
  atomic_store(&g_pool.shutdown, 0);

  if (pthread_create(&g_pool.thread, NULL, worker_thread_func, &g_pool) != 0) {
    perror("engine_init: pthread_create");
    return -1;
  }

  /*
   * Allow the worker thread to start, pin itself, and enter the
   * condvar wait loop.  10 ms is more than sufficient on any
   * modern kernel — this is a one-time startup cost.
   */
  usleep(10000);

  g_engine_initialized = 1;
  return 0;
}

void engine_shutdown(void) {
  if (!g_engine_initialized)
    return;

  /* Signal worker to exit */
  pthread_mutex_lock(&g_pool.mutex);
  atomic_store(&g_pool.shutdown, 1);
  pthread_cond_signal(&g_pool.wake_cond);
  pthread_mutex_unlock(&g_pool.mutex);

  pthread_join(g_pool.thread, NULL);

  pthread_mutex_destroy(&g_pool.mutex);
  pthread_cond_destroy(&g_pool.wake_cond);
  pthread_cond_destroy(&g_pool.done_cond);

  g_engine_initialized = 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Public API: Sequential Execution
 * ═══════════════════════════════════════════════════════════════════ */

int execute_sequential(const AlgoCombo *combo, HandshakeRole role,
                       SharedCryptoResult *result) {
  memset(result, 0, sizeof(*result));

  /* ── Pure Classical: ECDH only ── */
  if (combo->profile == PROFILE_PURE_CLASSICAL || combo->pqc_alg == PQC_NONE) {
    result->ecdh_ok = (perform_ecdh(combo->classical_curve, result->ecdh_secret,
                                    &result->ecdh_secret_len) == 0);
    return result->ecdh_ok ? 0 : -1;
  }

  /* ── Pure Quantum: KEM only ── */
  if (combo->profile == PROFILE_PURE_QUANTUM ||
      combo->classical_curve == CURVE_NONE) {
    result->kem_ok =
        (perform_kem_local(combo->pqc_name, role, result->kem_shared_secret,
                           &result->kem_shared_secret_len) == 0);
    return result->kem_ok ? 0 : -1;
  }

  /* ── Hybrid: ECDH → KEM (back-to-back, same thread, L1-hot) ── */
  result->ecdh_ok = (perform_ecdh(combo->classical_curve, result->ecdh_secret,
                                  &result->ecdh_secret_len) == 0);
  if (!result->ecdh_ok)
    return -1;

  result->kem_ok =
      (perform_kem_local(combo->pqc_name, role, result->kem_shared_secret,
                         &result->kem_shared_secret_len) == 0);

  return (result->ecdh_ok && result->kem_ok) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * Public API: Parallel Execution with Core Pinning
 * ═══════════════════════════════════════════════════════════════════ */

int execute_parallel_optimized(const AlgoCombo *combo, HandshakeRole role,
                               SharedCryptoResult *result) {
  if (!g_engine_initialized) {
    fprintf(stderr, "[engine] ERROR: engine not initialised — "
                    "call engine_init() first\n");
    return -1;
  }

  memset(result, 0, sizeof(*result));

  /* Non-hybrid profiles have no parallelism benefit → fallback */
  if (combo->pqc_alg == PQC_NONE || combo->classical_curve == CURVE_NONE) {
    return execute_sequential(combo, role, result);
  }

  /* ── Pin main thread to Core 0 ── */
  int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  if (n_cpus >= 2) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
  }

  /* ── Dispatch KEM work to pre-warmed worker (Core 1) ── */
  pthread_mutex_lock(&g_pool.mutex);
  g_pool.kem_alg_name = combo->pqc_name;
  g_pool.role = role;
  g_pool.kem_ok = 0;
  g_pool.kem_shared_secret_len = 0;
  atomic_store(&g_pool.work_done, 0);
  atomic_store(&g_pool.has_work, 1);
  pthread_cond_signal(&g_pool.wake_cond); /* Instant wake */
  pthread_mutex_unlock(&g_pool.mutex);

  /* ── Main thread (Core 0): ECDH keygen + derive ── */
  result->ecdh_ok = (perform_ecdh(combo->classical_curve, result->ecdh_secret,
                                  &result->ecdh_secret_len) == 0);

  /* ── Wait for worker to complete KEM ── */
  pthread_mutex_lock(&g_pool.mutex);
  while (!atomic_load(&g_pool.work_done))
    pthread_cond_wait(&g_pool.done_cond, &g_pool.mutex);
  pthread_mutex_unlock(&g_pool.mutex);

  /* ── Join results from shared memory struct ── */
  memcpy(result->kem_shared_secret, g_pool.kem_shared_secret,
         g_pool.kem_shared_secret_len);
  result->kem_shared_secret_len = g_pool.kem_shared_secret_len;
  result->kem_ok = g_pool.kem_ok;

  return (result->ecdh_ok && result->kem_ok) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * Public API: Affinity Verification
 * ═══════════════════════════════════════════════════════════════════ */

int verify_affinity(AffinityProbe *probe) {
  if (!g_engine_initialized || !probe)
    return -1;

  /* Pin main to Core 0 to get a clean reading */
  int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  if (n_cpus >= 2) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
  }

  probe->main_thread_cpu = sched_getcpu();
  probe->main_thread_tid = (long)syscall(SYS_gettid);
  probe->worker_thread_cpu = g_pool.worker_cpu;
  probe->worker_thread_tid = g_pool.worker_tid;

  return 0;
}
