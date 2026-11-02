/* c_dispatch/include/engine.h
 * Phase 3: The Execution Engine
 *
 * Provides two execution strategies for TLS 1.3 hybrid PQC:
 *
 * 1. execute_sequential()
 *    Runs ECDH_Derive then ML_KEM_Op back-to-back on the calling thread.
 *    Guarantees zero OS scheduler overhead and preserves L1 cache locality.
 *
 * 2. execute_parallel_optimized()
 *    Uses a persistent, pre-warmed worker thread pinned to Core 1.
 *    Main thread (Core 0) computes ECDH while worker computes KEM.
 *    Synchronisation via pthread_cond_t for instant wake.
 *
 * Protocol Alignment (RFC 9954):
 *   Client path: ECDH_Derive || ML_KEM_Decapsulate
 *   Server path: ECDH_Derive || ML_KEM_Encapsulate
 */

#ifndef ENGINE_H
#define ENGINE_H

#include "algo_config.h"
#include <stddef.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * TLS 1.3 Handshake Role (determines KEM operation)
 * ----------------------------------------------------------------------- */

typedef enum {
    ROLE_CLIENT,   /* ECDH_Derive || ML_KEM_Decapsulate */
    ROLE_SERVER    /* ECDH_Derive || ML_KEM_Encapsulate */
} HandshakeRole;

/* -----------------------------------------------------------------------
 * Shared result struct — joined after parallel execution
 * ----------------------------------------------------------------------- */

typedef struct {
    uint8_t  ecdh_secret[48];          /* Max P-384 shared secret = 48 bytes */
    size_t   ecdh_secret_len;
    uint8_t  kem_shared_secret[64];    /* ML-KEM shared secret              */
    size_t   kem_shared_secret_len;
    int      ecdh_ok;                  /* 1 = ECDH derivation succeeded     */
    int      kem_ok;                   /* 1 = KEM operation succeeded       */
} SharedCryptoResult;

/* -----------------------------------------------------------------------
 * Affinity verification probe
 * ----------------------------------------------------------------------- */

typedef struct {
    int  main_thread_cpu;      /* CPU core ID of main thread (sched_getcpu) */
    int  worker_thread_cpu;    /* CPU core ID of worker thread              */
    long main_thread_tid;      /* OS thread ID of main thread               */
    long worker_thread_tid;    /* OS thread ID of worker thread             */
} AffinityProbe;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * Initialize the persistent worker pool.
 * Creates one pre-warmed worker thread pinned to Core 1.
 * Must be called once before execute_parallel_optimized().
 *
 * @returns  0 on success, -1 on failure
 */
int engine_init(void);

/**
 * Shut down the worker pool and join the worker thread.
 */
void engine_shutdown(void);

/* -----------------------------------------------------------------------
 * Execution Strategies
 * ----------------------------------------------------------------------- */

/**
 * Sequential execution: ECDH then KEM on the calling thread.
 * Preserves L1 cache locality. Zero context-switch overhead.
 *
 * @param combo   Cipher suite descriptor
 * @param role    CLIENT or SERVER (selects encaps vs decaps)
 * @param result  Output struct for shared secrets
 * @returns       0 on success, -1 on failure
 */
int execute_sequential(const AlgoCombo *combo, HandshakeRole role,
                       SharedCryptoResult *result);

/**
 * Parallel execution with core-pinned worker.
 * Main thread (Core 0): ECDH keygen + derive.
 * Worker thread (Core 1): KEM keygen + encaps/decaps.
 * Results joined via SharedCryptoResult.
 *
 * Requires engine_init() to have been called.
 *
 * @param combo   Cipher suite descriptor
 * @param role    CLIENT or SERVER
 * @param result  Output struct for shared secrets
 * @returns       0 on success, -1 on failure
 */
int execute_parallel_optimized(const AlgoCombo *combo, HandshakeRole role,
                               SharedCryptoResult *result);

/* -----------------------------------------------------------------------
 * Verification
 * ----------------------------------------------------------------------- */

/**
 * Probe the current core assignments of main + worker threads.
 * Uses sched_getcpu() and SYS_gettid to populate the AffinityProbe.
 *
 * @param probe  Output struct
 * @returns      0 on success, -1 if engine not initialised
 */
int verify_affinity(AffinityProbe *probe);

#endif /* ENGINE_H */
