/* c_dispatch/include/engine.h
 * ═══════════════════════════════════════════════════════════════════
 * Adaptive Execution Engine for Hybrid Post-Quantum TLS 1.3
 *
 * Implements two distinct critical path phases:
 *
 * Phase A: engine_client_keygen()
 *   - Classical EC Keygen || PQC KEM Keygen
 *   - Bypassed entirely when Key Pool has a ready-to-use share!
 *
 * Phase B: engine_client_finish()
 *   - Classical ECDH Derive || PQC KEM Decapsulate
 *   - Overlaps curve scalar multiplication with heavy KEM math.
 * ═══════════════════════════════════════════════════════════════════
 */

#ifndef ENGINE_H
#define ENGINE_H

#include "algo_config.h"
#include "key_pool.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ROUTE_SEQUENTIAL,   /* Execute inline on calling thread */
    ROUTE_PARALLEL      /* Execute with core-pinned persistent worker */
} DispatchRoute;

/* Output results of Phase B (Shared Secret Derivation) */
typedef struct {
    uint8_t  ecdh_secret[48];          /* Classical shared secret */
    size_t   ecdh_secret_len;
    uint8_t  kem_shared_secret[64];    /* KEM shared secret */
    size_t   kem_shared_secret_len;
    int      ecdh_ok;
    int      kem_ok;
    int      fell_back;                /* 1 if parallel fell back to sequential */
} SharedCryptoResult;

typedef struct {
    int  main_thread_cpu;
    long main_thread_tid;
    int  worker_thread_cpu;
    long worker_thread_tid;
} AffinityProbe;

int  engine_init(void);
void engine_shutdown(void);
int  verify_affinity(AffinityProbe *probe);

/**
 * Phase A: Generate a fresh client key share (EC keypair + KEM keypair).
 *
 * @param combo      Cipher suite descriptor
 * @param route      ROUTE_SEQUENTIAL or ROUTE_PARALLEL
 * @param out_share  Output key share
 * @param fell_back  Output fallback flag
 * @returns          0 on success, -1 on failure
 */
int engine_client_keygen(const AlgoCombo *combo, DispatchRoute route,
                         ClientKeyShare *out_share, int *fell_back);

/**
 * Phase B: Finish key exchange (Derive ECDH secret and Decapsulate KEM).
 *
 * @param combo        Cipher suite descriptor
 * @param route        ROUTE_SEQUENTIAL or ROUTE_PARALLEL
 * @param ks           Client's key share from Phase A
 * @param srv_pub      Server's classical public key
 * @param srv_pub_len  Length of server's classical public key
 * @param ct           Server's PQC ciphertext
 * @param ct_len       Length of ciphertext
 * @param out_result   Output derived shared secrets
 * @returns            0 on success, -1 on failure
 */
int engine_client_finish(const AlgoCombo *combo, DispatchRoute route,
                         const ClientKeyShare *ks,
                         const uint8_t *srv_pub, size_t srv_pub_len,
                         const uint8_t *ct, size_t ct_len,
                         SharedCryptoResult *out_result);

#endif /* ENGINE_H */
