/* c_dispatch/include/dispatcher.h
 * Phase 4: The Adaptive Router
 *
 * Intercepts the handshake immediately before the cryptographic
 * execution phase and routes to the optimal engine based on:
 *
 *   1. Host telemetry (virtualized? core count?)
 *   2. Cipher suite weight (lightweight vs heavy)
 *
 * Routing Rules:
 *   → Sequential: Non-hybrid, VM with ≤2 cores, or lightweight (X25519) on low-core/VM
 *   → Parallel:   Bare-metal with ≥8 cores (all hybrids), or ≥3 cores with medium/heavy (P-256/P-384)
 */

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "algo_config.h"
#include "engine.h"

/* -----------------------------------------------------------------------
 * Route Decision
 * ----------------------------------------------------------------------- */

typedef enum {
    ROUTE_SEQUENTIAL,   /* execute_sequential()             */
    ROUTE_PARALLEL      /* execute_parallel_optimized()     */
} DispatchRoute;

/**
 * Evaluate routing decision for a given cipher suite.
 * Reads the global HostProfile to factor in environment telemetry.
 *
 * @param combo  Cipher suite to evaluate
 * @returns      ROUTE_SEQUENTIAL or ROUTE_PARALLEL
 */
DispatchRoute adaptive_dispatch(const AlgoCombo *combo);

/**
 * Execute the cipher suite through the adaptively chosen engine.
 * Combines adaptive_dispatch() + engine invocation in one call.
 *
 * @param combo   Cipher suite descriptor
 * @param role    CLIENT or SERVER
 * @param result  Output struct for shared secrets
 * @returns       0 on success, -1 on failure
 */
int dispatch_execute(const AlgoCombo *combo, HandshakeRole role,
                     SharedCryptoResult *result);

/**
 * Human-readable name for a dispatch route.
 */
const char *route_name(DispatchRoute route);

#endif /* DISPATCHER_H */
