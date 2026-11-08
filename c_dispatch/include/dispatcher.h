/* c_dispatch/include/dispatcher.h
 * Phase 4: The Adaptive Router
 *
 * Evaluates routing decision for a given cipher suite based on:
 *   1. Host telemetry (virtualized? core count?)
 *   2. Cipher suite weight (lightweight vs heavy)
 */

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "algo_config.h"
#include "engine.h"

/**
 * Evaluate routing decision for a given cipher suite.
 * Reads the global HostProfile to factor in environment telemetry.
 *
 * @param combo  Cipher suite to evaluate
 * @returns      ROUTE_SEQUENTIAL or ROUTE_PARALLEL
 */
DispatchRoute adaptive_dispatch(const AlgoCombo *combo);

/**
 * Human-readable name for a dispatch route.
 */
const char *route_name(DispatchRoute route);

#endif /* DISPATCHER_H */
