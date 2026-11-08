/* c_dispatch/src/dispatcher.c
 * Phase 4: The Adaptive Router
 */

#include "../include/dispatcher.h"
#include "../include/algo_config.h"
#include "../include/telemetry.h"

DispatchRoute adaptive_dispatch(const AlgoCombo *combo) {
  telemetry_refresh_dynamic();
  const HostProfile *hp = get_host_profile();

  /* Rule 1: Non-hybrid profiles have no concurrency benefit */
  if (combo->profile != PROFILE_HYBRID || combo->pqc_alg == PQC_NONE ||
      combo->classical_curve == CURVE_NONE)
    return ROUTE_SEQUENTIAL;

  /* Rule 2: Constrained topologies (single-core or low-vCPU VMs) */
  if (hp->logical_cores <= 1)
    return ROUTE_SEQUENTIAL;
  if (hp->is_virtualized && hp->logical_cores <= 2)
    return ROUTE_SEQUENTIAL;

  /* Rule 3: Dynamic CPU Contention / High Load Backoff */
  if (hp->is_congested || hp->load_per_core >= 0.80)
    return ROUTE_SEQUENTIAL;

  /* Rule 4: Lightweight hybrid suite (X25519 + ML-KEM-768) */
  if (combo->classical_curve == CURVE_X25519 && combo->pqc_alg == PQC_MLKEM_768)
    return ROUTE_SEQUENTIAL;

  /* Rule 5: Medium and Heavy hybrid suites on multi-core hosts */
  if (hp->logical_cores >= 2)
    return ROUTE_PARALLEL;

  return ROUTE_SEQUENTIAL;
}

const char *route_name(DispatchRoute route) {
  switch (route) {
  case ROUTE_SEQUENTIAL:
    return "Sequential";
  case ROUTE_PARALLEL:
    return "Parallel";
  default:
    return "Unknown";
  }
}
