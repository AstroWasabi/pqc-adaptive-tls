/* c/include/algo_config.h
 * Algorithm combo table — equivalent to config/algorithms.py.
 * Defines all hybrid, pure-classical, and pure-quantum profiles
 * used throughout the benchmark framework.
 */
#pragma once

#include <stddef.h>

/* --- Profile type constants --- */
#define PROFILE_HYBRID          0
#define PROFILE_PURE_CLASSICAL  1
#define PROFILE_PURE_QUANTUM    2

/* --- Classical curve identifiers --- */
#define CURVE_NONE   0
#define CURVE_X25519 1
#define CURVE_P256   2
#define CURVE_P384   3

/* --- PQC algorithm identifiers --- */
#define PQC_NONE           0
#define PQC_MLKEM_768      1
#define PQC_MLKEM_1024     2
#define PQC_FRODOKEM_1344  3
#define PQC_BIKE_L5        4

/* --- liboqs algorithm name strings --- */
#define OQS_MLKEM_768_NAME       "ML-KEM-768"
#define OQS_MLKEM_1024_NAME      "ML-KEM-1024"
#define OQS_FRODOKEM_1344_NAME   "FrodoKEM-1344-AES"
#define OQS_BIKE_L5_NAME         "BIKE-L5"

typedef struct {
    int         id;
    const char *label;
    int         profile;        /* PROFILE_* constant */
    int         classical_curve;/* CURVE_* constant   */
    int         pqc_alg;        /* PQC_* constant     */
    const char *pqc_name;       /* OQS method string or NULL */
    const char *info;           /* HKDF/BLAKE3 info label    */
} AlgoCombo;

/* Full algorithm table — matches Python ALGORITHM_COMBOS exactly */
static const AlgoCombo ALGORITHM_COMBOS[] = {
    /* id  label                               profile                  classical       pqc                 pqc_name                 info */
    {  1, "Hybrid: X25519 + ML-KEM-768",       PROFILE_HYBRID,          CURVE_X25519,   PQC_MLKEM_768,      OQS_MLKEM_768_NAME,      "Hybrid-X25519-MLKEM768-v1"   },
    {  2, "Hybrid: SecP256r1 + ML-KEM-768",    PROFILE_HYBRID,          CURVE_P256,     PQC_MLKEM_768,      OQS_MLKEM_768_NAME,      "Hybrid-P256-MLKEM768-v1"     },
    {  3, "Hybrid: SecP384r1 + ML-KEM-1024",   PROFILE_HYBRID,          CURVE_P384,     PQC_MLKEM_1024,     OQS_MLKEM_1024_NAME,     "Hybrid-P384-MLKEM1024-v1"    },
    {  9, "Hybrid: SecP384r1 + FrodoKEM-1344", PROFILE_HYBRID,          CURVE_P384,     PQC_FRODOKEM_1344,  OQS_FRODOKEM_1344_NAME,  "Hybrid-P384-Frodo1344-v1"    },
    { 10, "Hybrid: SecP384r1 + BIKE-L5",       PROFILE_HYBRID,          CURVE_P384,     PQC_BIKE_L5,        OQS_BIKE_L5_NAME,        "Hybrid-P384-BIKEL5-v1"       },
    {  4, "Pure Classical: X25519",             PROFILE_PURE_CLASSICAL,  CURVE_X25519,   PQC_NONE,           NULL,                    "Pure-Classical-X25519-v1"    },
    {  5, "Pure Classical: SecP256r1",          PROFILE_PURE_CLASSICAL,  CURVE_P256,     PQC_NONE,           NULL,                    "Pure-Classical-P256-v1"      },
    {  8, "Pure Classical: SecP384r1",          PROFILE_PURE_CLASSICAL,  CURVE_P384,     PQC_NONE,           NULL,                    "Pure-Classical-P384-v1"      },
    {  6, "Pure Quantum: ML-KEM-768",           PROFILE_PURE_QUANTUM,    CURVE_NONE,     PQC_MLKEM_768,      OQS_MLKEM_768_NAME,      "Pure-Quantum-MLKEM768-v1"    },
    {  7, "Pure Quantum: ML-KEM-1024",          PROFILE_PURE_QUANTUM,    CURVE_NONE,     PQC_MLKEM_1024,     OQS_MLKEM_1024_NAME,     "Pure-Quantum-MLKEM1024-v1"   },
};

#define NUM_ALGO_COMBOS ((int)(sizeof(ALGORITHM_COMBOS) / sizeof(ALGORITHM_COMBOS[0])))

/* Returns pointer to combo with matching id, or NULL if not found. */
static inline const AlgoCombo *get_combo_by_id(int combo_id)
{
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].id == combo_id)
            return &ALGORITHM_COMBOS[i];
    }
    return NULL;
}

/* Returns human-readable curve name string for display/JSON. */
static inline const char *curve_name_str(int curve)
{
    switch (curve) {
        case CURVE_X25519: return "X25519";
        case CURVE_P256:   return "P256";
        case CURVE_P384:   return "P384";
        default:           return "NONE";
    }
}
