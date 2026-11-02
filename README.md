# Client-Side Parallel Hybrid Post-Quantum Key Exchange with Pre-Computed Key Pool

[![Standard](https://img.shields.io/badge/TLS%201.3-RFC%208446%20%2F%20RFC%209954-blue.svg)](https://datatracker.ietf.org/doc/rfc9954/)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%20%2F%20ML--KEM-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![C Standard](https://img.shields.io/badge/C-C11-green.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An adaptive, client-side parallel cryptographic execution runtime and pre-computed ephemeral key pool for **Hybrid Post-Quantum TLS 1.3 Key Exchange**, built upon **OpenSSL ≥ 3.0** and **liboqs**.

---

## 1. Research Motivation & Core Architecture

Transitioning TLS 1.3 to post-quantum security requires **Hybrid Key Exchange** (e.g., ECDH concatenated with ML-KEM, FrodoKEM, or BIKE). However, evaluating hybrid handshakes reveals two major performance bottlenecks:

1. **Client-Side Initialization Spike (Phase A - Pre-ClientHello):** Generating both classical and post-quantum ephemeral keys introduces a substantial connection preparation delay before any byte is placed on the wire (up to $6\times$ latency overhead, Gómez-Cambronero et al., 2026).
2. **Interactive In-Flight Cryptographic Stall (Phase B - Post-ServerHello):** Computing classical ECDH scalar point multiplication while concurrently waiting on heavy PQC decapsulation (especially in NIST Level 5 suites like `SecP384r1 + FrodoKEM-1344` or `BIKE-L5`).

```
                              CLIENT CRITICAL PATH
  ┌────────────────────────────────────────────────────────────────────────┐
  │ PHASE A: Pre-ClientHello (Key Share Acquisition)                       │
  │ • Pool Hit:  Instant O(1) pop (< 5 µs) from pre-computed key pool      │
  │ • Pool Miss: Dynamic Route -> [EC Keygen || KEM Keygen] in parallel     │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ ClientHello (c_pub || pqc_pk)
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ SERVER EXECUTION (Sequential & Throughput-Optimized)                   │
  │ • Generates ephemeral EC keypair                                       │
  │ • Derives ECDH shared secret                                           │
  │ • Encapsulates KEM ciphertext against client pqc_pk                    │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ ServerHello (srv_pub || pqc_ct)
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ PHASE B: Post-ServerHello (In-Flight Interactive Phase)                │
  │ • Cost-Model Router dynamically selects execution pathway:             │
  │   - ROUTE_SEQUENTIAL: Single-core, low-vCPU VMs, or high CPU pressure │
  │   - ROUTE_PARALLEL:   Main (Core 0: ECDH) || Worker (Core 1: Decaps)   │
  │ • Shared Secret Derivation via RFC 9954 Fail-Closed Combiner           │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Structure

```
pqc-adaptive-tls/
├── c_dispatch/                     # Core C11 Dispatch Engine
│   ├── include/                    # Header declarations
│   │   ├── algo_config.h           # Hybrid cipher suite definitions
│   │   ├── crypto_engine.h         # OpenSSL & BLAKE3 wrappers
│   │   ├── dispatcher.h            # Cost-model adaptive router
│   │   ├── engine.h                # Sequential vs. core-pinned worker pool
│   │   ├── key_pool.h              # Pre-computed ephemeral key pool
│   │   ├── network_utils.h         # Binary wire framing (TLS 1.3 aligned)
│   │   └── telemetry.h             # Hardware & CPU pressure (PSI) profiler
│   ├── src/                        # Implementations
│   ├── tests/                      # Standalone test & verification harnesses
│   ├── vendor/                     # BLAKE3 & cJSON vendored dependencies
│   ├── client.c / server.c         # End-to-end socket binaries
│   ├── bench_e2e.c                 # Real-network client benchmarking
│   ├── benchmark_suite.c           # Micro-architectural latency evaluation
│   ├── bench_prims.c               # Isolated cryptographic primitive profiling
│   └── Makefile                    # Unified build & test recipes
├── experiments/                    # Automated multi-factor experiment runners
├── analysis/                       # Python statistical data reduction & plotting
├── results/                        # Raw CSV benchmark outputs
└── docs/                           # Architecture specs & action plan
```

---

## 3. Supported Hybrid Cipher Suites

| ID | Classical Curve | Post-Quantum KEM | Security Level | Purpose / Characteristics |
|:---|:---|:---|:---:|:---|
| `1` | **X25519** | **ML-KEM-768** | NIST Level 1/3 | Ultra-fast web traffic (Control case) |
| `3` | **SecP384r1** | **ML-KEM-1024** | NIST Level 5 | CNSA 2.0 High-Security government grade |
| `9` | **SecP384r1** | **FrodoKEM-1344-AES** | NIST Level 5 | Unstructured lattice / Conservative security |
| `10` | **SecP384r1** | **BIKE-L5** | NIST Level 5 | Code-based alternative PQC security |

---

## 4. Build Instructions

### Prerequisites
- GCC or Clang with C11 support and POSIX threads (`pthreads`)
- OpenSSL development headers (≥ 3.0) (`libssl-dev`, `libcrypto`)
- `liboqs` (Open Quantum Safe C library) installed on the system

### Compilation
```bash
cd c_dispatch

# Build all binaries
make all

# Run unit tests
make test
```
