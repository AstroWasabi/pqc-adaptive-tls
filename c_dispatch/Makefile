# c_dispatch/Makefile
# ═══════════════════════════════════════════════════════════════════
# Build system for pqc-adaptive-tls (Linux / POSIX)
# Adaptive Client-Side Parallel Hybrid Post-Quantum TLS 1.3
# ═══════════════════════════════════════════════════════════════════

# ─── liboqs detection (Standard Linux /usr, /usr/local, or custom) ───
LIBOQS_DIR ?= $(wildcard /home/sudoroot/_oqs)
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := $(wildcard /usr/local)
endif
ifeq ($(LIBOQS_DIR),)
  LIBOQS_DIR := /usr
endif

LIBOQS_LIB_DIR := $(wildcard $(LIBOQS_DIR)/lib64)
ifeq ($(LIBOQS_LIB_DIR),)
  LIBOQS_LIB_DIR := $(LIBOQS_DIR)/lib
endif

# ─── OpenSSL 3.x detection (Linux standard) ───────────────────────
OPENSSL_DIR ?= /usr
OPENSSL_INC := $(OPENSSL_DIR)/include
OPENSSL_LIB := $(wildcard $(OPENSSL_DIR)/lib64)
ifeq ($(OPENSSL_LIB),)
  OPENSSL_LIB := $(OPENSSL_DIR)/lib
endif

# ─── Vendored library directories ─────────────────────────────────
BLAKE3_DIR := ./vendor/blake3
CJSON_DIR  := ./vendor/cjson

# ─── Compiler / Flags ─────────────────────────────────────────────
CC      := gcc
CFLAGS  := -Wall -Wextra -O3 -std=c11 -pthread \
           -D_GNU_SOURCE \
           -I./include \
           -I$(BLAKE3_DIR) \
           -I$(CJSON_DIR) \
           -I$(OPENSSL_INC) \
           -I$(LIBOQS_DIR)/include

LDFLAGS := -L$(LIBOQS_LIB_DIR) \
           -L$(OPENSSL_LIB) \
           -Wl,-rpath,$(LIBOQS_LIB_DIR) \
           -loqs -lssl -lcrypto -lpthread -lm

.DEFAULT_GOAL := all

# ─── BLAKE3 objects (x86-64 Linux SIMD) ───────────────────────────
BLAKE3_CORE_SRCS := $(BLAKE3_DIR)/blake3.c \
                    $(BLAKE3_DIR)/blake3_dispatch.c \
                    $(BLAKE3_DIR)/blake3_portable.c

BLAKE3_CORE_OBJS := $(BLAKE3_CORE_SRCS:.c=.o)

$(BLAKE3_DIR)/blake3_sse2.o: $(BLAKE3_DIR)/blake3_sse2.c
	$(CC) $(CFLAGS) -msse2 -c $< -o $@

$(BLAKE3_DIR)/blake3_sse41.o: $(BLAKE3_DIR)/blake3_sse41.c
	$(CC) $(CFLAGS) -msse4.1 -c $< -o $@

$(BLAKE3_DIR)/blake3_avx2.o: $(BLAKE3_DIR)/blake3_avx2.c
	$(CC) $(CFLAGS) -mavx2 -c $< -o $@

$(BLAKE3_DIR)/blake3_avx512.o: $(BLAKE3_DIR)/blake3_avx512.c
	$(CC) $(CFLAGS) -mavx512f -mavx512vl -c $< -o $@

BLAKE3_SIMD_OBJS := $(BLAKE3_DIR)/blake3_sse2.o \
                    $(BLAKE3_DIR)/blake3_sse41.o \
                    $(BLAKE3_DIR)/blake3_avx2.o \
                    $(BLAKE3_DIR)/blake3_avx512.o

BLAKE3_OBJS := $(BLAKE3_CORE_OBJS) $(BLAKE3_SIMD_OBJS)

# ─── cJSON ────────────────────────────────────────────────────────
CJSON_SRCS := $(CJSON_DIR)/cJSON.c
CJSON_OBJS := $(CJSON_SRCS:.c=.o)

# ─── Dispatch runtime core ───────────────────────────────────────
DISPATCH_SRCS := src/telemetry.c \
                 src/engine.c \
                 src/dispatcher.c \
                 src/crypto_engine.c \
                 src/network_utils.c \
                 src/key_pool.c

DISPATCH_OBJS := $(DISPATCH_SRCS:.c=.o)

# ─── All common objects ──────────────────────────────────────────
ALL_COMMON := $(DISPATCH_OBJS) $(BLAKE3_OBJS) $(CJSON_OBJS)

# ─── Generic compile rule ────────────────────────────────────────
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ─── Targets ─────────────────────────────────────────────────────
.PHONY: all clean test test-asan test-tsan

all: server bench_e2e benchmark_suite bench_prims test_key_pool test_hybrid_kem
	@echo ""
	@echo "═══════════════════════════════════════════════════════"
	@echo "  Build complete (Linux):"
	@echo "    ./server           — Adaptive Dispatch TLS Server"
	@echo "    ./bench_e2e        — End-to-End Network Benchmark"
	@echo "    ./benchmark_suite  — Local Handshake Benchmark"
	@echo "    ./bench_prims      — Cryptographic Primitives Benchmark"
	@echo "    ./test_key_pool    — Key Pool Unit Test"
	@echo "    ./test_hybrid_kem  — Hybrid KEM Verification Test"
	@echo "═══════════════════════════════════════════════════════"

server: server.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_e2e: bench_e2e.o client.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

benchmark_suite: benchmark_suite.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_prims: bench_prims.o
	$(CC) -o $@ $^ $(LDFLAGS)

tests/test_key_pool.o: tests/test_key_pool.c
	$(CC) $(CFLAGS) -c $< -o $@

test_key_pool: tests/test_key_pool.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

tests/test_hybrid_kem.o: tests/test_hybrid_kem.c
	$(CC) $(CFLAGS) -c $< -o $@

test_hybrid_kem: tests/test_hybrid_kem.o $(ALL_COMMON)
	$(CC) -o $@ $^ $(LDFLAGS)

test: test_key_pool test_hybrid_kem
	@echo "Running tests..."
	./test_key_pool
	./test_hybrid_kem

clean:
	rm -f server bench_e2e benchmark_suite bench_prims test_key_pool test_hybrid_kem
	rm -f *.o src/*.o tests/*.o $(BLAKE3_DIR)/*.o $(CJSON_DIR)/*.o
	rm -f host_profile.json benchmark_results.json e2e_benchmark_results.json
	rm -f *.log
	@echo "Cleaned."
