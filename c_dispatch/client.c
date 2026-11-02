/* c_dispatch/client.c
 * ═══════════════════════════════════════════════════════════════════
 * Adaptive Dispatch TLS 1.3 Hybrid PQC Client
 *
 * Performs an end-to-end handshake with the dispatch server.
 * Wire protocol matches c/client.c exactly, with the addition of
 * an optional "dispatch_mode" field in ProfileSelect.
 *
 * Timing: starts AFTER TCP connection is established (isolates crypto
 * from TCP connect latency), ends after receiving ServerFinished.
 *
 * Protocol Alignment (RFC 9954):
 *   Client parallel step: ECDH_Derive || ML_KEM_Encapsulate
 *   (Client encapsulates using server's PQC public key)
 * ═══════════════════════════════════════════════════════════════════
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/dispatcher.h"
#include "include/engine.h"
#include "include/network_utils.h"
#include "include/telemetry.h"
#include "include/key_pool.h"

#include <oqs/oqs.h>

int g_client_use_key_pool = 0;
double g_last_ch_prep_ms = 0.0;

#define SERVER_PORT  4444
#define STATIC_SALT  "IEICE-Kyoto-Conference-2026"

#define MAX_PUB_KEY_BYTES  300
#define MAX_SHARED_SEC     64
#define MAX_IKM_BYTES      200

/* ═══════════════════════════════════════════════════════════════════
 * Timing helper
 * ═══════════════════════════════════════════════════════════════════ */

static inline double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ═══════════════════════════════════════════════════════════════════
 * Client PQC encapsulation worker (for parallel dispatch)
 *
 * The client's parallel step computes ML_KEM_Encapsulate using the
 * server's PQC public key while the main thread concurrently
 * computes ECDH_Derive.
 * ═══════════════════════════════════════════════════════════════════ */

/* ── PRE-EXISTING CODE COMMENTED OUT: ──
typedef struct {
    const char *pqc_name;
    const char *q_pk_b64;
    uint8_t    *q_secret;
    size_t     *q_secret_len;
    uint8_t   **ct_out;
    size_t     *ct_len_out;
    int         success;
} PQCEncapsArgs_Legacy;
── END PRE-EXISTING CODE ── */

/* ── NEW DEFINITION: supports raw binary wire public key & base64 fallback ── */
typedef struct {
    const char    *pqc_name;
    const char    *q_pk_b64;   /* Server's PQC public key (base64)     */
    const uint8_t *q_pk_raw;   /* Server's PQC public key (raw binary) */
    size_t         q_pk_raw_len;
    uint8_t       *q_secret;   /* Output: shared secret                */
    size_t        *q_secret_len;
    uint8_t      **ct_out;     /* Output: ciphertext (malloc'd)        */
    size_t        *ct_len_out;
    int            success;
} PQCEncapsArgs;

static void *client_pqc_encaps_worker(void *arg)
{
    PQCEncapsArgs *p = (PQCEncapsArgs *)arg;
    p->success = 0;

    OQS_KEM *kem = OQS_KEM_new(p->pqc_name);
    if (!kem) return NULL;

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    if (!ct || !ss) {
        free(ct); free(ss);
        OQS_KEM_free(kem); return NULL;
    }

    const uint8_t *pk = NULL;
    uint8_t *pk_allocated = NULL;

    if (p->q_pk_raw && p->q_pk_raw_len == kem->length_public_key) {
        /* Direct binary pointer — zero Base64 decoding, zero extra allocation */
        pk = p->q_pk_raw;
    } else if (p->q_pk_b64) {
        pk_allocated = malloc(kem->length_public_key);
        if (!pk_allocated) {
            free(ct); free(ss);
            OQS_KEM_free(kem); return NULL;
        }
        int pk_len = b64_decode(p->q_pk_b64, pk_allocated, kem->length_public_key);
        if (pk_len != (int)kem->length_public_key) {
            free(ct); free(ss); free(pk_allocated);
            OQS_KEM_free(kem); return NULL;
        }
        pk = pk_allocated;
    } else {
        free(ct); free(ss);
        OQS_KEM_free(kem); return NULL;
    }

    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
        free(ct); free(ss); free(pk_allocated);
        OQS_KEM_free(kem); return NULL;
    }

    *p->q_secret_len = kem->length_shared_secret;
    memcpy(p->q_secret, ss, kem->length_shared_secret);
    *p->ct_out     = ct;
    *p->ct_len_out = kem->length_ciphertext;

    free(ss); free(pk_allocated);
    OQS_KEM_free(kem);
    p->success = 1;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Pre-warmed Worker Pool for Client PQC Encapsulation
 * (Modeled after engine.c persistent worker pool)
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    pthread_t       thread;
    pthread_mutex_t mutex;
    pthread_cond_t  wake_cond;
    pthread_cond_t  done_cond;
    PQCEncapsArgs  *args;
    int             has_work;
    int             work_done;
    int             shutdown;
} ClientWorkerPool;

static ClientWorkerPool g_client_worker;
static int g_client_worker_initialized = 0;

static void *client_worker_loop(void *arg)
{
    ClientWorkerPool *pool = (ClientWorkerPool *)arg;

    /* Pin worker to Core 1 (matching engine.c) */
    int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus >= 2) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(1, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
            /* Affinity pinning fallback */
        }
    }

    while (1) {
        pthread_mutex_lock(&pool->mutex);
        while (!pool->has_work && !pool->shutdown) {
            pthread_cond_wait(&pool->wake_cond, &pool->mutex);
        }
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }
        PQCEncapsArgs *args = pool->args;
        pthread_mutex_unlock(&pool->mutex);

        if (args) {
            client_pqc_encaps_worker(args);
        }

        pthread_mutex_lock(&pool->mutex);
        pool->has_work = 0;
        pool->work_done = 1;
        pthread_cond_signal(&pool->done_cond);
        pthread_mutex_unlock(&pool->mutex);
    }
    return NULL;
}

void client_worker_shutdown(void)
{
    if (!g_client_worker_initialized) return;
    pthread_mutex_lock(&g_client_worker.mutex);
    g_client_worker.shutdown = 1;
    pthread_cond_signal(&g_client_worker.wake_cond);
    pthread_mutex_unlock(&g_client_worker.mutex);

    pthread_join(g_client_worker.thread, NULL);
    pthread_mutex_destroy(&g_client_worker.mutex);
    pthread_cond_destroy(&g_client_worker.wake_cond);
    pthread_cond_destroy(&g_client_worker.done_cond);
    g_client_worker_initialized = 0;
}

int client_worker_init(void)
{
    if (g_client_worker_initialized) return 0;
    memset(&g_client_worker, 0, sizeof(g_client_worker));
    pthread_mutex_init(&g_client_worker.mutex, NULL);
    pthread_cond_init(&g_client_worker.wake_cond, NULL);
    pthread_cond_init(&g_client_worker.done_cond, NULL);
    g_client_worker.has_work = 0;
    g_client_worker.work_done = 0;
    g_client_worker.shutdown = 0;

    if (pthread_create(&g_client_worker.thread, NULL, client_worker_loop, &g_client_worker) != 0) {
        perror("[client] pthread_create worker pool");
        return -1;
    }
    atexit(client_worker_shutdown);
    usleep(2000); /* 2ms warmup */
    g_client_worker_initialized = 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Execute a single end-to-end handshake
 *
 * Returns elapsed crypto time in milliseconds, or -1 on error.
 * ═══════════════════════════════════════════════════════════════════ */

/* ── PRE-EXISTING JSON-BASED HANDSHAKE (COMMENTED OUT): ──
double execute_dispatch_handshake_json(const char *host,
                                       const AlgoCombo *combo,
                                       const char *kdf_type,
                                       const char *dispatch_mode,
                                       DispatchRoute local_route)
{
    // Determine if we should send a salt
    int use_salt = (combo->profile == PROFILE_HYBRID &&
                    strcmp(kdf_type, "sha256") == 0);

    // TCP connect (NOT timed)
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1.0;

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, host, &srv.sin_addr);

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        close(fd); return -1.0;
    }

    // === Timing starts after TCP connect ===
    double t_start = now_ms();

    // Step 1: ProfileSelect
    {
        cJSON *sel = cJSON_CreateObject();
        cJSON_AddStringToObject(sel, "type", "ProfileSelect");
        cJSON_AddNumberToObject(sel, "combo_id", combo->id);
        cJSON_AddStringToObject(sel, "kdf_type", kdf_type);
        cJSON_AddStringToObject(sel, "dispatch_mode", dispatch_mode);
        if (use_salt) {
            char *salt_b64 = b64_encode((const uint8_t *)STATIC_SALT,
                                        strlen(STATIC_SALT));
            cJSON_AddStringToObject(sel, "salt", salt_b64);
            free(salt_b64);
        } else {
            cJSON_AddNullToObject(sel, "salt");
        }
        send_json_line(fd, sel);
        cJSON_Delete(sel);
    }

    // Step 2: Classical ClientHello (hybrid / pure_classical)
    EVP_PKEY *c_priv = NULL;
    uint8_t c_secret[MAX_SHARED_SEC] = {0};
    size_t c_secret_len = 0;

    if (combo->profile == PROFILE_HYBRID ||
        combo->profile == PROFILE_PURE_CLASSICAL) {

        c_priv = crypto_generate_keypair(combo->classical_curve);
        if (!c_priv) { close(fd); return -1.0; }

        uint8_t pub_buf[MAX_PUB_KEY_BYTES];
        size_t pub_len = 0;

        if (combo->classical_curve == CURVE_X25519)
            crypto_export_x25519_pub_raw(c_priv, pub_buf, &pub_len);
        else
            crypto_export_ec_pub_der(c_priv, pub_buf, &pub_len);

        char *pub_b64 = b64_encode(pub_buf, pub_len);
        cJSON *hello = cJSON_CreateObject();
        cJSON_AddStringToObject(hello, "type", "ClientHello");
        cJSON_AddStringToObject(hello, "c_pub", pub_b64);
        send_json_line(fd, hello);
        cJSON_Delete(hello);
        free(pub_b64);
    }

    // Step 3 & 4: Receive key material, derive secrets
    cJSON *resp = recv_json_line(fd);
    if (!resp) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }

    uint8_t q_secret[64] = {0};
    size_t q_secret_len = 0;
    uint8_t *pqc_ct = NULL;
    size_t pqc_ct_len = 0;

    if (combo->profile == PROFILE_HYBRID) {
        const char *q_pk_b64 = json_get_str(resp, "q_pk");
        if (!q_pk_b64) {
            if (c_priv) EVP_PKEY_free(c_priv);
            cJSON_Delete(resp); close(fd); return -1.0;
        }

        PQCEncapsArgs pqc_args = {
            .pqc_name     = combo->pqc_name,
            .q_pk_b64     = q_pk_b64,
            .q_secret     = q_secret,
            .q_secret_len = &q_secret_len,
            .ct_out       = &pqc_ct,
            .ct_len_out   = &pqc_ct_len,
            .success      = 0
        };

        client_pqc_encaps_worker(&pqc_args);

        const char *srv_cpub_b64 = json_get_str(resp, "c_pub");
        uint8_t srv_pub[MAX_PUB_KEY_BYTES];
        int srv_pub_len = srv_cpub_b64 ?
            b64_decode(srv_cpub_b64, srv_pub, sizeof(srv_pub)) : -1;

        if (srv_pub_len > 0) {
            EVP_PKEY *srv_pub_key =
                (combo->classical_curve == CURVE_X25519)
                    ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
                    : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);

            if (srv_pub_key) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(c_priv, srv_pub_key,
                                          c_secret, &c_secret_len);
                EVP_PKEY_free(srv_pub_key);
            }
        }
        if (c_priv) { EVP_PKEY_free(c_priv); c_priv = NULL; }

        if (!pqc_args.success || c_secret_len == 0) {
            free(pqc_ct);
            cJSON_Delete(resp); close(fd); return -1.0;
        }

        char *ct_b64 = b64_encode(pqc_ct, pqc_ct_len);
        cJSON *ct_msg = cJSON_CreateObject();
        cJSON_AddStringToObject(ct_msg, "type", "PQCCiphertext");
        cJSON_AddStringToObject(ct_msg, "ct", ct_b64);
        send_json_line(fd, ct_msg);
        cJSON_Delete(ct_msg);
        free(ct_b64);
        free(pqc_ct);
    }
    cJSON_Delete(resp);
    close(fd);
    return 0.0;
}
── END PRE-EXISTING JSON-BASED HANDSHAKE ── */

/* ═══════════════════════════════════════════════════════════════════
 * Execute a single end-to-end handshake
 * (Binary Wire Framing Edition — RFC 8446 / RFC 9954 Real-World Standard)
 * ═══════════════════════════════════════════════════════════════════ */

double execute_dispatch_handshake(const char *host,
                                  const AlgoCombo *combo,
                                  const char *kdf_type,
                                  const char *dispatch_mode,
                                  DispatchRoute local_route)
{
    /* ── TCP connect (NOT timed) ── */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1.0;

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, host, &srv.sin_addr);

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        close(fd); return -1.0;
    }

    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    /* === Timing starts after TCP connect === */
    double t_start = now_ms();

    /* ── Step 1: Classical Keypair & ClientHello (Binary Wire Protocol) ── */
    EVP_PKEY *c_priv = NULL;
    uint8_t pub_buf[MAX_PUB_KEY_BYTES];
    size_t pub_len = 0;

    double t_ch0 = now_ms();
    if (combo->profile == PROFILE_HYBRID || combo->profile == PROFILE_PURE_CLASSICAL) {
        if (g_client_use_key_pool) {
            if (key_pool_pop(combo->classical_curve, &c_priv, pub_buf, &pub_len) != 0 || !c_priv) {
                close(fd); return -1.0;
            }
        } else {
            c_priv = crypto_generate_keypair(combo->classical_curve);
            if (!c_priv) { close(fd); return -1.0; }

            if (combo->classical_curve == CURVE_X25519)
                crypto_export_x25519_pub_raw(c_priv, pub_buf, &pub_len);
            else
                crypto_export_ec_pub_der(c_priv, pub_buf, &pub_len);
        }
    }
    g_last_ch_prep_ms = now_ms() - t_ch0;

    /* Send Binary ClientHello in a single contiguous write to prevent TCP delayed-ACK */
    uint8_t kdf_code = (strcmp(kdf_type, "blake3") == 0) ? 1 : 0;
    uint8_t dmode_code = (strcmp(dispatch_mode, "sequential") == 0) ? 1 :
                         (strcmp(dispatch_mode, "parallel") == 0)   ? 2 : 0;

    ClientHelloMeta ch_meta = {
        .kdf_type      = kdf_code,
        .dispatch_mode = dmode_code,
        .c_pub_len     = (uint16_t)pub_len
    };

    WireHeader ch_hdr = {
        .magic       = htonl(WIRE_MAGIC),
        .msg_type    = htons(WIRE_MSG_CLIENT_HELLO),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(sizeof(ch_meta) + pub_len)
    };

    size_t ch_pkt_len = sizeof(WireHeader) + sizeof(ClientHelloMeta) + pub_len;
    uint8_t *ch_pkt = malloc(ch_pkt_len);
    if (!ch_pkt) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }
    memcpy(ch_pkt, &ch_hdr, sizeof(WireHeader));
    memcpy(ch_pkt + sizeof(WireHeader), &ch_meta, sizeof(ClientHelloMeta));
    if (pub_len > 0)
        memcpy(ch_pkt + sizeof(WireHeader) + sizeof(ClientHelloMeta), pub_buf, pub_len);

    int ch_rc = send_all(fd, ch_pkt, ch_pkt_len);
    free(ch_pkt);
    if (ch_rc != 0) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }

    /* ── Step 2: Receive ServerHello ── */
    WireHeader sh_hdr;
    if (recv_all(fd, &sh_hdr, sizeof(sh_hdr)) != 0 ||
        ntohl(sh_hdr.magic) != WIRE_MAGIC ||
        ntohs(sh_hdr.msg_type) != WIRE_MSG_SERVER_HELLO) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }

    ServerHelloMeta sh_meta;
    if (recv_all(fd, &sh_meta, sizeof(sh_meta)) != 0) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }

    uint16_t srv_pub_len = sh_meta.srv_pub_len;
    uint32_t pqc_pk_len  = sh_meta.pqc_pk_len;

    uint8_t srv_pub[MAX_PUB_KEY_BYTES];
    if (srv_pub_len > 0) {
        if (srv_pub_len > sizeof(srv_pub) ||
            recv_all(fd, srv_pub, srv_pub_len) != 0) {
            if (c_priv) EVP_PKEY_free(c_priv);
            close(fd); return -1.0;
        }
    }

    uint8_t *pqc_pk = NULL;
    if (pqc_pk_len > 0) {
        pqc_pk = malloc(pqc_pk_len);
        if (!pqc_pk || recv_all(fd, pqc_pk, pqc_pk_len) != 0) {
            free(pqc_pk);
            if (c_priv) EVP_PKEY_free(c_priv);
            close(fd); return -1.0;
        }
    }

    /* ── Step 3: Compute secrets (Parallel or Sequential dispatch) ── */
    uint8_t c_secret[MAX_SHARED_SEC] = {0};
    size_t c_secret_len = 0;
    uint8_t q_secret[64] = {0};
    size_t q_secret_len = 0;
    uint8_t *pqc_ct = NULL;
    size_t pqc_ct_len = 0;

    if (combo->profile == PROFILE_HYBRID) {
        PQCEncapsArgs pqc_args = {
            .pqc_name     = combo->pqc_name,
            .q_pk_b64     = NULL,
            .q_pk_raw     = pqc_pk,
            .q_pk_raw_len = pqc_pk_len,
            .q_secret     = q_secret,
            .q_secret_len = &q_secret_len,
            .ct_out       = &pqc_ct,
            .ct_len_out   = &pqc_ct_len,
            .success      = 0
        };

        int pqc_dispatched = 0;
        if (local_route == ROUTE_PARALLEL) {
            if (!g_client_worker_initialized) client_worker_init();
            if (g_client_worker_initialized) {
                int n_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
                if (n_cpus >= 2) {
                    cpu_set_t cpuset;
                    CPU_ZERO(&cpuset);
                    CPU_SET(0, &cpuset);
                    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
                }
                pthread_mutex_lock(&g_client_worker.mutex);
                g_client_worker.args = &pqc_args;
                g_client_worker.work_done = 0;
                g_client_worker.has_work = 1;
                pthread_cond_signal(&g_client_worker.wake_cond);
                pthread_mutex_unlock(&g_client_worker.mutex);
                pqc_dispatched = 1;
            }
        }
        if (!pqc_dispatched) {
            client_pqc_encaps_worker(&pqc_args);
        }

        /* Concurrently derive classical secret on main thread */
        if (srv_pub_len > 0) {
            EVP_PKEY *srv_pub_key =
                (combo->classical_curve == CURVE_X25519)
                    ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
                    : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);
            if (srv_pub_key) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(c_priv, srv_pub_key, c_secret, &c_secret_len);
                EVP_PKEY_free(srv_pub_key);
            }
        }
        if (c_priv) { EVP_PKEY_free(c_priv); c_priv = NULL; }

        if (pqc_dispatched) {
            pthread_mutex_lock(&g_client_worker.mutex);
            while (!g_client_worker.work_done) {
                pthread_cond_wait(&g_client_worker.done_cond, &g_client_worker.mutex);
            }
            pthread_mutex_unlock(&g_client_worker.mutex);
        }

        free(pqc_pk); pqc_pk = NULL;

        if (!pqc_args.success || c_secret_len == 0) {
            free(pqc_ct); close(fd); return -1.0;
        }

        /* ── Step 4: Transmit PQC Ciphertext in a single contiguous write ── */
        WireHeader ct_hdr = {
            .magic       = htonl(WIRE_MAGIC),
            .msg_type    = htons(WIRE_MSG_PQC_CIPHERTEXT),
            .combo_id    = htons(combo->id),
            .payload_len = htonl(pqc_ct_len)
        };
        size_t total_ct = sizeof(ct_hdr) + pqc_ct_len;
        uint8_t *ct_pkt = malloc(total_ct);
        if (ct_pkt) {
            memcpy(ct_pkt, &ct_hdr, sizeof(ct_hdr));
            memcpy(ct_pkt + sizeof(ct_hdr), pqc_ct, pqc_ct_len);
            send_all(fd, ct_pkt, total_ct);
            free(ct_pkt);
        }
        free(pqc_ct);

    } else if (combo->profile == PROFILE_PURE_CLASSICAL) {
        if (srv_pub_len > 0) {
            EVP_PKEY *srv_pub_key =
                (combo->classical_curve == CURVE_X25519)
                    ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
                    : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);
            if (srv_pub_key) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(c_priv, srv_pub_key, c_secret, &c_secret_len);
                EVP_PKEY_free(srv_pub_key);
            }
        }
        if (c_priv) { EVP_PKEY_free(c_priv); c_priv = NULL; }

    } else if (combo->profile == PROFILE_PURE_QUANTUM) {
        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        if (!kem || !pqc_pk) {
            free(pqc_pk); close(fd); return -1.0;
        }
        pqc_ct = malloc(kem->length_ciphertext);
        uint8_t *ss = malloc(kem->length_shared_secret);
        OQS_KEM_encaps(kem, pqc_ct, ss, pqc_pk);
        q_secret_len = kem->length_shared_secret;
        memcpy(q_secret, ss, q_secret_len);
        free(ss); free(pqc_pk);

        WireHeader ct_hdr = {
            .magic       = htonl(WIRE_MAGIC),
            .msg_type    = htons(WIRE_MSG_PQC_CIPHERTEXT),
            .combo_id    = htons(combo->id),
            .payload_len = htonl(kem->length_ciphertext)
        };
        size_t total_ct = sizeof(ct_hdr) + kem->length_ciphertext;
        uint8_t *ct_pkt = malloc(total_ct);
        if (ct_pkt) {
            memcpy(ct_pkt, &ct_hdr, sizeof(ct_hdr));
            memcpy(ct_pkt + sizeof(ct_hdr), pqc_ct, kem->length_ciphertext);
            send_all(fd, ct_pkt, total_ct);
            free(ct_pkt);
        }
        free(pqc_ct);
        OQS_KEM_free(kem);
    }

    /* ── Step 5: Local Key Derivation ── */
    uint8_t ikm[MAX_IKM_BYTES];
    size_t ikm_len = 0;
    if (c_secret_len > 0) {
        memcpy(ikm + ikm_len, c_secret, c_secret_len);
        ikm_len += c_secret_len;
    }
    if (q_secret_len > 0) {
        memcpy(ikm + ikm_len, q_secret, q_secret_len);
        ikm_len += q_secret_len;
    }

    uint8_t session_key[32];
    const uint8_t *info = (const uint8_t *)combo->info;
    size_t info_len = strlen(combo->info);

    if (strcmp(kdf_type, "blake3") == 0) {
        crypto_blake3_kdf(ikm, ikm_len, info, info_len, session_key);
    } else {
        const uint8_t *salt = (const uint8_t *)STATIC_SALT;
        crypto_hkdf_sha256(ikm, ikm_len, salt, strlen(STATIC_SALT),
                           info, info_len, session_key);
    }

    /* ── Step 6: Await ServerFinished ── */
    WireHeader fin_hdr;
    uint8_t fin_status = 0;
    if (recv_all(fd, &fin_hdr, sizeof(fin_hdr)) == 0 &&
        ntohl(fin_hdr.magic) == WIRE_MAGIC &&
        ntohs(fin_hdr.msg_type) == WIRE_MSG_SERVER_FINISHED) {
        recv_all(fd, &fin_status, 1);
    }

    double elapsed_ms = now_ms() - t_start;
    close(fd);
    return elapsed_ms;
}

/* ═══════════════════════════════════════════════════════════════════
 * Backward-compatible wrapper (defaults to "auto" dispatch)
 * ═══════════════════════════════════════════════════════════════════ */

double execute_handshake(const char *host, const AlgoCombo *combo,
                         const char *kdf_type)
{
    DispatchRoute route = adaptive_dispatch(combo);
    return execute_dispatch_handshake(host, combo, kdf_type, "auto", route);
}
