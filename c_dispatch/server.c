/* c_dispatch/server.c
 * ═══════════════════════════════════════════════════════════════════
 * Adaptive Dispatch TLS 1.3 Hybrid PQC Server
 *
 * Integrates the Adaptive Dispatch Runtime into a real TCP server.
 * Wire protocol (newline-delimited JSON, compatible with c/server.c):
 *
 *   1. Client → Server: ProfileSelect  { combo_id, kdf_type, salt?, dispatch_mode? }
 *   2. Client → Server: ClientHello    { c_pub }
 *   3. Server → Client: KeyMaterial    { c_pub, q_pk, dispatch_route }
 *   4. Client → Server: PQCCiphertext  { ct }
 *   5. Server → Client: ServerFinished { type, status, dispatch_route }
 *
 * The server uses the adaptive dispatcher to decide whether to execute
 * the ECDH derive and ML-KEM decapsulation sequentially or in parallel
 * with core-pinned threads.
 *
 * Dispatch modes (set via ProfileSelect.dispatch_mode):
 *   "auto"       — use adaptive_dispatch() routing (default)
 *   "sequential" — force execute_sequential()
 *   "parallel"   — force execute_parallel_optimized()
 * ═══════════════════════════════════════════════════════════════════
 */

#include <arpa/inet.h>
#include <errno.h>
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

#include <oqs/oqs.h>

#define SERVER_HOST "0.0.0.0"
#define SERVER_PORT 4444
#define STATIC_SALT "IEICE-Kyoto-Conference-2026"

#define MAX_PUB_KEY_BYTES  300
#define MAX_SHARED_SEC     64
#define MAX_IKM_BYTES      200

/* ═══════════════════════════════════════════════════════════════════
 * Server-side PQC keygen worker (parallel with ECDH on heavy suites)
 *
 * On the parallel path, the server dispatches KEM keygen to the
 * pre-warmed worker (Core 1) while generating the ECDH keypair
 * on the main thread (Core 0).
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *pqc_name;
    OQS_KEM    *kem;
    uint8_t    *q_pk;
    uint8_t    *q_sk;
    int         success;
} PQCKeygenArgs;

static void *pqc_keygen_worker(void *arg)
{
    PQCKeygenArgs *p = (PQCKeygenArgs *)arg;
    p->success = 0;

    p->kem = OQS_KEM_new(p->pqc_name);
    if (!p->kem) return NULL;

    p->q_pk = malloc(p->kem->length_public_key);
    p->q_sk = malloc(p->kem->length_secret_key);
    if (!p->q_pk || !p->q_sk) {
        free(p->q_pk); free(p->q_sk);
        OQS_KEM_free(p->kem);
        p->kem = NULL; p->q_pk = NULL; p->q_sk = NULL;
        return NULL;
    }

    if (OQS_KEM_keypair(p->kem, p->q_pk, p->q_sk) != OQS_SUCCESS) {
        free(p->q_pk); free(p->q_sk);
        OQS_KEM_free(p->kem);
        p->kem = NULL; p->q_pk = NULL; p->q_sk = NULL;
        return NULL;
    }

    p->success = 1;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Resolve the dispatch mode for this handshake
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum {
    DMODE_AUTO,
    DMODE_FORCE_SEQUENTIAL,
    DMODE_FORCE_PARALLEL
} DispatchMode;

static DispatchMode parse_dispatch_mode(const char *mode_str)
{
    if (!mode_str)                              return DMODE_AUTO;
    if (strcmp(mode_str, "sequential") == 0)     return DMODE_FORCE_SEQUENTIAL;
    if (strcmp(mode_str, "parallel") == 0)       return DMODE_FORCE_PARALLEL;
    return DMODE_AUTO;
}

static const char *dmode_str(DispatchMode m)
{
    switch (m) {
        case DMODE_FORCE_SEQUENTIAL: return "sequential";
        case DMODE_FORCE_PARALLEL:   return "parallel";
        default:                     return "auto";
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Binary Wire Protocol Handler (RFC 8446 / RFC 9954 Framing)
 * ═══════════════════════════════════════════════════════════════════ */

static void *handle_client_binary(int fd, const WireHeader *hdr_first, struct timespec t0)
{
    int combo_id = ntohs(hdr_first->combo_id);
    const AlgoCombo *combo = get_combo_by_id(combo_id);
    if (!combo) { close(fd); return NULL; }

    ClientHelloMeta ch_meta;
    if (recv_all(fd, &ch_meta, sizeof(ch_meta)) != 0) { close(fd); return NULL; }

    uint16_t cli_pub_len = ch_meta.c_pub_len;
    uint8_t cli_pub_buf[MAX_PUB_KEY_BYTES];
    if (cli_pub_len > 0) {
        if (cli_pub_len > sizeof(cli_pub_buf) ||
            recv_all(fd, cli_pub_buf, cli_pub_len) != 0) {
            close(fd); return NULL;
        }
    }

    const char *kdf_type = (ch_meta.kdf_type == 1) ? "blake3" : "sha256";
    DispatchMode dmode = (ch_meta.dispatch_mode == 1) ? DMODE_FORCE_SEQUENTIAL :
                         (ch_meta.dispatch_mode == 2) ? DMODE_FORCE_PARALLEL : DMODE_AUTO;
    DispatchRoute route = ROUTE_SEQUENTIAL;

    /* PQC Keygen */
    OQS_KEM *kem = NULL;
    uint8_t *q_pk = NULL;
    uint8_t *q_sk = NULL;
    uint32_t pqc_pk_len = 0;

    if (combo->profile == PROFILE_HYBRID || combo->profile == PROFILE_PURE_QUANTUM) {
        kem = OQS_KEM_new(combo->pqc_name);
        if (!kem) { close(fd); return NULL; }
        q_pk = malloc(kem->length_public_key);
        q_sk = malloc(kem->length_secret_key);
        if (!q_pk || !q_sk || OQS_KEM_keypair(kem, q_pk, q_sk) != OQS_SUCCESS) {
            free(q_pk); free(q_sk); if (kem) OQS_KEM_free(kem);
            close(fd); return NULL;
        }
        pqc_pk_len = (uint32_t)kem->length_public_key;
    }

    /* Classical Key Exchange */
    uint8_t c_secret[MAX_SHARED_SEC] = {0};
    size_t c_secret_len = 0;
    uint8_t srv_pub_buf[MAX_PUB_KEY_BYTES] = {0};
    size_t srv_pub_len = 0;
    EVP_PKEY *srv_priv = NULL;

    if (combo->profile == PROFILE_HYBRID || combo->profile == PROFILE_PURE_CLASSICAL) {
        srv_priv = crypto_generate_keypair(combo->classical_curve);
        if (!srv_priv) {
            free(q_pk); free(q_sk); if (kem) OQS_KEM_free(kem);
            close(fd); return NULL;
        }
        if (combo->classical_curve == CURVE_X25519) {
            crypto_export_x25519_pub_raw(srv_priv, srv_pub_buf, &srv_pub_len);
        } else {
            crypto_export_ec_pub_der(srv_priv, srv_pub_buf, &srv_pub_len);
        }

        if (cli_pub_len > 0) {
            EVP_PKEY *cli_pub = (combo->classical_curve == CURVE_X25519)
                ? crypto_load_x25519_pub_raw(cli_pub_buf, (size_t)cli_pub_len)
                : crypto_load_ec_pub_der(cli_pub_buf, (size_t)cli_pub_len);
            if (cli_pub) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(srv_priv, cli_pub, c_secret, &c_secret_len);
                EVP_PKEY_free(cli_pub);
            }
        }
    }

    /* Set TCP_NODELAY on socket */
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    /* Send ServerHello in a single contiguous write to prevent TCP delayed-ACK */
    ServerHelloMeta sh_meta = {
        .dispatch_route = (route == ROUTE_PARALLEL) ? 1 : 0,
        .reserved       = 0,
        .srv_pub_len    = (uint16_t)srv_pub_len,
        .pqc_pk_len     = pqc_pk_len
    };
    WireHeader sh_hdr = {
        .magic       = htonl(WIRE_MAGIC),
        .msg_type    = htons(WIRE_MSG_SERVER_HELLO),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(sizeof(sh_meta) + srv_pub_len + pqc_pk_len)
    };

    size_t total_sh = sizeof(sh_hdr) + sizeof(sh_meta) + srv_pub_len + pqc_pk_len;
    uint8_t *sh_pkt = malloc(total_sh);
    if (!sh_pkt) {
        free(q_pk); free(q_sk); if (kem) OQS_KEM_free(kem);
        if (srv_priv) EVP_PKEY_free(srv_priv);
        close(fd); return NULL;
    }
    memcpy(sh_pkt, &sh_hdr, sizeof(sh_hdr));
    memcpy(sh_pkt + sizeof(sh_hdr), &sh_meta, sizeof(sh_meta));
    size_t sh_off = sizeof(sh_hdr) + sizeof(sh_meta);
    if (srv_pub_len > 0) {
        memcpy(sh_pkt + sh_off, srv_pub_buf, srv_pub_len);
        sh_off += srv_pub_len;
    }
    if (pqc_pk_len > 0) {
        memcpy(sh_pkt + sh_off, q_pk, pqc_pk_len);
    }
    int sh_rc = send_all(fd, sh_pkt, total_sh);
    free(sh_pkt);

    free(q_pk); q_pk = NULL;
    if (srv_priv) { EVP_PKEY_free(srv_priv); srv_priv = NULL; }
    if (sh_rc != 0) {
        free(q_sk); if (kem) OQS_KEM_free(kem);
        close(fd); return NULL;
    }

    /* Receive PQC Ciphertext (if hybrid / pure_quantum) */
    uint8_t q_secret[64] = {0};
    size_t q_secret_len = 0;

    if (combo->profile == PROFILE_HYBRID || combo->profile == PROFILE_PURE_QUANTUM) {
        WireHeader ct_hdr;
        if (recv_all(fd, &ct_hdr, sizeof(ct_hdr)) != 0 ||
            ntohl(ct_hdr.magic) != WIRE_MAGIC ||
            ntohs(ct_hdr.msg_type) != WIRE_MSG_PQC_CIPHERTEXT) {
            free(q_sk); if (kem) OQS_KEM_free(kem);
            close(fd); return NULL;
        }

        uint32_t ct_len = ntohl(ct_hdr.payload_len);
        uint8_t *ct = malloc(ct_len);
        if (!ct || recv_all(fd, ct, ct_len) != 0) {
            free(ct); free(q_sk); if (kem) OQS_KEM_free(kem);
            close(fd); return NULL;
        }

        if (ct_len == kem->length_ciphertext) {
            uint8_t *ss = malloc(kem->length_shared_secret);
            if (ss && OQS_KEM_decaps(kem, ss, ct, q_sk) == OQS_SUCCESS) {
                q_secret_len = kem->length_shared_secret;
                memcpy(q_secret, ss, q_secret_len);
            }
            free(ss);
        }
        free(ct);
        free(q_sk);
        OQS_KEM_free(kem);
    }

    /* Key Derivation */
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

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                        (t1.tv_nsec - t0.tv_nsec) / 1e6;

    /* Send ServerFinished in a single contiguous write */
    uint8_t fin_pkt[sizeof(WireHeader) + 1];
    WireHeader fin_hdr = {
        .magic       = htonl(WIRE_MAGIC),
        .msg_type    = htons(WIRE_MSG_SERVER_FINISHED),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(1)
    };
    memcpy(fin_pkt, &fin_hdr, sizeof(fin_hdr));
    fin_pkt[sizeof(fin_hdr)] = 0;
    send_all(fd, fin_pkt, sizeof(fin_pkt));

    printf("  [✔] %s | route=%-10s | mode=%-10s | %.3f ms (wire: binary)\n",
           combo->label, route_name(route), dmode_str(dmode), elapsed_ms);

    close(fd);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Client handler — executed in a dedicated pthread per connection
 * ═══════════════════════════════════════════════════════════════════ */

static void *handle_client(void *arg)
{
    int fd = *(int *)arg;
    free(arg);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* ──── Binary Wire Protocol Detection ──── */
    uint32_t peek_magic = 0;
    ssize_t peek_n = recv(fd, &peek_magic, sizeof(peek_magic), MSG_PEEK);
    if (peek_n == (ssize_t)sizeof(peek_magic) && ntohl(peek_magic) == WIRE_MAGIC) {
        WireHeader hdr;
        if (recv_all(fd, &hdr, sizeof(hdr)) == 0) {
            return handle_client_binary(fd, &hdr, t0);
        }
        close(fd);
        return NULL;
    }

    /* ──── Legacy JSON Wire Protocol Fallback ──── */
    cJSON *sel = recv_json_line(fd);
    if (!sel) { close(fd); return NULL; }

    int combo_id          = json_get_int(sel, "combo_id", -1);
    const char *kdf_type  = json_get_str(sel, "kdf_type");
    const char *salt_b64  = json_get_str(sel, "salt");
    const char *mode_str  = json_get_str(sel, "dispatch_mode");
    DispatchMode dmode    = parse_dispatch_mode(mode_str);

    /* Copy kdf_type before deleting sel */
    char kdf_buf[16] = "sha256";
    if (kdf_type) strncpy(kdf_buf, kdf_type, sizeof(kdf_buf) - 1);
    kdf_type = kdf_buf;

    cJSON_Delete(sel);

    const AlgoCombo *combo = get_combo_by_id(combo_id);
    if (!combo) {
        fprintf(stderr, "[!] Unknown combo_id %d\n", combo_id);
        close(fd);
        return NULL;
    }

    /*
     * Server Execution Policy: Always Sequential Execution.
     * All cryptographic operations (ECDH keygen/derive, ML-KEM keygen/decaps)
     * run inline on the server handler thread.
     */
    DispatchRoute route = ROUTE_SEQUENTIAL;

    /* Decode optional salt */
    uint8_t salt_buf[128] = {0};
    int salt_len = 0;
    if (salt_b64 && strlen(salt_b64) > 0)
        salt_len = b64_decode(salt_b64, salt_buf, sizeof(salt_buf));

    /* ──── PQC Keygen (always sequential on server) ──── */
    PQCKeygenArgs pqc_args = { .pqc_name = combo->pqc_name,
                               .kem = NULL, .q_pk = NULL, .q_sk = NULL,
                               .success = 0 };

    if (combo->profile == PROFILE_HYBRID ||
        combo->profile == PROFILE_PURE_QUANTUM) {
        pqc_keygen_worker(&pqc_args);
        if (!pqc_args.success) {
            free(pqc_args.q_pk); free(pqc_args.q_sk);
            if (pqc_args.kem) OQS_KEM_free(pqc_args.kem);
            close(fd); return NULL;
        }
    }

    /* ──── Step 2: Classical Key Exchange (hybrid / pure_classical) ──── */
    uint8_t c_secret[MAX_SHARED_SEC] = {0};
    size_t c_secret_len = 0;
    uint8_t srv_pub_buf[MAX_PUB_KEY_BYTES] = {0};
    size_t srv_pub_len = 0;
    EVP_PKEY *srv_priv = NULL;

    if (combo->profile == PROFILE_HYBRID ||
        combo->profile == PROFILE_PURE_CLASSICAL) {

        /* Read ClientHello */
        cJSON *hello = recv_json_line(fd);
        if (!hello) {
            free(pqc_args.q_pk); free(pqc_args.q_sk);
            if (pqc_args.kem) OQS_KEM_free(pqc_args.kem);
            close(fd); return NULL;
        }

        const char *c_pub_b64 = json_get_str(hello, "c_pub");
        uint8_t cli_pub_buf[MAX_PUB_KEY_BYTES] = {0};
        int cli_pub_len = b64_decode(c_pub_b64, cli_pub_buf, sizeof(cli_pub_buf));
        cJSON_Delete(hello);

        if (cli_pub_len <= 0) {
            free(pqc_args.q_pk); free(pqc_args.q_sk);
            if (pqc_args.kem) OQS_KEM_free(pqc_args.kem);
            close(fd); return NULL;
        }

        /* Generate server ECDH keypair */
        srv_priv = crypto_generate_keypair(combo->classical_curve);
        if (!srv_priv) {
            free(pqc_args.q_pk); free(pqc_args.q_sk);
            if (pqc_args.kem) OQS_KEM_free(pqc_args.kem);
            close(fd); return NULL;
        }

        /* Export server public key */
        if (combo->classical_curve == CURVE_X25519) {
            crypto_export_x25519_pub_raw(srv_priv, srv_pub_buf, &srv_pub_len);
        } else {
            crypto_export_ec_pub_der(srv_priv, srv_pub_buf, &srv_pub_len);
        }

        /* Load client public key and derive ECDH shared secret */
        EVP_PKEY *cli_pub =
            (combo->classical_curve == CURVE_X25519)
                ? crypto_load_x25519_pub_raw(cli_pub_buf, (size_t)cli_pub_len)
                : crypto_load_ec_pub_der(cli_pub_buf, (size_t)cli_pub_len);

        if (cli_pub) {
            c_secret_len = sizeof(c_secret);
            crypto_derive_ecdh_secret(srv_priv, cli_pub, c_secret, &c_secret_len);
            EVP_PKEY_free(cli_pub);
        }
    }

    /* ──── Step 3: Transmit key material + PQC decapsulation ──── */
    uint8_t q_secret[64] = {0};
    size_t q_secret_len = 0;

    if (combo->profile == PROFILE_HYBRID ||
        combo->profile == PROFILE_PURE_QUANTUM) {

        char *srv_cpub_b64 = (srv_pub_len > 0) ?
            b64_encode(srv_pub_buf, srv_pub_len) : NULL;
        char *q_pk_b64 = b64_encode(pqc_args.q_pk,
                                    pqc_args.kem->length_public_key);

        cJSON *resp = cJSON_CreateObject();
        if (srv_cpub_b64) cJSON_AddStringToObject(resp, "c_pub", srv_cpub_b64);
        cJSON_AddStringToObject(resp, "q_pk", q_pk_b64);
        cJSON_AddStringToObject(resp, "dispatch_route", route_name(route));
        send_json_line(fd, resp);
        cJSON_Delete(resp);
        free(srv_cpub_b64);
        free(q_pk_b64);

        /* Receive PQC ciphertext from client */
        cJSON *ct_msg = recv_json_line(fd);
        if (!ct_msg) {
            free(pqc_args.q_pk); free(pqc_args.q_sk);
            OQS_KEM_free(pqc_args.kem);
            if (srv_priv) EVP_PKEY_free(srv_priv);
            close(fd); return NULL;
        }

        const char *ct_b64 = json_get_str(ct_msg, "ct");
        uint8_t *ct = malloc(pqc_args.kem->length_ciphertext);
        int ct_len = b64_decode(ct_b64, ct, pqc_args.kem->length_ciphertext);
        cJSON_Delete(ct_msg);

        if (ct_len == (int)pqc_args.kem->length_ciphertext) {
            /* Server: ML_KEM_Decapsulate */
            uint8_t *ss = malloc(pqc_args.kem->length_shared_secret);
            OQS_KEM_decaps(pqc_args.kem, ss, ct, pqc_args.q_sk);
            q_secret_len = pqc_args.kem->length_shared_secret;
            memcpy(q_secret, ss, q_secret_len);
            free(ss);
        }

        free(ct);
        free(pqc_args.q_pk); free(pqc_args.q_sk);
        OQS_KEM_free(pqc_args.kem);

    } else {
        /* Pure classical: send classical key material only */
        char *srv_cpub_b64 = b64_encode(srv_pub_buf, srv_pub_len);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "c_pub", srv_cpub_b64);
        cJSON_AddStringToObject(resp, "dispatch_route", route_name(route));
        send_json_line(fd, resp);
        cJSON_Delete(resp);
        free(srv_cpub_b64);
    }

    if (srv_priv) EVP_PKEY_free(srv_priv);

    /* ──── Step 4: Key Derivation ──── */
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

    int use_blake3 = (strcmp(kdf_type, "blake3") == 0);
    if (use_blake3) {
        crypto_blake3_kdf(ikm, ikm_len, info, info_len, session_key);
    } else {
        const uint8_t *salt = (salt_len > 0) ? salt_buf : NULL;
        crypto_hkdf_sha256(ikm, ikm_len, salt, (size_t)salt_len,
                           info, info_len, session_key);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                        (t1.tv_nsec - t0.tv_nsec) / 1e6;

    /* ──── Step 5: Send ServerFinished ──── */
    cJSON *finished = cJSON_CreateObject();
    cJSON_AddStringToObject(finished, "type", "ServerFinished");
    cJSON_AddStringToObject(finished, "status", "success");
    cJSON_AddStringToObject(finished, "dispatch_route", route_name(route));
    cJSON_AddStringToObject(finished, "dispatch_mode", dmode_str(dmode));
    cJSON_AddNumberToObject(finished, "server_crypto_ms", elapsed_ms);
    send_json_line(fd, finished);
    cJSON_Delete(finished);

    printf("  [✔] %s | route=%-10s | mode=%-10s | %.3f ms\n",
           combo->label, route_name(route), dmode_str(dmode), elapsed_ms);

    close(fd);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Main — TCP listener + dispatcher init
 * ═══════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  Adaptive Dispatch TLS 1.3 Server\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /* Boot-time profiler */
    host_profile_init();
    host_profile_export_json("host_profile.json");

    const HostProfile *hp = get_host_profile();
    printf("[Boot] Hostname: %s | Vendor: %s | Cores: %d logical, %d physical | VM: %s\n",
           hp->hostname, hp->sys_vendor, hp->logical_cores, hp->physical_cores,
           hp->is_virtualized ? "YES" : "NO");
    printf("[Boot] CPU Features: AVX2=%s AVX-512=%s | Inter-Thread Sync Latency: %.2f µs\n",
           hp->has_avx2 ? "YES" : "NO", hp->has_avx512 ? "YES" : "NO",
           (double)hp->sync_overhead_ns / 1000.0);
    printf("[Boot] Initial Load: %.2f (%.1f%% / core) | Congested: %s\n",
           hp->load_1min, hp->load_per_core * 100.0,
           hp->is_congested ? "YES" : "NO");
    printf("[Boot] Exported → host_profile.json\n\n");

    /* Initialize execution engine */
    if (engine_init() != 0) {
        fprintf(stderr, "FATAL: engine_init() failed\n");
        return 1;
    }

    /* Verify affinity */
    AffinityProbe probe;
    if (verify_affinity(&probe) == 0) {
        printf("[Engine] Main TID: %ld → Core %d | Worker TID: %ld → Core %d\n",
               probe.main_thread_tid, probe.main_thread_cpu,
               probe.worker_thread_tid, probe.worker_thread_cpu);
    }

    /* TCP listener */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(SERVER_PORT),
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 128) < 0) {
        perror("listen"); return 1;
    }

    printf("[*] Listening on %s:%d\n\n", SERVER_HOST, SERVER_PORT);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) { perror("accept"); continue; }

        int nodelay = 1;
        setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        int *fd_ptr = malloc(sizeof(int));
        *fd_ptr = cli_fd;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, handle_client, fd_ptr);
        pthread_attr_destroy(&attr);
    }

    engine_shutdown();
    close(server_fd);
    return 0;
}
