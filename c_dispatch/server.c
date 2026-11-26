/* c_dispatch/server.c
 * ═══════════════════════════════════════════════════════════════════
 * Dedicated Sequential Hybrid PQC TLS 1.3 Server (Wire Framing V2)
 *
 * Supports both:
 *   1. Standard Inline Ephemeral Keygen (Default)
 *   2. Server-Side Pre-Computed Key Share Pool (--precompute)
 *      Pre-generates server classical key shares before listening,
 *      allowing O(1) (< 1 µs) retrieval on client connection.
 *
 * Wire Flow:
 *   1. Recv: ClientHello (WireHeaderV2 + ClientHelloMetaV2 + c_pub + pqc_pk)
 *   2. Compute:
 *      - EC keygen & derive shared secret (or pop from precomputed pool)
 *      - KEM encaps against client's pqc_pk -> produces (ct, ss)
 *      - Derive session key via RFC 9954 combiner
 *   3. Send: ServerHello (WireHeaderV2 + ServerHelloMetaV2 + srv_pub + ct)
 *   4. Send: ServerFinished (WireHeaderV2 + HMAC confirmation tag)
 * ═══════════════════════════════════════════════════════════════════
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/network_utils.h"
#include <oqs/oqs.h>

#define SERVER_HOST "0.0.0.0"
#define SERVER_PORT 4444
#define DEFAULT_POOL_CAPACITY 1024
#define IDLE_REFILL_DELAY_MS  500ULL

/* ─── Server Precomputed Key Share Pool ────────────────────────────── */

static inline uint64_t now_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static atomic_uint_fast64_t g_last_activity_ms = 0;

typedef struct {
    EVP_PKEY *srv_priv;
    uint8_t   srv_pub[300];
    size_t    srv_pub_len;
} ServerKeyShare;

typedef struct {
    ServerKeyShare  *slots;
    size_t           capacity;
    size_t           head;
    size_t           tail;
    size_t           count;
    pthread_mutex_t  lock;
    const AlgoCombo *combo;
} ServerKeyRing;

typedef struct {
    ServerKeyRing   rings[8];
    int             num_rings;
    pthread_t       worker_thread;
    pthread_mutex_t worker_mutex;
    pthread_cond_t  refill_cond;
    int             running;
    int             initialized;
    size_t          capacity;
    atomic_ulong    total_popped;
    atomic_ulong    total_replenished;
} ServerKeyPool;

static ServerKeyPool g_server_pool;
static int g_server_precompute = 0;
static size_t g_pool_capacity = DEFAULT_POOL_CAPACITY;

static int generate_server_share(const AlgoCombo *combo, ServerKeyShare *out)
{
    memset(out, 0, sizeof(*out));
    if (combo->classical_curve == CURVE_NONE) return 0;

    out->srv_priv = crypto_generate_keypair(combo->classical_curve);
    if (!out->srv_priv) return -1;

    if (combo->classical_curve == CURVE_X25519) {
        if (crypto_export_x25519_pub_raw(out->srv_priv, out->srv_pub, &out->srv_pub_len) != 0) {
            EVP_PKEY_free(out->srv_priv);
            out->srv_priv = NULL;
            return -1;
        }
    } else {
        if (crypto_export_ec_pub_der(out->srv_priv, out->srv_pub, &out->srv_pub_len) != 0) {
            EVP_PKEY_free(out->srv_priv);
            out->srv_priv = NULL;
            return -1;
        }
    }
    return 0;
}

static void *server_key_pool_worker_loop(void *arg)
{
    ServerKeyPool *p = (ServerKeyPool *)arg;

    while (1) {
        int urgent = 0;
        pthread_mutex_lock(&p->worker_mutex);
        while (p->running) {
            urgent = 0;
            int any_deficit = 0;
            for (int r = 0; r < p->num_rings; r++) {
                ServerKeyRing *ring = &p->rings[r];
                pthread_mutex_lock(&ring->lock);
                size_t low_wm = (ring->capacity < 64) ? (ring->capacity / 2) : 32;
                if (ring->count < low_wm) {
                    urgent = 1;
                }
                if (ring->count < ring->capacity) {
                    any_deficit = 1;
                }
                pthread_mutex_unlock(&ring->lock);
            }

            uint64_t last_ms = atomic_load(&g_last_activity_ms);
            uint64_t now_ms  = now_monotonic_ms();
            int is_idle = (last_ms == 0) || ((now_ms - last_ms) >= IDLE_REFILL_DELAY_MS);

            if (urgent || (any_deficit && is_idle)) {
                break;
            }

            struct timespec wake_ts;
            clock_gettime(CLOCK_REALTIME, &wake_ts);
            wake_ts.tv_nsec += 500000000L; /* 500 ms check interval */
            if (wake_ts.tv_nsec >= 1000000000L) {
                wake_ts.tv_sec += 1;
                wake_ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&p->refill_cond, &p->worker_mutex, &wake_ts);
        }

        if (!p->running) {
            pthread_mutex_unlock(&p->worker_mutex);
            break;
        }
        pthread_mutex_unlock(&p->worker_mutex);

        unsigned long cycle_replenished = 0;
        for (int r = 0; r < p->num_rings && p->running; r++) {
            ServerKeyRing *ring = &p->rings[r];
            size_t low_wm = (ring->capacity < 64) ? (ring->capacity / 2) : 32;

            while (p->running) {
                pthread_mutex_lock(&ring->lock);
                size_t cur_count = ring->count;
                pthread_mutex_unlock(&ring->lock);

                if (cur_count >= ring->capacity) break;

                /* Yield CPU immediately if active client traffic resumed and pool is safe */
                uint64_t last_ms = atomic_load(&g_last_activity_ms);
                if (cur_count >= low_wm && last_ms != 0 &&
                    (now_monotonic_ms() - last_ms) < IDLE_REFILL_DELAY_MS) {
                    break;
                }

                ServerKeyShare share;
                if (generate_server_share(ring->combo, &share) != 0) {
                    usleep(1000);
                    continue;
                }

                pthread_mutex_lock(&ring->lock);
                if (ring->count < ring->capacity) {
                    ring->slots[ring->tail] = share;
                    ring->tail = (ring->tail + 1) % ring->capacity;
                    ring->count++;
                    atomic_fetch_add(&p->total_replenished, 1);
                    cycle_replenished++;
                    pthread_mutex_unlock(&ring->lock);
                } else {
                    pthread_mutex_unlock(&ring->lock);
                    if (share.srv_priv) EVP_PKEY_free(share.srv_priv);
                    break;
                }
            }
        }

        if (cycle_replenished > 0 && !urgent) {
            printf("[Server Pool] Idle window: replenished %lu shares back to capacity (%zu/suite)\n",
                   cycle_replenished, p->capacity);
            fflush(stdout);
        }
    }
    return NULL;
}

static int server_key_pool_init(size_t capacity)
{
    if (g_server_pool.initialized) return 0;
    const AlgoCombo *combos[8];
    int n_combos = 0;
    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        if (ALGORITHM_COMBOS[i].profile == PROFILE_HYBRID) {
            combos[n_combos++] = &ALGORITHM_COMBOS[i];
        }
    }
    if (n_combos <= 0 || n_combos > 8) return -1;
    if (capacity == 0) capacity = DEFAULT_POOL_CAPACITY;

    memset(&g_server_pool, 0, sizeof(g_server_pool));
    g_server_pool.capacity = capacity;
    g_server_pool.num_rings = n_combos;
    atomic_store(&g_last_activity_ms, now_monotonic_ms());

    pthread_mutex_init(&g_server_pool.worker_mutex, NULL);
    pthread_cond_init(&g_server_pool.refill_cond, NULL);

    printf("[*] Pre-computing server ephemeral key table (%zu capacity/suite)...\n", capacity);

    for (int i = 0; i < n_combos; i++) {
        ServerKeyRing *ring = &g_server_pool.rings[i];
        ring->combo = combos[i];
        ring->capacity = capacity;
        ring->head = 0;
        ring->tail = 0;
        ring->count = 0;
        pthread_mutex_init(&ring->lock, NULL);

        ring->slots = calloc(ring->capacity, sizeof(ServerKeyShare));
        if (!ring->slots) return -1;

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        for (size_t s = 0; s < capacity; s++) {
            ServerKeyShare share;
            if (generate_server_share(ring->combo, &share) == 0) {
                ring->slots[ring->tail] = share;
                ring->tail = (ring->tail + 1) % ring->capacity;
                ring->count++;
                atomic_fetch_add(&g_server_pool.total_replenished, 1);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0;
        printf("  [+] Suite %-2d (%-33s): %zu shares precomputed (%.2f ms total, %.3f ms/share)\n",
               combos[i]->id, combos[i]->label, ring->count, elapsed_ms, elapsed_ms / (ring->count ? ring->count : 1));
    }

    g_server_pool.running = 1;
    if (pthread_create(&g_server_pool.worker_thread, NULL, server_key_pool_worker_loop, &g_server_pool) != 0) {
        return -1;
    }

    g_server_pool.initialized = 1;
    printf("[✔] Server Precomputation Complete: %lu shares ready in RAM (< 1 µs pop, idle-window refill)\n\n",
           (unsigned long)(g_server_pool.num_rings * capacity));
    return 0;
}

static int server_key_pool_pop(int combo_id, EVP_PKEY **out_priv, uint8_t *out_pub, size_t *out_pub_len)
{
    if (!g_server_pool.initialized) return -1;

    ServerKeyRing *target_ring = NULL;
    for (int r = 0; r < g_server_pool.num_rings; r++) {
        if (g_server_pool.rings[r].combo->id == combo_id) {
            target_ring = &g_server_pool.rings[r];
            break;
        }
    }
    if (!target_ring) return -1;

    pthread_mutex_lock(&target_ring->lock);
    if (target_ring->count > 0) {
        ServerKeyShare share = target_ring->slots[target_ring->head];
        memset(&target_ring->slots[target_ring->head], 0, sizeof(ServerKeyShare));
        target_ring->head = (target_ring->head + 1) % target_ring->capacity;
        target_ring->count--;

        *out_priv = share.srv_priv;
        memcpy(out_pub, share.srv_pub, share.srv_pub_len);
        *out_pub_len = share.srv_pub_len;

        atomic_fetch_add(&g_server_pool.total_popped, 1);

        size_t low_wm = (target_ring->capacity < 64) ? (target_ring->capacity / 2) : 32;
        int need_urgent = (target_ring->count < low_wm);
        pthread_mutex_unlock(&target_ring->lock);

        if (need_urgent) {
            pthread_mutex_lock(&g_server_pool.worker_mutex);
            pthread_cond_signal(&g_server_pool.refill_cond);
            pthread_mutex_unlock(&g_server_pool.worker_mutex);
        }
        return 0;
    }
    pthread_mutex_unlock(&target_ring->lock);

    pthread_mutex_lock(&g_server_pool.worker_mutex);
    pthread_cond_signal(&g_server_pool.refill_cond);
    pthread_mutex_unlock(&g_server_pool.worker_mutex);
    return -1;
}

static void server_key_pool_destroy(void)
{
    if (!g_server_pool.initialized) return;

    pthread_mutex_lock(&g_server_pool.worker_mutex);
    g_server_pool.running = 0;
    pthread_cond_signal(&g_server_pool.refill_cond);
    pthread_mutex_unlock(&g_server_pool.worker_mutex);
    pthread_join(g_server_pool.worker_thread, NULL);

    for (int r = 0; r < g_server_pool.num_rings; r++) {
        ServerKeyRing *ring = &g_server_pool.rings[r];
        pthread_mutex_lock(&ring->lock);
        for (size_t s = 0; s < ring->capacity; s++) {
            if (ring->slots[s].srv_priv) {
                EVP_PKEY_free(ring->slots[s].srv_priv);
                ring->slots[s].srv_priv = NULL;
            }
        }
        free(ring->slots);
        pthread_mutex_unlock(&ring->lock);
        pthread_mutex_destroy(&ring->lock);
    }
    pthread_mutex_destroy(&g_server_pool.worker_mutex);
    pthread_cond_destroy(&g_server_pool.refill_cond);
    g_server_pool.initialized = 0;
}

static void sigint_handler(int sig)
{
    (void)sig;
    server_key_pool_destroy();
    _exit(0);
}

/* ─── Client Connection Handler ────────────────────────────────────── */

static void *handle_client(void *arg)
{
    int fd = *(int *)arg;
    free(arg);

    atomic_store(&g_last_activity_ms, now_monotonic_ms());

    WireHeaderV2 hdr;
    if (recv_all(fd, &hdr, sizeof(hdr)) != 0 ||
        ntohl(hdr.magic) != WIRE_MAGIC_V2 ||
        ntohs(hdr.msg_type) != WIRE_MSG_CLIENT_HELLO) {
        close(fd);
        return NULL;
    }

    int combo_id = ntohs(hdr.combo_id);
    const AlgoCombo *combo = get_combo_by_id(combo_id);
    if (!combo) { close(fd); return NULL; }

    ClientHelloMetaV2 ch_meta;
    if (recv_all(fd, &ch_meta, sizeof(ch_meta)) != 0) { close(fd); return NULL; }

    uint16_t c_pub_len = ntohs(ch_meta.c_pub_len);
    uint32_t pqc_pk_len = ntohl(ch_meta.pqc_pk_len);
    const char *kdf_type = (ch_meta.kdf_type == 1) ? "blake3" : "sha256";

    uint8_t cli_pub[300];
    if (c_pub_len > sizeof(cli_pub) || recv_all(fd, cli_pub, c_pub_len) != 0) {
        close(fd); return NULL;
    }

    uint8_t *cli_pqc_pk = NULL;
    if (pqc_pk_len > 0) {
        cli_pqc_pk = malloc(pqc_pk_len);
        if (!cli_pqc_pk || recv_all(fd, cli_pqc_pk, pqc_pk_len) != 0) {
            free(cli_pqc_pk); close(fd); return NULL;
        }
    }

    /* 1. Classical ECDH (Server Ephemeral Keygen & Derive) */
    uint8_t srv_pub[300];
    size_t srv_pub_len = 0;
    uint8_t ecdh_ss[48];
    size_t ecdh_ss_len = sizeof(ecdh_ss);
    EVP_PKEY *srv_priv = NULL;
    int srv_pool_hit = 0;

    if (combo->classical_curve != CURVE_NONE) {
        if (g_server_precompute) {
            if (server_key_pool_pop(combo->id, &srv_priv, srv_pub, &srv_pub_len) == 0) {
                srv_pool_hit = 1;
            }
        }

        if (!srv_pool_hit) {
            srv_priv = crypto_generate_keypair(combo->classical_curve);
            if (!srv_priv) { free(cli_pqc_pk); close(fd); return NULL; }

            if (combo->classical_curve == CURVE_X25519)
                crypto_export_x25519_pub_raw(srv_priv, srv_pub, &srv_pub_len);
            else
                crypto_export_ec_pub_der(srv_priv, srv_pub, &srv_pub_len);
        }

        EVP_PKEY *cli_key = (combo->classical_curve == CURVE_X25519)
            ? crypto_load_x25519_pub_raw(cli_pub, c_pub_len)
            : crypto_load_ec_pub_der(cli_pub, c_pub_len);

        if (!cli_key || crypto_derive_ecdh_secret(srv_priv, cli_key, ecdh_ss, &ecdh_ss_len) != 0) {
            if (cli_key) EVP_PKEY_free(cli_key);
            EVP_PKEY_free(srv_priv);
            free(cli_pqc_pk);
            close(fd);
            return NULL;
        }
        EVP_PKEY_free(cli_key);
        EVP_PKEY_free(srv_priv);
    }

    /* 2. PQC KEM Encapsulation */
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t kem_ss[64];
    size_t kem_ss_len = 0;

    if (combo->pqc_name && cli_pqc_pk) {
        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        if (!kem || pqc_pk_len != kem->length_public_key) {
            if (kem) OQS_KEM_free(kem);
            free(cli_pqc_pk); close(fd); return NULL;
        }

        ct_len = kem->length_ciphertext;
        kem_ss_len = kem->length_shared_secret;
        ct = malloc(ct_len);
        if (!ct || OQS_KEM_encaps(kem, ct, kem_ss, cli_pqc_pk) != OQS_SUCCESS) {
            free(ct); free(cli_pqc_pk); OQS_KEM_free(kem); close(fd); return NULL;
        }
        OQS_KEM_free(kem);
    }

    /* 3. Session Key Derivation (RFC 9954 Combiner) */
    uint8_t session_key[32];
    if (hybrid_derive_session_key(combo, kdf_type, ecdh_ss, ecdh_ss_len,
                                  kem_ss, kem_ss_len, session_key) != 0) {
        free(ct); free(cli_pqc_pk); close(fd); return NULL;
    }
    free(cli_pqc_pk);

    /* 4. Send ServerHello (WireHeaderV2 + ServerHelloMetaV2 + srv_pub + ct) */
    ServerHelloMetaV2 sh_meta = {
        .srv_pub_len = htons((uint16_t)srv_pub_len),
        .reserved    = 0,
        .pqc_ct_len  = htonl((uint32_t)ct_len)
    };

    WireHeaderV2 sh_hdr = {
        .magic       = htonl(WIRE_MAGIC_V2),
        .msg_type    = htons(WIRE_MSG_SERVER_HELLO),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(sizeof(sh_meta) + srv_pub_len + ct_len)
    };

    size_t total_sh = sizeof(sh_hdr) + sizeof(sh_meta) + srv_pub_len + ct_len;
    uint8_t *sh_pkt = malloc(total_sh);
    if (!sh_pkt) { free(ct); close(fd); return NULL; }

    memcpy(sh_pkt, &sh_hdr, sizeof(sh_hdr));
    memcpy(sh_pkt + sizeof(sh_hdr), &sh_meta, sizeof(sh_meta));
    size_t off = sizeof(sh_hdr) + sizeof(sh_meta);
    if (srv_pub_len > 0) {
        memcpy(sh_pkt + off, srv_pub, srv_pub_len);
        off += srv_pub_len;
    }
    if (ct_len > 0) {
        memcpy(sh_pkt + off, ct, ct_len);
    }
    free(ct);

    if (send_all(fd, sh_pkt, total_sh) != 0) {
        free(sh_pkt); close(fd); return NULL;
    }
    free(sh_pkt);

    /* 5. Send ServerFinished (HMAC Confirmation Tag) */
    uint8_t confirm_tag[32];
    crypto_key_confirm_tag(session_key, "server finished", confirm_tag);

    WireHeaderV2 fin_hdr = {
        .magic       = htonl(WIRE_MAGIC_V2),
        .msg_type    = htons(WIRE_MSG_SERVER_FINISHED),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(32)
    };

    uint8_t fin_pkt[sizeof(fin_hdr) + 32];
    memcpy(fin_pkt, &fin_hdr, sizeof(fin_hdr));
    memcpy(fin_pkt + sizeof(fin_hdr), confirm_tag, 32);

    send_all(fd, fin_pkt, sizeof(fin_pkt));

    atomic_store(&g_last_activity_ms, now_monotonic_ms());

    static atomic_ulong s_handshake_cnt = 0;
    unsigned long n = atomic_fetch_add(&s_handshake_cnt, 1) + 1;
    if (n % 100 == 0 || n <= 3) {
        printf("[Server] Handshake #%lu completed: %s (id=%d)%s\n",
               n, combo->label, combo->id,
               g_server_precompute ? (srv_pool_hit ? " [Pool Hit]" : " [Pool Miss]") : "");
        fflush(stdout);
    }

    close(fd);
    return NULL;
}

/* ─── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int port = SERVER_PORT;
    const char *host = SERVER_HOST;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--precompute") == 0 || strcmp(argv[i], "-p") == 0) {
            g_server_precompute = 1;
        } else if (strcmp(argv[i], "--capacity") == 0 || strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) {
                g_pool_capacity = (size_t)atoi(argv[++i]);
                if (g_pool_capacity == 0) g_pool_capacity = DEFAULT_POOL_CAPACITY;
            }
        } else if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-P") == 0) {
            if (i + 1 < argc) {
                port = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--host") == 0 || strcmp(argv[i], "-H") == 0) {
            if (i + 1 < argc) {
                host = argv[++i];
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  --precompute, -p        Precompute server ephemeral key table before listening\n");
            printf("  --capacity <N>, -c <N>  Capacity per suite (default: %d)\n", DEFAULT_POOL_CAPACITY);
            printf("  --port <PORT>, -P <PORT>Listen port (default: %d)\n", SERVER_PORT);
            printf("  --host <HOST>, -H <HOST>Listen host (default: %s)\n", SERVER_HOST);
            printf("  --help, -h              Show this help message\n");
            return 0;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("\n═══════════════════════════════════════════════════════\n");
    printf("  Sequential Hybrid PQC TLS 1.3 Server (Wire V2)      \n");
    printf("  Port: %d | Host: %s\n", port, host);
    printf("  Precomputation: %s\n",
           g_server_precompute ? "ENABLED (Ephemeral Key Pool Active)" : "DISABLED (Inline Server Keygen)");
    printf("═══════════════════════════════════════════════════════\n\n");

    if (g_server_precompute) {
        if (server_key_pool_init(g_pool_capacity) != 0) {
            fprintf(stderr, "[!] Failed to initialize server key pool.\n");
            return 1;
        }
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = inet_addr(host),
        .sin_port        = htons(port)
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 128) < 0) {
        perror("listen"); return 1;
    }

    printf("[*] Server listening on %s:%d\n\n", host, port);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) continue;

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

    close(server_fd);
    server_key_pool_destroy();
    return 0;
}
