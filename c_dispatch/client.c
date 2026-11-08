/* c_dispatch/client.c
 * ═══════════════════════════════════════════════════════════════════
 * Client-Side Parallel Hybrid Post-Quantum TLS 1.3 Handshake (Wire V2)
 *
 * Implements two distinct phases:
 *   Phase A (Pre-ClientHello):
 *     - If Key Pool active: O(1) Pop (< 5 µs) of (EC + KEM keypair)
 *     - If Key Pool off: Dynamic Keygen (EC Keygen || KEM Keygen)
 *     - Records: ch_prep_ms
 *
 *   Phase B (Post-ServerHello):
 *     - Sequential or Parallel (Core 0: ECDH Derive || Core 1: KEM Decaps)
 *     - Records: post_sh_ms
 *
 *   Total Handshake Time:
 *     - Records: total_ms
 * ═══════════════════════════════════════════════════════════════════
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/dispatcher.h"
#include "include/engine.h"
#include "include/network_utils.h"
#include "include/key_pool.h"

#define SERVER_PORT 4444

int g_client_use_key_pool = 0;

typedef struct {
    double ch_prep_ms;
    double post_sh_ms;
    double total_ms;
    int    pool_hit;
    int    ok;
} HandshakeTiming;

static inline double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int execute_dispatch_handshake_v2(const char *host,
                                  const AlgoCombo *combo,
                                  const char *kdf_type,
                                  DispatchRoute local_route,
                                  HandshakeTiming *out_timing)
{
    memset(out_timing, 0, sizeof(*out_timing));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, host, &srv.sin_addr);

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        close(fd); return -1;
    }

    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    double t_total_start = now_ms();

    /* ═══════════════════════════════════════════════════════════════
     * PHASE A: Client Key Share Acquisition & ClientHello
     * ═══════════════════════════════════════════════════════════════ */
    double t_ch0 = now_ms();
    ClientKeyShare share;
    int pool_hit = 0;

    if (g_client_use_key_pool) {
        if (key_pool_pop(combo, &share, &pool_hit) != 0) {
            close(fd); return -1;
        }
    } else {
        int fell_back = 0;
        if (engine_client_keygen(combo, local_route, &share, &fell_back) != 0) {
            close(fd); return -1;
        }
    }

    uint8_t kdf_code = (kdf_type && strcmp(kdf_type, "blake3") == 0) ? 1 : 0;
    ClientHelloMetaV2 ch_meta = {
        .kdf_type    = kdf_code,
        .reserved    = 0,
        .c_pub_len   = htons((uint16_t)share.ec_pub_len),
        .pqc_pk_len  = htonl((uint32_t)share.kem_pk_len)
    };

    WireHeaderV2 ch_hdr = {
        .magic       = htonl(WIRE_MAGIC_V2),
        .msg_type    = htons(WIRE_MSG_CLIENT_HELLO),
        .combo_id    = htons(combo->id),
        .payload_len = htonl(sizeof(ch_meta) + share.ec_pub_len + share.kem_pk_len)
    };

    size_t total_ch = sizeof(ch_hdr) + sizeof(ch_meta) + share.ec_pub_len + share.kem_pk_len;
    uint8_t *ch_pkt = malloc(total_ch);
    if (!ch_pkt) { client_key_share_free(&share); close(fd); return -1; }

    memcpy(ch_pkt, &ch_hdr, sizeof(ch_hdr));
    memcpy(ch_pkt + sizeof(ch_hdr), &ch_meta, sizeof(ch_meta));
    size_t off = sizeof(ch_hdr) + sizeof(ch_meta);
    if (share.ec_pub_len > 0) {
        memcpy(ch_pkt + off, share.ec_pub, share.ec_pub_len);
        off += share.ec_pub_len;
    }
    if (share.kem_pk_len > 0) {
        memcpy(ch_pkt + off, share.kem_pk, share.kem_pk_len);
    }

    int send_rc = send_all(fd, ch_pkt, total_ch);
    free(ch_pkt);
    double t_ch1 = now_ms();

    out_timing->ch_prep_ms = t_ch1 - t_ch0;
    out_timing->pool_hit = pool_hit;

    if (send_rc != 0) { client_key_share_free(&share); close(fd); return -1; }

    /* ═══════════════════════════════════════════════════════════════
     * RECEIVE SERVERHELLO
     * ═══════════════════════════════════════════════════════════════ */
    WireHeaderV2 sh_hdr;
    if (recv_all(fd, &sh_hdr, sizeof(sh_hdr)) != 0 ||
        ntohl(sh_hdr.magic) != WIRE_MAGIC_V2 ||
        ntohs(sh_hdr.msg_type) != WIRE_MSG_SERVER_HELLO) {
        client_key_share_free(&share); close(fd); return -1;
    }

    ServerHelloMetaV2 sh_meta;
    if (recv_all(fd, &sh_meta, sizeof(sh_meta)) != 0) {
        client_key_share_free(&share); close(fd); return -1;
    }

    uint16_t srv_pub_len = ntohs(sh_meta.srv_pub_len);
    uint32_t pqc_ct_len  = ntohl(sh_meta.pqc_ct_len);

    uint8_t srv_pub[300];
    if (srv_pub_len > sizeof(srv_pub) || recv_all(fd, srv_pub, srv_pub_len) != 0) {
        client_key_share_free(&share); close(fd); return -1;
    }

    uint8_t *pqc_ct = NULL;
    if (pqc_ct_len > 0) {
        pqc_ct = malloc(pqc_ct_len);
        if (!pqc_ct || recv_all(fd, pqc_ct, pqc_ct_len) != 0) {
            free(pqc_ct); client_key_share_free(&share); close(fd); return -1;
        }
    }

    /* ═══════════════════════════════════════════════════════════════
     * PHASE B: Interactive Key Derivation (ECDH Derive || KEM Decaps)
     * ═══════════════════════════════════════════════════════════════ */
    double t_post0 = now_ms();
    SharedCryptoResult crypto_res;
    if (engine_client_finish(combo, local_route, &share, srv_pub, srv_pub_len,
                             pqc_ct, pqc_ct_len, &crypto_res) != 0) {
        free(pqc_ct); client_key_share_free(&share); close(fd); return -1;
    }
    free(pqc_ct);
    client_key_share_free(&share);

    uint8_t client_session_key[32];
    if (hybrid_derive_session_key(combo, kdf_type,
                                  crypto_res.ecdh_secret, crypto_res.ecdh_secret_len,
                                  crypto_res.kem_shared_secret, crypto_res.kem_shared_secret_len,
                                  client_session_key) != 0) {
        close(fd); return -1;
    }
    double t_post1 = now_ms();
    out_timing->post_sh_ms = t_post1 - t_post0;

    if (combo->id == 9) {
        static int printed_cli9 = 0;
        if (!printed_cli9) {
            printf("\n[Client Debug Suite 9]\n");
            printf("  share.ec_pub_len=%zu | kem_pk_len=%zu | pqc_ct_len=%u\n",
                   share.ec_pub_len, share.kem_pk_len, pqc_ct_len);
            printf("  client kem_pk[0..7]: ");
            for (int i = 0; i < 8 && i < (int)share.kem_pk_len; i++) printf("%02x", share.kem_pk[i]);
            printf("\n  received ct[0..7]: ");
            for (int i = 0; i < 8 && i < (int)pqc_ct_len; i++) printf("%02x", pqc_ct[i]);
            printf("\n  client ecdh_secret[0..7]: ");
            for (int i = 0; i < 8 && i < (int)crypto_res.ecdh_secret_len; i++) printf("%02x", crypto_res.ecdh_secret[i]);
            printf("\n  client kem_shared_secret[0..7]: ");
            for (int i = 0; i < 8 && i < (int)crypto_res.kem_shared_secret_len; i++) printf("%02x", crypto_res.kem_shared_secret[i]);
            printf("\n  client session_key[0..7]: ");
            for (int i = 0; i < 8; i++) printf("%02x", client_session_key[i]);
            printf("\n\n");
            fflush(stdout);
            printed_cli9 = 1;
        }
    }

    /* ═══════════════════════════════════════════════════════════════
     * RECEIVE & VERIFY SERVERFINISHED
     * ═══════════════════════════════════════════════════════════════ */
    WireHeaderV2 fin_hdr;
    if (recv_all(fd, &fin_hdr, sizeof(fin_hdr)) != 0 ||
        ntohl(fin_hdr.magic) != WIRE_MAGIC_V2 ||
        ntohs(fin_hdr.msg_type) != WIRE_MSG_SERVER_FINISHED) {
        close(fd); return -1;
    }

    uint8_t srv_tag[32];
    if (recv_all(fd, srv_tag, 32) != 0) { close(fd); return -1; }

    uint8_t expected_tag[32];
    crypto_key_confirm_tag(client_session_key, "server finished", expected_tag);

    if (CRYPTO_memcmp(srv_tag, expected_tag, 32) != 0) {
        static int printed_mismatch = 0;
        if (!printed_mismatch) {
            fprintf(stderr, "\n[!] Key confirmation HMAC mismatch on %s (id=%d)!\n",
                    combo->label, combo->id);
            fprintf(stderr, "    Expected tag: ");
            for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", expected_tag[i]);
            fprintf(stderr, " | Server tag: ");
            for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", srv_tag[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "    Client session key: ");
            for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", client_session_key[i]);
            fprintf(stderr, "\n");
            printed_mismatch = 1;
        }
        close(fd); return -1;
    }

    double t_total_end = now_ms();
    out_timing->total_ms = t_total_end - t_total_start;
    out_timing->ok = 1;

    close(fd);
    return 0;
}
