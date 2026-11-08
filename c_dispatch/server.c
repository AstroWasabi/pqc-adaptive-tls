/* c_dispatch/server.c
 * ═══════════════════════════════════════════════════════════════════
 * Dedicated Sequential Hybrid PQC TLS 1.3 Server (Wire Framing V2)
 *
 * Designed specifically for high-throughput, sequential processing.
 *
 * Wire Flow:
 *   1. Recv: ClientHello (WireHeaderV2 + ClientHelloMetaV2 + c_pub + pqc_pk)
 *   2. Compute:
 *      - EC keygen & derive shared secret
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/network_utils.h"
#include <oqs/oqs.h>

#define SERVER_HOST "0.0.0.0"
#define SERVER_PORT 4444

static void *handle_client(void *arg)
{
    int fd = *(int *)arg;
    free(arg);

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

    if (combo->classical_curve != CURVE_NONE) {
        srv_priv = crypto_generate_keypair(combo->classical_curve);
        if (!srv_priv) { free(cli_pqc_pk); close(fd); return NULL; }

        if (combo->classical_curve == CURVE_X25519)
            crypto_export_x25519_pub_raw(srv_priv, srv_pub, &srv_pub_len);
        else
            crypto_export_ec_pub_der(srv_priv, srv_pub, &srv_pub_len);

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
        free(cli_pqc_pk);
    }

    /* 3. Session Key Derivation (RFC 9954 Combiner) */
    uint8_t session_key[32];
    if (hybrid_derive_session_key(combo, kdf_type, ecdh_ss, ecdh_ss_len,
                                  kem_ss, kem_ss_len, session_key) != 0) {
        free(ct); close(fd); return NULL;
    }

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
    close(fd);
    return NULL;
}

int main(void)
{
    printf("\n═══════════════════════════════════════════════════════\n");
    printf("  Sequential Hybrid PQC TLS 1.3 Server (Wire V2)      \n");
    printf("  Port: %d | Host: %s\n", SERVER_PORT, SERVER_HOST);
    printf("═══════════════════════════════════════════════════════\n\n");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(SERVER_PORT)
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 128) < 0) {
        perror("listen"); return 1;
    }

    printf("[*] Server listening on %s:%d\n\n", SERVER_HOST, SERVER_PORT);

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
    return 0;
}
