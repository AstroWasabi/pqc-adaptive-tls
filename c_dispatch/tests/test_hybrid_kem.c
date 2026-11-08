/* c_dispatch/tests/test_hybrid_kem.c
 * ═══════════════════════════════════════════════════════════════════
 * Standalone Verification of All Hybrid Suites (Keygen, Encaps, Decaps, KDF)
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "../include/algo_config.h"
#include "../include/crypto_engine.h"
#include "../include/engine.h"
#include <oqs/oqs.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void)
{
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Hybrid KEM & Session Key Verification (All Suites)  \n");
    printf("═══════════════════════════════════════════════════════\n\n");

    int all_passed = 1;

    for (int i = 0; i < NUM_ALGO_COMBOS; i++) {
        const AlgoCombo *combo = &ALGORITHM_COMBOS[i];
        if (combo->profile != PROFILE_HYBRID) continue;

        printf("─── Testing Suite %d: %s ───\n", combo->id, combo->label);

        /* 1. Client Phase A: Keygen */
        ClientKeyShare client_share;
        int fell_back = 0;
        if (engine_client_keygen(combo, ROUTE_SEQUENTIAL, &client_share, &fell_back) != 0) {
            fprintf(stderr, "  [FAIL] engine_client_keygen failed\n");
            all_passed = 0;
            continue;
        }

        /* 2. Server Mock Computation */
        /* Classical Server EC */
        EVP_PKEY *srv_priv = crypto_generate_keypair(combo->classical_curve);
        uint8_t srv_pub[300];
        size_t srv_pub_len = 0;
        if (combo->classical_curve == CURVE_X25519)
            crypto_export_x25519_pub_raw(srv_priv, srv_pub, &srv_pub_len);
        else
            crypto_export_ec_pub_der(srv_priv, srv_pub, &srv_pub_len);

        EVP_PKEY *cli_key = (combo->classical_curve == CURVE_X25519)
            ? crypto_load_x25519_pub_raw(client_share.ec_pub, client_share.ec_pub_len)
            : crypto_load_ec_pub_der(client_share.ec_pub, client_share.ec_pub_len);

        uint8_t srv_ecdh_ss[48];
        size_t srv_ecdh_len = sizeof(srv_ecdh_ss);
        if (crypto_derive_ecdh_secret(srv_priv, cli_key, srv_ecdh_ss, &srv_ecdh_len) != 0) {
            fprintf(stderr, "  [FAIL] Server ECDH derive failed\n");
            all_passed = 0;
            continue;
        }
        EVP_PKEY_free(cli_key);
        EVP_PKEY_free(srv_priv);

        /* Server PQC KEM Encaps */
        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        if (!kem) {
            fprintf(stderr, "  [FAIL] OQS_KEM_new(\"%s\") returned NULL (not enabled in liboqs?)\n",
                    combo->pqc_name);
            all_passed = 0;
            client_key_share_free(&client_share);
            continue;
        }

        uint8_t *ct = malloc(kem->length_ciphertext);
        uint8_t srv_kem_ss[64];
        size_t srv_kem_len = kem->length_shared_secret;
        if (OQS_KEM_encaps(kem, ct, srv_kem_ss, client_share.kem_pk) != OQS_SUCCESS) {
            fprintf(stderr, "  [FAIL] OQS_KEM_encaps failed\n");
            all_passed = 0;
            free(ct);
            OQS_KEM_free(kem);
            client_key_share_free(&client_share);
            continue;
        }

        /* Server Derive Session Key */
        uint8_t server_session_key[32];
        if (hybrid_derive_session_key(combo, "sha256", srv_ecdh_ss, srv_ecdh_len,
                                      srv_kem_ss, srv_kem_len, server_session_key) != 0) {
            fprintf(stderr, "  [FAIL] Server hybrid_derive_session_key failed\n");
            all_passed = 0;
        }

        uint8_t server_confirm_tag[32];
        crypto_key_confirm_tag(server_session_key, "server finished", server_confirm_tag);

        /* 3. Client Phase B: Finish */
        SharedCryptoResult client_res;
        if (engine_client_finish(combo, ROUTE_SEQUENTIAL, &client_share,
                                 srv_pub, srv_pub_len, ct, kem->length_ciphertext,
                                 &client_res) != 0) {
            fprintf(stderr, "  [FAIL] engine_client_finish failed\n");
            all_passed = 0;
            free(ct);
            OQS_KEM_free(kem);
            client_key_share_free(&client_share);
            continue;
        }

        /* Check individual shared secrets */
        if (srv_ecdh_len != client_res.ecdh_secret_len ||
            CRYPTO_memcmp(srv_ecdh_ss, client_res.ecdh_secret, srv_ecdh_len) != 0) {
            fprintf(stderr, "  [FAIL] Classical ECDH shared secret mismatch!\n");
            all_passed = 0;
        }

        if (srv_kem_len != client_res.kem_shared_secret_len ||
            CRYPTO_memcmp(srv_kem_ss, client_res.kem_shared_secret, srv_kem_len) != 0) {
            fprintf(stderr, "  [FAIL] PQC KEM shared secret mismatch!\n");
            print_hex("    Server KEM SS", srv_kem_ss, srv_kem_len);
            print_hex("    Client KEM SS", client_res.kem_shared_secret, client_res.kem_shared_secret_len);
            all_passed = 0;
        }

        /* Client Derive Session Key */
        uint8_t client_session_key[32];
        if (hybrid_derive_session_key(combo, "sha256",
                                      client_res.ecdh_secret, client_res.ecdh_secret_len,
                                      client_res.kem_shared_secret, client_res.kem_shared_secret_len,
                                      client_session_key) != 0) {
            fprintf(stderr, "  [FAIL] Client hybrid_derive_session_key failed\n");
            all_passed = 0;
        }

        uint8_t client_expected_tag[32];
        crypto_key_confirm_tag(client_session_key, "server finished", client_expected_tag);

        if (CRYPTO_memcmp(server_confirm_tag, client_expected_tag, 32) != 0) {
            fprintf(stderr, "  [FAIL] Confirmation HMAC tag mismatch!\n");
            print_hex("    Server Tag", server_confirm_tag, 32);
            print_hex("    Client Tag", client_expected_tag, 32);
            all_passed = 0;
        } else {
            printf("  [PASS] Key exchange & confirmation HMAC verified successfully!\n");
            printf("         ECDH SS len: %zu | KEM SS len: %zu\n", srv_ecdh_len, srv_kem_len);
            print_hex("         Session Key", client_session_key, 16);
        }

        free(ct);
        OQS_KEM_free(kem);
        client_key_share_free(&client_share);
        printf("\n");
    }

    if (all_passed) {
        printf("[✔] All hybrid suites passed cryptographic verification!\n");
        return 0;
    } else {
        printf("[!] Some hybrid suites failed verification.\n");
        return 1;
    }
}
