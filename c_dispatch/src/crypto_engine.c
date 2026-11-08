/* c_dispatch/src/crypto_engine.c
 * Implementation of classical KEX (X25519, P-256, P-384), KDFs,
 * and RFC 9954 Fail-Closed Combiner.
 */

#include "../include/crypto_engine.h"
#include "../include/algo_config.h"
#include "blake3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#define STATIC_SALT "IEICE-Kyoto-Conference-2026"

/* -----------------------------------------------------------------------
 * Key Generation
 * ----------------------------------------------------------------------- */

EVP_PKEY *crypto_generate_keypair(int curve_id)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (curve_id == CURVE_X25519) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
        if (!ctx) goto fail;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto fail;
        if (EVP_PKEY_generate(ctx, &pkey) <= 0) goto fail;
    } else {
        int nid = (curve_id == CURVE_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) goto fail;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto fail;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) goto fail;
        if (EVP_PKEY_generate(ctx, &pkey) <= 0) goto fail;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;

fail:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return NULL;
}

/* -----------------------------------------------------------------------
 * Public Key Export
 * ----------------------------------------------------------------------- */

int crypto_export_x25519_pub_raw(EVP_PKEY *pkey, uint8_t *out, size_t *out_len)
{
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, out, &len) != 1)
        return -1;
    *out_len = len;
    return 0;
}

int crypto_export_ec_pub_der(EVP_PKEY *pkey, uint8_t *out, size_t *out_len)
{
    uint8_t *der = NULL;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0 || !der)
        return -1;
    memcpy(out, der, (size_t)len);
    *out_len = (size_t)len;
    OPENSSL_free(der);
    return 0;
}

EVP_PKEY *crypto_load_x25519_pub_raw(const uint8_t *raw, size_t len)
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw, len);
}

EVP_PKEY *crypto_load_ec_pub_der(const uint8_t *der, size_t len)
{
    const uint8_t *p = der;
    return d2i_PUBKEY(NULL, &p, (long)len);
}

int crypto_derive_ecdh_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_pub,
                              uint8_t *secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0) goto out;

    size_t req_len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &req_len) <= 0) goto out;
    if (req_len > *secret_len) goto out;

    if (EVP_PKEY_derive(ctx, secret, &req_len) <= 0) goto out;
    *secret_len = req_len;
    rc = 0;

out:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int crypto_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;

    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kdf_ctx) return -1;

    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    if (salt && salt_len > 0)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    if (info && info_len > 0)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[idx] = OSSL_PARAM_construct_end();

    size_t out_len = 32;
    int rc = (EVP_KDF_derive(kdf_ctx, out, out_len, params) == 1) ? 0 : -1;

    EVP_KDF_CTX_free(kdf_ctx);
    return rc;
}

int crypto_blake3_kdf(const uint8_t *ikm,  size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, info, info_len);
    blake3_hasher_update(&hasher, ikm, ikm_len);
    blake3_hasher_finalize(&hasher, out, 32);
    return 0;
}

/* -----------------------------------------------------------------------
 * RFC 9954 Fail-Closed Combiner
 * Order: kem_ss || ecdh_ss (matching RFC 9954 / RFC 10024)
 * ----------------------------------------------------------------------- */

int hybrid_derive_session_key(const AlgoCombo *combo, const char *kdf_type,
                              const uint8_t *ecdh_ss, size_t ecdh_len,
                              const uint8_t *kem_ss, size_t kem_len,
                              uint8_t session_key_out[32])
{
    if (combo->profile == PROFILE_HYBRID) {
        if (ecdh_len == 0 || kem_len == 0 || !ecdh_ss || !kem_ss) {
            return -1; /* Fail-closed */
        }
    }

    uint8_t ikm[256];
    size_t ikm_len = 0;

    /* Concatenation order: KEM shared secret, then ECDH shared secret */
    if (kem_len > 0 && kem_ss) {
        memcpy(ikm + ikm_len, kem_ss, kem_len);
        ikm_len += kem_len;
    }
    if (ecdh_len > 0 && ecdh_ss) {
        memcpy(ikm + ikm_len, ecdh_ss, ecdh_len);
        ikm_len += ecdh_len;
    }

    const uint8_t *info = (const uint8_t *)combo->info;
    size_t info_len = strlen(combo->info);

    if (kdf_type && strcmp(kdf_type, "blake3") == 0) {
        return crypto_blake3_kdf(ikm, ikm_len, info, info_len, session_key_out);
    } else {
        const uint8_t *salt = (const uint8_t *)STATIC_SALT;
        return crypto_hkdf_sha256(ikm, ikm_len, salt, strlen(STATIC_SALT),
                                  info, info_len, session_key_out);
    }
}

int crypto_key_confirm_tag(const uint8_t key[32], const char *label, uint8_t tag[32])
{
    unsigned int len = 32;
    uint8_t *res = HMAC(EVP_sha256(), key, 32, (const unsigned char *)label,
                        strlen(label), tag, &len);
    return (res != NULL) ? 0 : -1;
}
