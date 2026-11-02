/* c_dispatch/src/crypto_engine.c
 * Implementation of classical KEX (X25519, P-256, P-384) and both KDF engines
 * (HKDF-SHA256 via OpenSSL, BLAKE3 via vendored reference implementation).
 *
 * Copied from c/src/crypto_engine.c with adjusted include paths for the
 * c_dispatch/ directory layout.
 */

#include "../include/crypto_engine.h"
#include "../include/algo_config.h"
#include "blake3.h"          /* Found via -I$(BLAKE3_DIR) in Makefile */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>

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
    /* EVP_PKEY_get_raw_public_key gives us the 32-byte raw X25519 public key */
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, out, &len) != 1)
        return -1;
    *out_len = len;
    return 0;
}

int crypto_export_ec_pub_der(EVP_PKEY *pkey, uint8_t *out, size_t *out_len)
{
    /* i2d_PUBKEY writes DER SubjectPublicKeyInfo — identical to Python's
     * serialization.Encoding.DER / PublicFormat.SubjectPublicKeyInfo */
    uint8_t *buf = out;
    int len = i2d_PUBKEY(pkey, &buf);
    if (len < 0)
        return -1;
    *out_len = (size_t)len;
    return 0;
}

/* -----------------------------------------------------------------------
 * Public Key Import
 * ----------------------------------------------------------------------- */

EVP_PKEY *crypto_load_x25519_pub_raw(const uint8_t *raw, size_t len)
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw, len);
}

EVP_PKEY *crypto_load_ec_pub_der(const uint8_t *der, size_t len)
{
    /* d2i_PUBKEY mirrors Python's serialization.load_der_public_key() */
    const uint8_t *p = der;
    return (EVP_PKEY *)d2i_PUBKEY(NULL, &p, (long)len);
}

/* -----------------------------------------------------------------------
 * ECDH Key Agreement
 * ----------------------------------------------------------------------- */

int crypto_derive_ecdh_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_pub,
                              uint8_t *secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }

    /* First call: determine length */
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    /* Second call: derive actual secret */
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

/* -----------------------------------------------------------------------
 * HKDF-SHA256 KDF (mirrors derive_hybrid_secret_sha256 in Python)
 * ----------------------------------------------------------------------- */

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

/* -----------------------------------------------------------------------
 * BLAKE3 KDF (mirrors derive_hybrid_secret_blake3 in Python)
 * Feeds info label first, then ikm — identical order to Python hasher.
 * ----------------------------------------------------------------------- */

void crypto_blake3_kdf(const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, info, info_len);
    blake3_hasher_update(&hasher, ikm, ikm_len);
    blake3_hasher_finalize(&hasher, out, 32);
}
