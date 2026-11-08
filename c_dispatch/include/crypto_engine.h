/* c_dispatch/include/crypto_engine.h
 * Classical KEX + KDF + Fail-Closed Hybrid Combiner
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include "algo_config.h"

EVP_PKEY *crypto_generate_keypair(int curve_id);
int       crypto_export_x25519_pub_raw(EVP_PKEY *pkey, uint8_t *out, size_t *out_len);
int       crypto_export_ec_pub_der(EVP_PKEY *pkey, uint8_t *out, size_t *out_len);
EVP_PKEY *crypto_load_x25519_pub_raw(const uint8_t *raw, size_t len);
EVP_PKEY *crypto_load_ec_pub_der(const uint8_t *der, size_t len);
int       crypto_derive_ecdh_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_pub,
                                    uint8_t *secret, size_t *secret_len);

int crypto_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out);

int crypto_blake3_kdf(const uint8_t *ikm,  size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out);

/**
 * RFC 9954 Fail-Closed Hybrid Combiner.
 * Combines ecdh_ss and kem_ss to produce 32-byte session key.
 * Enforces: returns -1 if either secret is empty for a hybrid profile.
 */
int hybrid_derive_session_key(const AlgoCombo *combo, const char *kdf_type,
                              const uint8_t *ecdh_ss, size_t ecdh_len,
                              const uint8_t *kem_ss, size_t kem_len,
                              uint8_t session_key_out[32]);

/**
 * Compute HMAC-SHA256 key confirmation tag over label.
 */
int crypto_key_confirm_tag(const uint8_t key[32], const char *label, uint8_t tag[32]);
