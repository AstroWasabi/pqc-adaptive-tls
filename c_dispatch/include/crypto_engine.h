/* c/include/crypto_engine.h
 * Classical KEX + KDF function declarations.
 * Wraps OpenSSL for X25519/P-256/P-384 ECDH and HKDF-SHA256,
 * plus the vendored BLAKE3 KDF.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

/* -----------------------------------------------------------------------
 * Classical key-pair types
 * All keys are OpenSSL EVP_PKEY objects for unified API across curves.
 * ----------------------------------------------------------------------- */

/**
 * Generate an X25519 or ECDH (P-256 / P-384) ephemeral key-pair.
 *
 * @param curve_id  CURVE_X25519 | CURVE_P256 | CURVE_P384
 * @returns         Newly allocated EVP_PKEY* (caller must EVP_PKEY_free),
 *                  or NULL on failure.
 */
EVP_PKEY *crypto_generate_keypair(int curve_id);

/**
 * Export the *raw* public key bytes for X25519 (32 bytes) into caller-supplied buffer.
 *
 * @param pkey      EVP_PKEY* containing an X25519 key
 * @param out       Output buffer (must be >= 32 bytes)
 * @param out_len   Set to number of bytes written on success
 * @returns         0 on success, -1 on failure
 */
int crypto_export_x25519_pub_raw(EVP_PKEY *pkey, uint8_t *out, size_t *out_len);

/**
 * Export the DER SubjectPublicKeyInfo encoding for P-256/P-384 public key.
 *
 * @param pkey      EVP_PKEY* containing an EC key
 * @param out       Caller-supplied buffer (must be >= 200 bytes for P-384)
 * @param out_len   Set to bytes written on success
 * @returns         0 on success, -1 on failure
 */
int crypto_export_ec_pub_der(EVP_PKEY *pkey, uint8_t *out, size_t *out_len);

/**
 * Load a peer X25519 public key from 32 raw bytes.
 *
 * @returns   Newly allocated EVP_PKEY* or NULL on failure.
 */
EVP_PKEY *crypto_load_x25519_pub_raw(const uint8_t *raw, size_t len);

/**
 * Load a peer EC public key from DER SubjectPublicKeyInfo bytes.
 *
 * @returns   Newly allocated EVP_PKEY* or NULL on failure.
 */
EVP_PKEY *crypto_load_ec_pub_der(const uint8_t *der, size_t len);

/**
 * Perform ECDH / X25519 key agreement.
 *
 * @param priv_key  Our private EVP_PKEY*
 * @param peer_pub  Peer's public EVP_PKEY*
 * @param secret    Output buffer (must be >= 48 bytes — largest P-384 shared secret)
 * @param secret_len Set to shared secret length on success
 * @returns         0 on success, -1 on failure
 */
int crypto_derive_ecdh_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_pub,
                              uint8_t *secret, size_t *secret_len);

/* -----------------------------------------------------------------------
 * KDF engines
 * ----------------------------------------------------------------------- */

/**
 * HKDF-SHA256 key derivation.
 * Mirrors derive_hybrid_secret_sha256() from Python crypto_engine.py.
 *
 * @param ikm       Input keying material (concatenated classical+pqc secrets)
 * @param ikm_len   Length of ikm
 * @param salt      Optional salt (may be NULL)
 * @param salt_len  Length of salt (0 if NULL)
 * @param info      Context info label bytes
 * @param info_len  Length of info
 * @param out       Output buffer (must be >= 32 bytes)
 * @returns         0 on success, -1 on failure
 */
int crypto_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out);

/**
 * BLAKE3 KDF.
 * Mirrors derive_hybrid_secret_blake3() from Python crypto_engine.py.
 * Feeds info label then ikm into the hasher, outputs 32 bytes.
 *
 * @param ikm       Input keying material
 * @param ikm_len   Length of ikm
 * @param info      Context info label bytes
 * @param info_len  Length of info
 * @param out       Output buffer (must be >= 32 bytes)
 */
void crypto_blake3_kdf(const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out);
