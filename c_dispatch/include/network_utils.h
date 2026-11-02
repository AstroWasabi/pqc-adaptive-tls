/* c/include/network_utils.h
 * Newline-delimited JSON send/recv helpers and Base64 encode/decode.
 * Mirrors the Python b64e(), b64d(), send_json(), recv_json() helpers.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

/* -----------------------------------------------------------------------
 * Base64 helpers (OpenSSL BIO-based)
 * ----------------------------------------------------------------------- */

/**
 * Base64-encode src bytes into a newly allocated null-terminated string.
 * Caller must free() the returned pointer.
 * Returns NULL on failure.
 */
char *b64_encode(const uint8_t *src, size_t src_len);

/**
 * Base64-decode a null-terminated string into caller-supplied buffer.
 *
 * @param b64       Null-terminated Base64 string
 * @param out       Output buffer
 * @param max_len   Size of output buffer
 * @returns         Number of decoded bytes, or -1 on failure
 */
int b64_decode(const char *b64, uint8_t *out, size_t max_len);

/* -----------------------------------------------------------------------
 * Newline-delimited JSON I/O over a raw socket fd
 * ----------------------------------------------------------------------- */

/**
 * Serialise cJSON object to a JSON line and send it over the socket fd.
 * Appends a '\n' terminator (matches Python send_json behaviour).
 *
 * @returns  0 on success, -1 on failure
 */
int send_json_line(int fd, cJSON *obj);

/**
 * Read a '\n'-terminated line from fd and parse it as JSON.
 * Returns a newly allocated cJSON* (caller must cJSON_Delete),
 * or NULL on connection close / parse error.
 */
cJSON *recv_json_line(int fd);

/* -----------------------------------------------------------------------
 * Convenience JSON field accessors
 * ----------------------------------------------------------------------- */

/** Get a string field from a cJSON object. Returns NULL if not found. */
const char *json_get_str(cJSON *obj, const char *key);

/** Get an integer field from a cJSON object. Returns def if not found. */
int json_get_int(cJSON *obj, const char *key, int def);

/** Get a double field from a cJSON object. Returns def if not found. */
double json_get_double(cJSON *obj, const char *key, double def);

/* -----------------------------------------------------------------------
 * Binary Wire Framing (RFC 8446 / RFC 9954 Real-World Protocol Format)
 * ----------------------------------------------------------------------- */

#define WIRE_MAGIC 0x544C5350U /* 'T','L','S','P' */

typedef enum {
    WIRE_MSG_CLIENT_HELLO    = 0x01,
    WIRE_MSG_SERVER_HELLO    = 0x02,
    WIRE_MSG_PQC_CIPHERTEXT  = 0x03,
    WIRE_MSG_SERVER_FINISHED = 0x04
} WireMsgType;

typedef struct __attribute__((packed)) {
    uint32_t magic;         /* WIRE_MAGIC in network byte order */
    uint16_t msg_type;      /* WireMsgType (network byte order) */
    uint16_t combo_id;      /* Cipher suite ID (network byte order) */
    uint32_t payload_len;   /* Length of payload following header (network byte order) */
} WireHeader;

typedef struct __attribute__((packed)) {
    uint8_t  kdf_type;      /* 0 = sha256, 1 = blake3 */
    uint8_t  dispatch_mode; /* 0 = auto, 1 = seq, 2 = par */
    uint16_t c_pub_len;     /* Length of classical public key in bytes */
} ClientHelloMeta;

typedef struct __attribute__((packed)) {
    uint8_t  dispatch_route; /* 0 = seq, 1 = par */
    uint8_t  reserved;
    uint16_t srv_pub_len;    /* Length of server classical public key */
    uint32_t pqc_pk_len;     /* Length of server PQC public key */
} ServerHelloMeta;

/** Read exactly len bytes from fd. Returns 0 on success, -1 on EOF/error. */
int recv_all(int fd, void *buf, size_t len);

/** Write exactly len bytes to fd. Returns 0 on success, -1 on error. */
int send_all(int fd, const void *buf, size_t len);
