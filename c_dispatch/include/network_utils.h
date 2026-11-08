/* c_dispatch/include/network_utils.h
 * Real-World TLS 1.3 Wire Framing (RFC 8446 / RFC 9954)
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

/* -----------------------------------------------------------------------
 * Base64 helpers
 * ----------------------------------------------------------------------- */
char *b64_encode(const uint8_t *src, size_t src_len);
int   b64_decode(const char *b64, uint8_t *out, size_t max_len);

/* -----------------------------------------------------------------------
 * Binary Wire Framing V2 (RFC 8446 / RFC 9954 Real-World Protocol Format)
 *
 * Wire Flow:
 *   1. Client -> Server: ClientHello
 *      Header: combo_id, payload_len
 *      Meta:   kdf_type, c_pub_len, pqc_pk_len
 *      Data:   c_pub || pqc_pk
 *
 *   2. Server -> Client: ServerHello
 *      Header: combo_id, payload_len
 *      Meta:   srv_pub_len, pqc_ct_len
 *      Data:   srv_pub || pqc_ct
 *
 *   3. Server -> Client: ServerFinished
 *      Header: combo_id, payload_len = 32
 *      Data:   HMAC key confirmation tag (32 bytes)
 * ----------------------------------------------------------------------- */

#define WIRE_MAGIC_V2 0x544C5332U /* 'T','L','S','2' */

typedef enum {
    WIRE_MSG_CLIENT_HELLO    = 0x11,
    WIRE_MSG_SERVER_HELLO    = 0x12,
    WIRE_MSG_SERVER_FINISHED = 0x14
} WireMsgTypeV2;

typedef struct __attribute__((packed)) {
    uint32_t magic;         /* WIRE_MAGIC_V2 in network byte order */
    uint16_t msg_type;      /* WireMsgTypeV2 (network byte order) */
    uint16_t combo_id;      /* Cipher suite ID (network byte order) */
    uint32_t payload_len;   /* Length of payload following header (network byte order) */
} WireHeaderV2;

typedef struct __attribute__((packed)) {
    uint8_t  kdf_type;      /* 0 = sha256, 1 = blake3 */
    uint8_t  reserved;
    uint16_t c_pub_len;     /* Length of classical public key in bytes */
    uint32_t pqc_pk_len;    /* Length of client PQC public key in bytes */
} ClientHelloMetaV2;

typedef struct __attribute__((packed)) {
    uint16_t srv_pub_len;   /* Length of server classical public key */
    uint16_t reserved;
    uint32_t pqc_ct_len;    /* Length of PQC ciphertext */
} ServerHelloMetaV2;

/** Read exactly len bytes from fd. Returns 0 on success, -1 on EOF/error. */
int recv_all(int fd, void *buf, size_t len);

/** Write exactly len bytes to fd. Returns 0 on success, -1 on error. */
int send_all(int fd, const void *buf, size_t len);
