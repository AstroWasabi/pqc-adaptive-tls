/* c/src/network_utils.c
 * Newline-delimited JSON I/O over raw socket fds, and Base64 encode/decode.
 * Mirrors Python b64e(), b64d(), send_json(), recv_json() in core/crypto_engine.py.
 */

#include "../include/network_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

/* -----------------------------------------------------------------------
 * Base64 encode/decode using OpenSSL BIO chains
 * ----------------------------------------------------------------------- */

char *b64_encode(const uint8_t *src, size_t src_len)
{
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (!b64_bio || !mem_bio) return NULL;

    /* No newlines — match Python base64.b64encode output (no line breaks) */
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_bio, mem_bio);

    BIO_write(b64_bio, src, (int)src_len);
    BIO_flush(b64_bio);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem_bio, &bptr);

    /* Copy into a null-terminated string */
    char *result = malloc(bptr->length + 1);
    if (!result) { BIO_free_all(b64_bio); return NULL; }
    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';

    BIO_free_all(b64_bio);
    return result;
}

int b64_decode(const char *b64, uint8_t *out, size_t max_len)
{
    if (!b64 || !*b64) return 0;

    size_t b64_len = strlen(b64);

    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, (int)b64_len);
    if (!b64_bio || !mem_bio) return -1;

    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_bio, mem_bio);

    int decoded = BIO_read(b64_bio, out, (int)max_len);
    BIO_free_all(b64_bio);

    return (decoded >= 0) ? decoded : -1;
}

/* -----------------------------------------------------------------------
 * send_json_line: serialise and write "JSON\n" to socket fd
 * ----------------------------------------------------------------------- */

int send_json_line(int fd, cJSON *obj)
{
    char *str = cJSON_PrintUnformatted(obj);
    if (!str) return -1;

    size_t len = strlen(str);

    /* Append newline in a single write to avoid TCP fragmentation */
    char *buf = malloc(len + 2);
    if (!buf) { free(str); return -1; }

    memcpy(buf, str, len);
    buf[len]     = '\n';
    buf[len + 1] = '\0';
    free(str);

    ssize_t sent = write(fd, buf, len + 1);
    free(buf);

    return (sent == (ssize_t)(len + 1)) ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * recv_json_line: read up to '\n' from socket fd and parse as JSON
 * ----------------------------------------------------------------------- */

cJSON *recv_json_line(int fd)
{
    /* Grow a dynamic buffer until we hit '\n' */
    size_t cap = 4096;
    size_t used = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    while (1) {
        if (used + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }

        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) { free(buf); return NULL; }  /* connection closed or error */
        if (c == '\n') break;
        buf[used++] = c;
    }

    buf[used] = '\0';
    cJSON *obj = cJSON_Parse(buf);
    free(buf);
    return obj;
}

/* -----------------------------------------------------------------------
 * Convenience JSON field accessors
 * ----------------------------------------------------------------------- */

const char *json_get_str(cJSON *obj, const char *key)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return NULL;
    return item->valuestring;
}

int json_get_int(cJSON *obj, const char *key, int def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return def;
    return (int)item->valuedouble;
}

double json_get_double(cJSON *obj, const char *key, double def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return def;
    return item->valuedouble;
}

/* -----------------------------------------------------------------------
 * Binary framing helpers
 * ----------------------------------------------------------------------- */

int send_all(int fd, const void *buf, size_t len)
{
    size_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len)
{
    size_t total = 0;
    uint8_t *p = (uint8_t *)buf;
    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}
