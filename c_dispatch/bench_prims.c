#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static double bench_ec(int nid) {
    struct timespec t0, t1;
    int runs = 100;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < runs; i++) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
        EVP_PKEY *k1 = NULL, *k2 = NULL;
        EVP_PKEY_generate(pctx, &k1);
        EVP_PKEY_generate(pctx, &k2);
        EVP_PKEY_CTX_free(pctx);
        
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(k1, NULL);
        EVP_PKEY_derive_init(dctx);
        EVP_PKEY_derive_set_peer(dctx, k2);
        size_t slen = 128;
        unsigned char s[128];
        EVP_PKEY_derive(dctx, s, &slen);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(k1);
        EVP_PKEY_free(k2);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return ((t1.tv_sec - t0.tv_sec)*1000.0 + (t1.tv_nsec - t0.tv_nsec)/1000000.0) / runs;
}

static double bench_kem(const char *alg_name) {
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return -1;
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);
    
    int runs = 50;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < runs; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss1, pk);
        OQS_KEM_decaps(kem, ss2, ct, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    OQS_KEM_free(kem);
    return ((t1.tv_sec - t0.tv_sec)*1000.0 + (t1.tv_nsec - t0.tv_nsec)/1000000.0) / runs;
}

int main() {
    printf("Classical ECDH Keypair + Derivation:\n");
    printf("  P-256:             %6.3f ms\n", bench_ec(NID_X9_62_prime256v1));
    printf("  P-384:             %6.3f ms\n", bench_ec(NID_secp384r1));
    printf("  P-521:             %6.3f ms\n", bench_ec(NID_secp521r1));
    
    printf("\nPost-Quantum KEM Keypair + Encaps + Decaps:\n");
    printf("  ML-KEM-768:        %6.3f ms\n", bench_kem("ML-KEM-768"));
    printf("  ML-KEM-1024:       %6.3f ms\n", bench_kem("ML-KEM-1024"));
    printf("  FrodoKEM-1344-AES: %6.3f ms\n", bench_kem("FrodoKEM-1344-AES"));
    printf("  BIKE-L5:           %6.3f ms\n", bench_kem("BIKE-L5"));
    return 0;
}
