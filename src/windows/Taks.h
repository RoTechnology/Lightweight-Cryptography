#ifndef IEEE802154_TAKS_WT_H_
#define IEEE802154_TAKS_WT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include <time.h>

#define TAKS_KEY_LEN 16

#define COMPLEN (TAKS_KEY_LEN*2)
#define TAKS_MAC_LEN 4
#define TAKS_KRI_LEN (TAKS_KEY_LEN*2)
#define POLY 0x11B

#define TAKS_PAYLOAD_LEN 16

#define TAKS_USE_AES
//#define TAKS_SIMPLE

typedef struct message {
    uint16_t counter;
    uint8_t payload[TAKS_PAYLOAD_LEN];
    uint8_t mac[TAKS_MAC_LEN];
    uint8_t kri[TAKS_KRI_LEN];
} message_t;


uint8_t *tc_getY(uint8_t *data);
uint32_t getSeed(void);
void getNonce(uint8_t *out);
uint8_t galois_mult(uint8_t a, uint8_t b);
void elementwise_mult(uint8_t *out, uint8_t *c1, uint8_t *c2);
void vector_mult(uint8_t *out_ss, uint8_t *c1, uint8_t *c2);
void symmetric_encrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
void symmetric_decrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
void authentication_tag(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);

uint32_t getSeed(void)
{
    // TODO - add sensor readings
    return 0x11223344;
}

void getNonce(uint8_t *out)
{
    int i, j;
    uint8_t p[4]; // TODO - increase size
    uint8_t q[4];
    uint32_t *p32 = (uint32_t*)p;
    uint32_t *q32 = (uint32_t*)q;
    uint32_t n;
    uint32_t s;
    uint32_t x;

    srand(time(0));
    for (i = 0; i < 4; ++i) {
        p[i] = (rand()%sizeof (out - 1)) & 0xFF;
        q[i] = (rand()%sizeof (out - 1)) & 0xFF;
    }
    while (((*p32) % 4) != 3) *p32 = (*p32) + 1;
    while (((*q32) % 4) != 3) *q32 = (*q32) + 1;
    n = ((*p32) * (*q32));
    s = getSeed() % n;
    x = (s * s) % n;

    for (i = 0; i < COMPLEN/2; ++i) {
        uint8_t z = 0;
        for (j = 0; j < 8; ++j) {
            x = (x * x) % n;
            z |= x & 1;
            z <<= 1;
        }
        out[i] = tc_getY(out)[i] = z;
    }
}


void print(uint8_t *input, int size, char *message){
    int i;
    printf("\n\n%s",message);
    for(i = 0; i<size; i++)
        printf("%02x", input[i]);
}

int encrypt_pw(uint8_t *out_ciphertext,uint8_t *plaintext, size_t size,
               uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC,
               uint8_t *src_TKC, uint8_t *dst_TKC){
    uint8_t ss[TAKS_KEY_LEN];
    uint8_t nonce[COMPLEN];
    uint8_t alpha_LKC[COMPLEN];

    printf("\n\n    ||------------------------------- TAKS ENCRYPT -------------------------------||");
    printf("\n\n        ENCRYPT - INPUT MESSAGE: ");
    int i;
    for (i = 0; i < TAKS_PAYLOAD_LEN; ++i) {
        printf("%02x", plaintext[i]);
    }
    // 1. retrieve a nonce
    getNonce(nonce);
    // 2. obtain alpha*LKC
    elementwise_mult(alpha_LKC, nonce, src_LKC);
    // 3. obtain the SS
    vector_mult(ss, alpha_LKC, dst_TKC);
    print(ss,TAKS_KEY_LEN,"        ENCRYPT - SS: ");
    // 4. obtain the KRI
    elementwise_mult(out_kri, nonce, src_TKC);
    print(out_kri, TAKS_KRI_LEN, "        ENCRYPT - KRI: ");
    // 5.AES symmetric encrypt
    symmetric_encrypt(out_ciphertext, plaintext, size, ss);
    print(out_ciphertext,TAKS_PAYLOAD_LEN,"        ENCRYPT - CIPHERTEXT: ");

    authentication_tag(out_mac, out_ciphertext, size, ss);
    print(out_mac,4,"        ENCRYPT - MAC: ");

    printf("\n\n    ||----------------------------------------------------------------------------||");
    return 0;
}

int decrypt_pw(uint8_t *out_plaintext,uint8_t *ciphertext, size_t size,
               uint8_t *mac, uint8_t *kri, uint8_t *node_LKC){
    printf("\n\n    ||------------------------------- TAKS DECRYPT -------------------------------||");
    int i;
    uint8_t ss[TAKS_KEY_LEN];
    uint8_t computed_mac[TAKS_MAC_LEN];

    print(ciphertext,TAKS_PAYLOAD_LEN,"        DECRYPT - INPUT CIPHERTEXT: ");

    print(kri, TAKS_KRI_LEN, "        DECRYPT - KRI: ");

    vector_mult(ss, kri, node_LKC);
    print(ss,TAKS_KEY_LEN,"        DECRYPT - SS: ");

    authentication_tag(computed_mac, ciphertext, size, ss);
    print(computed_mac,TAKS_MAC_LEN,"        DECRYPT - MAC: ");

    for (i = 0; i < TAKS_MAC_LEN; ++i) {
        if (computed_mac[i] != mac[i]) {
            printf("\n\n        DECRYPT - SRC_MAC != DES_MAC");
            return -1;
        }
    }
    // AES symmetric decrypt
    symmetric_decrypt(out_plaintext, ciphertext, size, ss);

    printf("\n\n        DECRYPT - MESSAGE DECRYPTED: %s",out_plaintext);
    printf("\n\n    ||----------------------------------------------------------------------------||");
    return 0;
}

uint8_t *tc_getY(uint8_t *data) {
    return data+(COMPLEN/2);
}

uint8_t galois_mult(uint8_t a, uint8_t b){
    uint8_t p = 0;
    while (a && b) {
        if (b & 1)
            p ^= a;
        if (a & 0x80)
            a = (a << 1) ^ POLY;
        else
            a <<= 1;
        b >>= 1;
    }
    return p;
}

void elementwise_mult(uint8_t *out, uint8_t *c1, uint8_t *c2){
    int i;
    for (i = 0; i < COMPLEN; ++i) {
        out[i] = galois_mult(c1[i], c2[i]);
    }
}

void vector_mult(uint8_t *out_ss, uint8_t *c1, uint8_t *c2){
    int i;
    uint8_t *ss = out_ss;
    uint8_t *p1x = c1;
    uint8_t *p1y = tc_getY(c1);
    uint8_t *p2x = c2;
    uint8_t *p2y = tc_getY(c2);
    for (i = 0; i < TAKS_KEY_LEN; ++i) {
        ss[i] = galois_mult(p1x[i], p2x[i]) ^ galois_mult(p1y[i], p2y[i]);
    }
}

void symmetric_encrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k){
#if defined(TAKS_USE_AES)
    AES_Encrypt_CTR(out, k, in, size);
#elif defined(TAKS_SIMPLE)
    int i;
    for (i = 0; i < size; ++i) {
        out[i] = in[i] ^ k[i % TAKS_KEY_LEN];
    }
#else
#error "Don't know how to encrypt"
#endif
}

void symmetric_decrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k){
#if defined(TAKS_USE_AES)
    AES_Decrypt_CTR(out, k, in, size);
#elif defined(TAKS_SIMPLE)
    int i;
    for (i = 0; i < size; ++i) {
        out[i] = in[i] ^ k[i % TAKS_KEY_LEN];
    }
#else
#error "Don't know how to decrypt"
#endif
}

void authentication_tag(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k){
#if defined(TAKS_USE_AES)
    AES_CBC_MAC(out, k, in, size);
#elif defined(TAKS_SIMPLE)
    int i;
    uint8_t checksum = 0;
    for (i = 0; i < size; ++i) {
        checksum += in[i];
    }
    for (i = 0; i < TAKS_KEY_LEN; ++i) {
        checksum += k[i];
    }
    for (i = 0; i < TAKS_MAC_LEN; ++i) {
        out[i] = checksum;
    }
#else
#error "Don't know how to compute auth tag"
#endif
}

void debug_printhex(uint8_t *d, size_t size, uint8_t flags){
    printf("\n\n PRINTHEX: \n");
    int i;
    uint8_t n = 91 + flags;
    printf("\x1b[%2dm", n);
    for (i = 0; i < size; ++i) {
        printf("%02x", d[i]);
    }
    printf("\x1b[0m\r\n");
}

#endif /* end of IEEE802154_TAKS_WT_H_ */
