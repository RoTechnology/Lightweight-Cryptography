#ifndef IEEE802154_TAKS_WT_H_
#define IEEE802154_TAKS_WT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"

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
void debug_printhex(uint8_t *d, size_t size, uint8_t flags);

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

    //srand(call LocalTime.get());
    for (i = 0; i < 4; ++i) {
        p[i] = rand() & 0xFF;
        q[i] = rand() & 0xFF;
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

/*
void getNonce(uint8_t *out){
    int i;
    int size = COMPLEN;

    for (i = 0;  i<size ; i++) {
        out[i] = 1;
    }
}
*/


void print(uint8_t *input, int size, char *message){
    int i;
    printf("\n\n%s",message);
    for(i = 0; i<size; i++)
        printf("%02x", input[i]);
}

void printEncryptInputElements(uint8_t *out_ciphertext,uint8_t *plaintext,
                               uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC,
                               uint8_t *src_TKC, uint8_t *dst_TKC){
    //printf("\n\nENCRYPT - plaintext: %s",plaintext);
   // print(out_ciphertext,16,"ENCRYPT - out_ciphertext: ");
    //print(out_mac,4,"ENCRYPT - out_mac: ");
    //print(out_kri, 32,"ENCRYPT - out_kri: ");
    print(src_LKC, 32, "ENCRYPT - src_LKC: ");
    print(src_TKC, 32,"ENCRYPT - src_TKC: " );
    print(dst_TKC, 32,"ENCRYPT - dst_TKC: ");
}

void printDecryptInputElements(uint8_t *out_plaintext,uint8_t *ciphertext,
                               uint8_t *mac, uint8_t *kri, uint8_t *node_LKC){
    //printf("\n\nDECRYPT - MESSAGE - PLAINTEXT: %s",out_plaintext);
    print(ciphertext,16,"DECRYPT - CHIPHERTEXT: ");
    print(kri, 32,"DECRYPT - KRI: ");
    print(node_LKC, 32, "DECRYPT - LKC: ");

}

int encrypt_pw(uint8_t *out_ciphertext,uint8_t *plaintext, size_t size,
               uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC,
               uint8_t *src_TKC, uint8_t *dst_TKC){
    uint8_t ss[TAKS_KEY_LEN];
    uint8_t nonce[COMPLEN];
    uint8_t alpha_LKC[COMPLEN];

    printf("\n\n#################################### ENCRYPT #################################");
    printEncryptInputElements(out_ciphertext,plaintext,out_mac,out_kri,src_LKC,src_TKC,dst_TKC);

    // 1. retrieve a nonce
    getNonce(nonce);
    print(nonce,sizeof(nonce),"ENCRYPT - nonce: ");

    // 2. obtain alpha*LKC
    elementwise_mult(alpha_LKC, nonce, src_LKC);

    // 3. obtain the SS
    vector_mult(ss, alpha_LKC, dst_TKC);
    print(ss,16,"ENCRYPT - SS: ");

    // 4. obtain the KRI
    elementwise_mult(out_kri, nonce, src_TKC);
    print(out_kri,32,"ENCRYPT - elementwise_mult - out_kri: ");

    symmetric_encrypt(out_ciphertext, plaintext, size, ss);
    print(out_ciphertext,16,"ENCRYPT - out_ciphertext: ");

    authentication_tag(out_mac, out_ciphertext, size, ss);
    print(out_mac,4,"ENCRYPT - out_mac: ");

    printf("\n\n###################################################################################");
    return 0;
}

int decrypt_pw(uint8_t *out_plaintext,uint8_t *ciphertext, size_t size,
               uint8_t *mac, uint8_t *kri, uint8_t *node_LKC){
    printf("\n\n#################################### DECRYPT #################################");
    int i;
    uint8_t ss[TAKS_KEY_LEN];
    uint8_t computed_mac[TAKS_MAC_LEN];
    size_t minsize;

    printDecryptInputElements(out_plaintext,ciphertext,mac,kri,node_LKC);

    vector_mult(ss, kri, node_LKC);
    print(ss,16,"DECRYPT - SS: ");

    authentication_tag(computed_mac, ciphertext, size, ss);
    print(computed_mac,TAKS_MAC_LEN,"DECRYPT - computed_mac: ");
    print(mac,TAKS_MAC_LEN,"DECRYPT - mac: ");

    for (i = 0; i < TAKS_MAC_LEN; ++i) {
        if (computed_mac[i] != mac[i]) {
            printf("\n\nDECRYPT - SRC_MAC != DES_MAC");
            return -1;
        }
    }
    symmetric_decrypt(out_plaintext, ciphertext, size, ss);
    printf("\n\nDECRYPT - MESSAGE DECRYPTED: %s",out_plaintext);
    printf("\n\n###################################################################################");
    return 0;
}

uint8_t *tc_getY(uint8_t *data) {
    return data+(COMPLEN/2);
}

void componentFromHexString(uint8_t *data, const char *s){
    int i;
    uint8_t subs[2];
    for (i = 0; i < COMPLEN; ++i) {
        uint8_t value;
        subs[0] = s[2*i];
        subs[1] = s[2*i+1];
        value = (uint8_t) strtoul((char*)subs, NULL, 16);
        data[i] = value;
    }
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
