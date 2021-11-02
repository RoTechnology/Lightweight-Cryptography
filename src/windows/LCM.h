//
// Created by Diego Abbatangelo on 26/04/21.
//
#include <stdio.h>
#include <string.h>
#include "Taks.h"
#include <time.h>

uint8_t LKC_0[COMPLEN];
uint8_t LKC_1[COMPLEN];
uint8_t TKC_0_1[COMPLEN];
uint8_t TKC_1_0[COMPLEN];

void initDestKeys(void);
void initSrcKeys(void);
int encrypt(message_t *output, void *inputMessage);
int decrypt(void *output, message_t *msg);
void sendMessage(message_t *msg, char *endpoint);
void hexToStringConverter(char *output, void *hex, int size);
void componentFromHexString(uint8_t *data, const char *s);
void serializeTransmissionMessage(void *out_payload, void *out_KRI, void *out_MAC,
                                  void *in_payload, void *in_KRI, void *in_MAC);

void deserializeTransmissionMessage(message_t *msg,void *in_payload, void *in_KRI, void *in_MAC);

void initSrcKeys(void){
    componentFromHexString(LKC_0, "1F598C9C83D8213F61975A621E10320CE4C182FDC07A92C55009A48209E63308");
    componentFromHexString(TKC_1_0,"5C16A98C1889BCA4BF9AA9C8042CD83A729FA9B4F71384668C793C7B2070C36D");
    componentFromHexString(TKC_0_1,"6034A63B434633E0F2AC5557917796405463B5410F273D82786DC845D7D15780");
}

void initDestKeys(void){
    componentFromHexString(LKC_1,"9BC71C4CBD4B26CE9E5EBC3DD4C777FD42A81703C8DE3E717BF5200E622EA292");
}

int encrypt(message_t *output, void *inputMessage){
    initSrcKeys();
    memcpy(&output->payload[0], inputMessage, TAKS_PAYLOAD_LEN);
    return encrypt_pw(output->payload, inputMessage, TAKS_PAYLOAD_LEN, output->mac, output->kri, LKC_0, TKC_0_1, TKC_1_0);
}

int decrypt(void *output, message_t *msg){
    initDestKeys();
    return decrypt_pw(output, msg->payload, TAKS_PAYLOAD_LEN, msg->mac, msg->kri, LKC_1);
}

void hexToStringConverter(char *output, void *hex, int size){
    char *ptr = &output[0]; 
    uint8_t *byteArray = (uint8_t *)hex;

    int i;

    for (i = 0; i < size; i++) {
        ptr += sprintf(ptr, "%02x", byteArray[i]);
    }

}

void serializeTransmissionMessage(void *out_payload, void *out_KRI, void *out_MAC,
                                  void *in_payload, void *in_KRI, void *in_MAC){
    hexToStringConverter(out_KRI,in_KRI, COMPLEN);
    hexToStringConverter(out_MAC,in_MAC, COMPLEN);
    hexToStringConverter(out_payload,in_payload,TAKS_PAYLOAD_LEN);
}

void deserializeTransmissionMessage(message_t *msg,void *in_payload, void *in_KRI, void *in_MAC){
    uint8_t cipherMessage[COMPLEN];
    uint8_t KRI[COMPLEN];
    uint8_t MAC[COMPLEN];

    componentFromHexString(cipherMessage,in_payload);
    componentFromHexString(MAC,in_MAC);
    componentFromHexString(KRI,in_KRI);

    memcpy(msg->payload, cipherMessage, TAKS_PAYLOAD_LEN);
    memcpy(msg->kri, KRI, TAKS_KRI_LEN);
    memcpy(msg->mac,MAC,TAKS_MAC_LEN);
}

void componentFromHexString(uint8_t *data, const char *s){
    int i;
    uint8_t subs[2];
    for (i = 0; i < COMPLEN; ++i) {
        uint8_t value;
        subs[0] = s[2*i];
        subs[1] = s[2*i+1];
        value = (uint8_t) strtoul((char*)subs, NULL, TAKS_KEY_LEN);
        data[i] = value;
    }
}

void sendMessage(message_t *msg, char *endpoint){
    char KRI[(COMPLEN) + 1];
    char MAC[(TAKS_MAC_LEN * 2) + 1];
    char PAYLOAD[(TAKS_PAYLOAD_LEN * 2) + 1];
    char child2[BUFSIZ];

    serializeTransmissionMessage(PAYLOAD,KRI,MAC,msg->payload,msg->kri,msg->mac);

    strncpy (child2,endpoint,BUFSIZ);
    strncat (child2, " ",BUFSIZ);
    strncat (child2,PAYLOAD,BUFSIZ);
    strncat (child2, " ",BUFSIZ);
    strncat(child2,KRI,BUFSIZ);
    strncat (child2, " ",BUFSIZ);
    strncat (child2, MAC,BUFSIZ);
    system(child2);
}
