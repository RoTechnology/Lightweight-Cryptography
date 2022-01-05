#include <stdio.h>
#include <string.h>
#include "Taks.h"
#include <time.h>

uint8_t LKC_0[COMPLEN];
uint8_t LKC_1[COMPLEN];
uint8_t TKC_0_1[COMPLEN];
uint8_t TKC_1_0[COMPLEN];

void initNodes(void);
int encryptMessage(message_t *output, char *inputMessage);
int decryptMessage(char *output, message_t *msg);

void initNodes(void)
{
    componentFromHexString(LKC_0, "1F598C9C83D8213F61975A621E10320CE4C182FDC07A92C55009A48209E63308");
    componentFromHexString(LKC_1,"9BC71C4CBD4B26CE9E5EBC3DD4C777FD42A81703C8DE3E717BF5200E622EA292");
    componentFromHexString(TKC_1_0,"5C16A98C1889BCA4BF9AA9C8042CD83A729FA9B4F71384668C793C7B2070C36D");
    componentFromHexString(TKC_0_1,"6034A63B434633E0F2AC5557917796405463B5410F273D82786DC845D7D15780");
}

int encryptMessage(message_t *output, char *inputMessage)
{
    memcpy(&output->payload[0], inputMessage, TAKS_PAYLOAD_LEN);
    return encrypt_pw(output->payload, inputMessage, TAKS_PAYLOAD_LEN, output->mac, output->kri, LKC_0, TKC_0_1, TKC_1_0);
}

int decryptMessage(char *output, message_t *msg)
{
    return decrypt_pw(output, msg->payload, TAKS_PAYLOAD_LEN, msg->mac, msg->kri, LKC_1);
}