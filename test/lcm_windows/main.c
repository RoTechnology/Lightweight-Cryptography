#include "LCM.h"


int main(int argc, char **argv){

    message_t temp;
    char decrypted[TAKS_PAYLOAD_LEN];

    if (argc < 2)
        return -1;

    printf("\n\nINPUT MESSAGE - PLAIN TEXT: %s",argv[1]);

    int r = encrypt(&temp,argv[1]);

    if (r == -1) {
        printf("\n\n    ENCRYPT ERROR");
        printf("\n||---------------------------------------------------------------------------------------||\n\n\n\n\n\n\n\n");
        return 0;
    }

    printf("\n\n    Message Encrypted \n");
    printf("\nRESULT: %d", r);

    r = decrypt(decrypted,&temp);
     
    if (r == -1) {
        printf("\n\n    DECRYPT ERROR");
        printf("\n||---------------------------------------------------------------------------------------||\n\n\n\n\n\n\n\n");
        return 0;
    }

    printf("\n\n    Message Decrypted \n");
    printf("\nRESULT: %d\n\n", r);

    return 0;
}