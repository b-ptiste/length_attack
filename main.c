#include <stdio.h>

#include <string.h>
#include "lengthAttack.h"


/*
 *
 * Final Version
 * I have tried this code with many complicated instances and it always goes to the end, so if there is a problem, let me know!
 * For lauching the code I use command line :
 *
 *      gcc main.c lengthAttack.c -o main.exe -lcrypto
 *      .\main.exe
 *
 * If you want more information on how this works, have a look at the README file attached to this project.
 */
int main() {
    printf("############ START #############\n\n");
    unsigned char buffer[MD5_DIGEST_LENGTH];
    int i;
    uint32_t iv[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

    // /!\ /!\ /!\ /!\ /!\ /!\
    // REALLY IMPORTANT THE ALWAYS HAVE '\0' at the end of messages and key
    //
    // Can work without it but in order to be sure !
    // /!\ /!\ /!\ /!\ /!\ /!\

    uint8_t received_message [1000] = "Hello, I would like to order two pizzas and three drinks for bugers ! My adress is one the main street 1 floor ! thank you in, see U\0";
    int length_message = getLength(received_message);
    uint8_t key [200] = "HardS_cret@!-2Could_be_Re@LLyDifficultvzrvzefdbvzeSFVB GRBAGRZEFSQCV GNTGRFEsqc ZGREADs\0";
    int length_key = getLength(key);
    uint8_t attacker_message [200] = "Could you please send them to this new address - 21 rue jean paul - ? I made a mistake in my last message!\0";
    int length_attacker_message = getLength(attacker_message);
    int lenght_forging_message = 0;
    unsigned char* forging_hash = malloc(sizeof(unsigned char)*1);

    // display variable

    printf("the message sent is : %s\n",received_message);
    printf("the secret key is : %s\n",key);
    printf("the attacker's message is : %s\n",attacker_message);



    int trykeylength = 6;
    int stop = 0;


    uint8_t* received_hash;
    uint8_t* forging_message = malloc(sizeof(uint8_t)*(SIZE));
    received_hash = getHash(received_message,key,length_message,length_key);
    printf("the hash sent with the message is  : \n");
    for(int i = 0 ; i<16;i++){
        printf("%x",received_hash[i]);
    }
    printf("\n-------------------------------------\n");
    printf("\nWe are trying to send a fraudulent message by testing several key sizes with the forging hash\n\n");
    while(stop==0){
        lengthExtensionAttack(received_message,received_hash,attacker_message,forging_hash,forging_message,trykeylength,length_message,length_attacker_message,&lenght_forging_message);
        stop = serverChecking(key,forging_message,forging_hash,lenght_forging_message,length_key);
        trykeylength++;
    }

    printf("\n");
    printf("The length of the key is %d\n\n",trykeylength-1);

    printf("-------------------------------------\n");
    printf("We can also check that the initial message with the hash is accepted by the server\n");
    serverChecking(key,received_message,received_hash,length_message,length_key);
    printf("\n");
    printf("############ END #############");


    return 0;
}
