//
// Created by baptc on 25/06/2022.
//

#include "lengthAttack.h"

/*
 *
 * This function is used to compute the length of a string of uint8_t which finished by '\0'
 *
 * input :
 *
 * unsigned char* hash : output of MD5_Final(.,.)
 *
 * output : output of MD5_Final(.,.) in uint32_t
 *
 */

int getLength(uint8_t* text){
    int j = 0;
    while(text[j]!='\0'){
        j++;
        if(j>10000000){
            printf("PLEASE PUT \\0 at the end of every messages");
            break;
        }
    }
    return(j);

}

/*
 *
 * This function is used to convert the hash returned by MD5 into a uint32_t[4].
 * Indeed, to modify the internal state of MD5 we must have 4 uin32_t for A,B,C and D
 *
 * input :
 *
 * unsigned char* hash : output of MD5_Final(.,.)
 *
 * output : output of MD5_Final(.,.) in uint32_t
 *
 */

uint32_t* charTounint32_t(unsigned char* hash){

    uint32_t* hl = malloc(sizeof(uint32_t)*4);
    for(int i = 0;i<4;i++){
        hl[i] = 0;
    }
    for (int i = 0; i < 16; i++)
    {
        hl[i/4] +=  hash[i] << (i%4)*8;
    }

    return hl;

}

/*
 *
 * This function allows to calculate the hash for a message and a key : H(key||message)
 *
 * input :
 *
 * uint8_t * message : message we want to hash
 * uint8_t* key : key used before the message for the hash
 * int length_message : length of the message
 * int length_key : length of the key
 *
 * output : H(key||message)
 *
 */

uint8_t * getHash(uint8_t * message, uint8_t* key, int length_message, int length_key){
    unsigned char buffer[MD5_DIGEST_LENGTH];
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, key, length_key);
    MD5_Update(&c, message,length_message);
    MD5_Final(buffer, &c);
    return(memcpy(malloc(sizeof(unsigned char)*MD5_DIGEST_LENGTH),buffer,sizeof(unsigned char)*MD5_DIGEST_LENGTH));
}

/*
 *
 * This function performs the length extension attack. It assumes that the attacker knows the message and the corresponding hash
 * The attacker can either know the length of the key and in this case the attack is direct. Otherwise it is also possible to brute force the length of the key
 * input :
 *
 * uint8_t * receive_message : message intercepted by the attacker and sent by the operator
 * uint8_t* receive_hash : hash intercepted by the attacker and sent by the operator
 * uint8_t* attacker_message : message added by the attacker
 * unsigned char* forging_hash : new hash of (receive_message||padding||attacker_message)
 * uint8_t* forging_message : modified but valid message for the new hash(receive_message||padding||attacker_message)
 * int length_key : length of the key
 * int length_message : length of the message
 * int length_message_attacker : length of the attacker's message
 * int bytesSize : number of bytes
 *
 * output :
 *
 * variables forging_hash,forging_message are updated
 *
 */
void lengthExtensionAttack(uint8_t * receive_message, uint8_t* receive_hash, uint8_t* attacker_message, unsigned char* forging_hash, uint8_t* forging_message, int length_key, int length_message, int length_message_attacker, int* bytesSize){
    uint8_t buffer [SIZE];
    int j = 0;
    int i = 0;
    uint64_t length = (length_message+length_key)*8;
    for(i=0;i<length_message;i++){
        buffer[j]=receive_message[i];
        j++;
    }
    buffer[j] = 0x80;
    j++;
    while((j+length_key)%64 != 56){
        buffer[j] = 0x0;
        j++;
    }



    for(i=0;i<8;i++){
        buffer[j] = (length>>i*8) & 0x00000000000000ff;
        j++;
    }


    int temp = j+length_key;
    for(i = 0;i<length_message_attacker;i++){
        buffer[j] = attacker_message[i];
        j++;
    }

    /*uint8_t * messagepad = complete_pad(receive_message,length_message+length_key,length_key);*/
    //uint8_t* temp = addText(messagepad,attacker_message,bytesSize-length_key,length_message_attacker);
    /*for(int i = 0 ; i <bytesSize-length_key+length_message_attacker;i++){
        forging_message[i] = temp[i];
    }*/
    forging_message = realloc(forging_message, sizeof(uint8_t)*j);
    for(i = 0 ; i <j;i++){
        forging_message[i] = buffer[i];
    }

    *bytesSize = j;

    //***************************************************************************************************

    MD5_CTX c;
    uint32_t* hash = charTounint32_t(receive_hash);
    MD5_Init(&c);
    // we initialize the class MD5

    for(int i = 0;i<(temp/64);i++){
        MD5_Update(&c,"0000000000000000000000000000000000000000000000000000000000000000",64);
    }

    c.A = hash[0];
    c.B = hash[1];
    c.C = hash[2];
    c.D = hash[3];
    MD5_Update(&c,attacker_message,length_message_attacker);
    MD5_Final(forging_hash,&c);
}



/*
 *
 * This function takes as argument a key which is added to the beginning of the message. The function calculates the
 * hash of key||message and compares with the received hash
 *
 * input :
 *
 * uint8_t* key : key
 * uint8_t* message: message
 * uint8_t* received_hash: hash received
 * int message_length : length of the message
 * int key_length : length of the key
 *
 * output :
 *
 * Is the test validated?
 *
 * True: 1
 * False: 0
 *
 */

int serverChecking(uint8_t* key, uint8_t* message,uint8_t* received_hash, int message_length, int key_length){
    uint8_t* hash = getHash(message,key,message_length,key_length);



    for (int i = 0; i < 16; i++) {
        if(hash[i]!=received_hash[i]){
            return(0);
        }
    }
    printf("The following hash is valid :\n");
    for(int i=0;i<16;i++){
        printf("%x",received_hash[i]);

    }
    printf("\n");

    return(1);
}