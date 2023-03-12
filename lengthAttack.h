//
// Created by baptc on 25/06/2022.
//

#ifndef ASSIGNEMENT_4_2_LENGTHATTACK_H
#define ASSIGNEMENT_4_2_LENGTHATTACK_H

#endif //ASSIGNEMENT_4_2_LENGTHATTACK_H


#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/md5.h>

#define SIZE 1000000

uint32_t* charTounint32_t(unsigned char* hash);
void lengthExtensionAttack(uint8_t * receive_message, uint8_t* receive_hash, uint8_t* attacker_message, unsigned char* forging_hash, uint8_t* forging_message, int length_key, int length_message, int length_message_attacker, int* byteSize);
uint8_t* getHash(uint8_t* message, uint8_t* key, int length_message, int length_key);
int getLength(uint8_t* text);
int serverChecking(uint8_t* key, uint8_t* forging_message,uint8_t* forging_hash, int message_length, int key_length);