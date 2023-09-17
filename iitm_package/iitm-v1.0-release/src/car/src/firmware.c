#include <stdbool.h>
#include <stdint.h>
#define PART_TM4C123GH6PM 1
#include "random.h"

#include "inc/hw_ints.h"
#include "inc/hw_gpio.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"

#include "uart.h"
#include "time.h"
#include "delay.h"
#include "ascon.h"
#include "brownout.h"
#include "eeprom.h"

#include "secrets.h"


#define NONCELEN 16                             //Nonce length used in ASCON
#define AUTHENTICATED_TAG_LEN 16                //Authenticated Tag length used in ASCON
#define KEYLEN 16                               //Key length used in ASCON
#define SECRET_FLAG_LEN 64                      //Secret Flag length

#define CARIDLEN 1                              //Length of CARID
#define FEATUREIDLEN 1                          //Length of Feature ID
#define FEATURE1LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE2LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE3LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURECHECKLEN 1                       //Length of Feature ID List
#define TOKEN_LEN 16                            //Token Length used in encryptions

#define TOTAL_UNLOCK_KEYS 12                    //Total number of keys

#define CAR_ID 0x40
#define KEYPAIR_START 0x80
#define UNLOCK_MESSAGE_START 0x7c0
#define FEATURE1_MESSAGE_START 0x780
#define FEATURE2_MESSAGE_START 0x740
#define FEATURE3_MESSAGE_START 0x700

#define EEPROM_BLOCK_SIZE 64

inline __attribute__((__always_inline__)) void erase_stack_data(uint8_t *start_add, uint32_t data_len){
    for(uint32_t i=0; i < data_len; i++){
        start_add[i] = 0;
    }
}

/*********************************************************************
 <<<<<<<<<<<<<<<<<<< Code to be modified by Divya to implement EEPROM
***********************************************************************/




/*
Returns a 16 byte random nonce by storing it in array 'nonce'
*/
inline __attribute__((__always_inline__)) void get_nonce(uint8_t* nonce){
    for(uint8_t i = 0; i < NONCELEN; i++)
        nonce[i] = (uint8_t)random_number();
    return;
}


/*
Returns a 16 byte random token by storing it in array 'token'
*/
void get_token(uint8_t* token){
    for(uint8_t i = 0; i < TOKEN_LEN; i++)
        token[i] = (uint8_t)random_number();
    return;
}





//Padding byte at the start and end of the unlock message to ensure alignment
#define PADDING 0b11001100
#define PADDINGLEN 1


//Byte to be sent by the fob to the car at the start of unlocking process to indicate to start the process
#define UNLOCK_FOBTOCAR_STARTBYTE 0b10101010
#define UNLOCK_FOBTOCAR_STARTBYTELEN 1
//Which key_id to use
#define KEYID_LEN 1
//Length of first message to be sent by fob to car
//first message: {start_byte, key_id}
#define UNLOCK_FOBTOCAR_STARTLEN (UNLOCK_FOBTOCAR_STARTBYTELEN + KEYID_LEN)


// Once car receives the message to start the unlock process, It sends an encrypted message containing the token
#define UNLOCK_CARTOFOB_TOKENLEN TOKEN_LEN
// message: {token} so message_length = token_length 
#define UNLOCK_CARTOFOB_MESSAGELEN UNLOCK_CARTOFOB_TOKENLEN
// Encrypted message length = plaintext_length + authenticated_tag_length = token_length + authenticated_tag_length = cipher_text_length
#define UNLOCK_CARTOFOB_ENCRYPTMESSAGELEN (UNLOCK_CARTOFOB_MESSAGELEN + AUTHENTICATED_TAG_LEN)
// Message sent = {padding, nonce, cipher_text, padding}
#define UNLOCK_CARTOFOB_SENDLEN (PADDINGLEN + NONCELEN + UNLOCK_CARTOFOB_ENCRYPTMESSAGELEN + PADDINGLEN)


//Once fob receives the encrypted token, it decrypts the token. Along with the token, car_id, feature_ids 
//are attached and encrypted using another key and sent. 
//The car receives the message, and decrypts the token. If the token is same as the one it sent, then the
//car is unlocked along with printing the secrets. 

//decrypted_message = {token, car_id, feature1id, feature2id, feature3id, featurelist, random_byte, random_byte}
//received_message = {padding, nonce, decrypted_message, authenticated tag, padding}
#define UNLOCK_FOBTOCAR_TOKENLEN TOKEN_LEN
#define UNLOCK_FOBTOCAR_RANDOMLEN 2
#define UNLOCK_FOBTOCAR_MESSAGELEN (UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN + FEATURE3LEN + FEATURECHECKLEN + UNLOCK_FOBTOCAR_RANDOMLEN)
#define UNLOCK_FOBTOCAR_DECRYPTMESSAGELEN (UNLOCK_FOBTOCAR_MESSAGELEN + AUTHENTICATED_TAG_LEN)
#define UNLOCK_FOBTOCAR_RECEIVELEN (PADDINGLEN + NONCELEN + UNLOCK_FOBTOCAR_DECRYPTMESSAGELEN + PADDINGLEN)


//If token matches, an unlock_byte is sent indicating the unlock process is completed
#define UNLOCK_ACK 0b01010101




void unlock_process(){

    int32_t result;
    uint8_t associated_data_temp[1];

    //If no character is received in UART return
    if(!uart_read_avail(UART1_BASE))
        return;
    
    //Receiving first message: {start_byte, key_id}
    uint8_t unlock_start_message[UNLOCK_FOBTOCAR_STARTLEN];
    result = uart_read(UART1_BASE, unlock_start_message, UNLOCK_FOBTOCAR_STARTLEN, 50);
    //If message is not fully received return
    if (result != 0)
        return;

    uint8_t unlock_start_byte = unlock_start_message[0];
    //If the start_byte is not the expected one, then return
    if(unlock_start_byte != UNLOCK_FOBTOCAR_STARTBYTE)
        return;

    //If the start_byte matches, then retrieve the keys used to encrypt and decrypt from EEPROM
    uint8_t key_id = unlock_start_message[1];

    uint8_t decrypt_key[KEYLEN];
    uint8_t encrypt_key[KEYLEN];
    retrieve_unlockkey(key_id, 0, decrypt_key);
    retrieve_unlockkey(key_id, 1, encrypt_key);    

    //Message to be sent from car to fob
    //message: {token}
    //Message sent = {padding, nonce, cipher_text, padding}
    random_mini_delay();
    //get random 16 bytes token
    uint8_t token[UNLOCK_CARTOFOB_TOKENLEN];
    get_token(token);
    random_mini_delay();
    //get random 16 bytes nonce
    uint8_t nonce_send[NONCELEN];
    get_nonce(nonce_send);

    //encrypt the token and store the cipher_text in encrypt_token
    uint8_t encrypt_token[UNLOCK_CARTOFOB_ENCRYPTMESSAGELEN];
    uint32_t encrypt_token_len;
    crypto_aead_encrypt(encrypt_token, &encrypt_token_len, token, UNLOCK_CARTOFOB_MESSAGELEN, associated_data_temp, 0, nonce_send, encrypt_key);
    //if length of cipher text is not matching return. This shouldn't happen
    if (encrypt_token_len != UNLOCK_CARTOFOB_ENCRYPTMESSAGELEN)
        return;

    // {padding, nonce, cipher_text, padding}
    uint8_t token_cartofob_message[UNLOCK_CARTOFOB_SENDLEN];
    token_cartofob_message[0] = PADDING;
    token_cartofob_message[UNLOCK_CARTOFOB_SENDLEN - 1] = PADDING;
    for(uint8_t i = 0; i < NONCELEN; i++)
        token_cartofob_message[PADDINGLEN + i] = nonce_send[i];
    for(uint8_t i = 0; i < UNLOCK_CARTOFOB_ENCRYPTMESSAGELEN; i++)
        token_cartofob_message[PADDINGLEN + NONCELEN + i] = encrypt_token[i];

    // Send the data
    uart_write(UART1_BASE, token_cartofob_message, UNLOCK_CARTOFOB_SENDLEN);





    //Once fob receives the encrypted token, it decrypts the token. Along with the token, car_id, feature_ids 
    //are attached and encrypted using another key and sent. 
    //The car receives the message, and decrypts the token. If the token is same as the one it sent, then the
    //car is unlocked along with printing the secrets. 

    // Receive encrypted version of {token, car_id, feature1id, feature2id, feature3id, featurelist, random_byte, random_byte}
    uint8_t token_fobtocar_message[UNLOCK_FOBTOCAR_RECEIVELEN];
    // Read the message from UART
    result = uart_read(UART1_BASE, token_fobtocar_message, UNLOCK_FOBTOCAR_RECEIVELEN, 250);
    // If expected message is not fully received return;
    if(result!=0)
        return;

    // If the first and last byte are not expected, indicating misalignment - Return
    if(token_fobtocar_message[0] != PADDING)
        return;
    if(token_fobtocar_message[UNLOCK_FOBTOCAR_RECEIVELEN-1] != PADDING)
        return;

    // Get the nonce from the message
    uint8_t nonce_receive[NONCELEN];
    for (uint8_t i = 0; i < NONCELEN; i++)
        nonce_receive[i] = token_fobtocar_message[PADDINGLEN + i];

    // Get the cipher text from the message
    uint8_t ciphertext[UNLOCK_FOBTOCAR_DECRYPTMESSAGELEN];
    for(uint8_t i = 0; i < UNLOCK_FOBTOCAR_DECRYPTMESSAGELEN; i++)
        ciphertext[i] = token_fobtocar_message[PADDINGLEN + NONCELEN + i];

    // Decrypt the cipher message using the key, nonce
    uint8_t decrypt_message[UNLOCK_FOBTOCAR_MESSAGELEN];
    uint32_t decrypt_message_len;
    result = crypto_aead_decrypt(decrypt_message, &decrypt_message_len, ciphertext, UNLOCK_FOBTOCAR_DECRYPTMESSAGELEN, associated_data_temp, 0, nonce_receive, decrypt_key);
    random_mini_delay();
    //If authentication failed return
    if (result != 0){
        large_delay();
        SysCtlReset();
    }
    //If decrypted message length is not same as expected
    if (decrypt_message_len != UNLOCK_FOBTOCAR_MESSAGELEN)
        return;

    bool correct_token = true;
    //Check whether token is same as expected.
    for (uint8_t i = 0; i < TOKEN_LEN; i++){
        random_micro_delay();
        if(token[i] != decrypt_message[i]) 
            correct_token = false;
    }
    random_mini_delay();
    if(correct_token == false){
        large_delay();
        SysCtlReset();
    }

    random_mini_delay();
    //Check whether the CAR_ID is same as the car's
    if(decrypt_message[UNLOCK_FOBTOCAR_TOKENLEN] != retrieve_carid()){
        large_delay();
        SysCtlReset();
    }

    //If CAR_ID matches, the received token is same as the one we sent, then read the features
    uint8_t feature1id = decrypt_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN];
    uint8_t feature2id = decrypt_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN];
    uint8_t feature3id = decrypt_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN];
    uint8_t featurelist = decrypt_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN + FEATURE3LEN];
    
    //Note featurelist is a single byte entity where only the LSB 3 bits are valid 
    //0b000001xx indicates first feature is valid
    //0b00000x1x indicates second feature is valid
    //0b00000xx1 indicates third feature is valid





    //Send the acknowledgement byte indicating unlocking process is complete
    uint8_t unlock_ack = UNLOCK_ACK;
    uart_write(UART1_BASE, &unlock_ack, 1);

    erase_stack_data(decrypt_key, KEYLEN);
    erase_stack_data(encrypt_key, KEYLEN);

    uint8_t unlock_secret[SECRET_FLAG_LEN];
    retrieve_unlock_secret(unlock_secret);
    uart_write(UART0_BASE, unlock_secret, SECRET_FLAG_LEN);

    uint8_t feature1_secret[SECRET_FLAG_LEN];
    uint8_t feature2_secret[SECRET_FLAG_LEN];
    uint8_t feature3_secret[SECRET_FLAG_LEN];

    //Print features only when they are valid
    random_mini_delay();
    if((featurelist & 0b00000100) == 0b00000100 && feature1id == 1){
        retrieve_feature1_secret(feature1_secret);
        uart_write(UART0_BASE, feature1_secret, SECRET_FLAG_LEN);
    }
    random_mini_delay();
    if((featurelist & 0b00000010) == 0b00000010 && feature2id == 2){
        retrieve_feature2_secret(feature2_secret);
        uart_write(UART0_BASE, feature2_secret, SECRET_FLAG_LEN);
    }
    random_mini_delay();
    if((featurelist & 0b00000001) == 0b00000001 && feature3id == 3){
        retrieve_feature3_secret(feature3_secret);
        uart_write(UART0_BASE, feature3_secret, SECRET_FLAG_LEN);
    }
}

void setup()
{
    // unsigned int num = arr[10];
    // srand((unsigned int) num);
    set_processor_clock();
    srand(random_seed_generator());
    set_brownout_protection();
    start_time();
    eeprom_init();

    uart_board_init();
    uart_hosttools_init();
}

void loop()
{
    unlock_process();       
}


int main(void){
    setup();
    while(true)
        loop();
}

