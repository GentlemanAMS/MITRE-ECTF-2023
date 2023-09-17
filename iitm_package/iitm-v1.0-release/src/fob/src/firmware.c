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
#include "driverlib/uart.h"

#include "uart.h"
#include "time.h"
#include "ascon.h"
#include "delay.h"
#include "brownout.h"
#include "eeprom.h"

#include "secrets.h"


#define NONCELEN 16                             //Nonce length used in ASCON
#define AUTHENTICATED_TAG_LEN 16                //Authenticated Tag length used in ASCON
#define KEYLEN 16                               //Key length used in ASCON
#define SECRET_FLAG_LEN 64                      //Secret Flag length

#define PAIRINGPINLEN 6                         //Length of Pairing PIN
#define CARIDLEN 1                              //Length of CARID
#define FEATUREIDLEN 1                          //Length of Feature ID
#define FEATURE1LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE2LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE3LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURECHECKLEN 1                       //Length of Feature ID List
#define TOKEN_LEN 16                            //Token Length used in encryptions
#define EXTRA_3 3                                //To make data to be written in eeeprom multiple of 4
#define EXTRA_2 2 

#define PAIRED_BOOL 0b01111111
#define TOTAL_UNLOCK_KEYS 12                    //Total number of keys

#define PAIRED_BOOL_START 0x40                  //Starting address of pair_bool
#define CARID_START 0x80                        //Starting address of CAR_ID
#define CARPIN_START 0xC0                       //Starting address of pairing pin
#define FEATURE_INFO_START 0x100                //Starting address of feature info
#define PACKAGEKEY_START 0x140                  //Starting address of package key
#define KEYPAIR_START 0x180                     //Starting address of unlock key

#define EEPROM_BLOCK_SIZE 64


/**
 * @brief 
 * Configures GPIO Pins to set up the switch
 */
void switch_setup(void){
    //Enables Peripheral GPIOF for switch
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF));

    //Sets GPIO Pin 4 for switch and configures to it act as a pull-up
    GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
    GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);
}


/**
 * @brief 
 * Erase stack data. Zeroes array values
 */
inline __attribute__((__always_inline__)) void erase_stack_data(uint8_t *start_add, uint32_t data_len){
    for(uint32_t i=0; i < data_len; i++){
        start_add[i] = 0;
    }
}

/**
 * @brief 
 * Returns a 16 byte random nonce by storing it in array 'nonce'
 */
inline __attribute__((__always_inline__)) void get_nonce(uint8_t* nonce){
    for(uint8_t i = 0; i < NONCELEN; i++)
        nonce[i] = (uint8_t)random_number();
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
#define UNLOCK_CARTOFOB_DECRYPTMESSAGELEN (UNLOCK_CARTOFOB_MESSAGELEN + AUTHENTICATED_TAG_LEN)
// Message received = {padding, nonce, cipher_text, padding}
#define UNLOCK_CARTOFOB_RECEIVELEN (PADDINGLEN + NONCELEN + UNLOCK_CARTOFOB_DECRYPTMESSAGELEN + PADDINGLEN)


//Once fob receives the encrypted token, it decrypts the token. Along with the token, car_id, feature_ids 
//are attached and encrypted using another key and sent. 
//The car receives the message, and decrypts the token. If the token is same as the one it sent, then the
//car is unlocked along with printing the secrets. 

//encrypting_message = {token, car_id, feature1id, feature2id, feature3id, featurelist, random_byte, random_byte}
//send_message = {padding, nonce, encrypting_message, authenticated tag, padding}
#define UNLOCK_FOBTOCAR_TOKENLEN TOKEN_LEN
#define UNLOCK_FOBTOCAR_RANDOMLEN 2
#define UNLOCK_FOBTOCAR_MESSAGELEN (UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN + FEATURE3LEN + FEATURECHECKLEN + UNLOCK_FOBTOCAR_RANDOMLEN)
#define UNLOCK_FOBTOCAR_ENCRYPTMESSAGE_LEN (UNLOCK_FOBTOCAR_MESSAGELEN + AUTHENTICATED_TAG_LEN)
#define UNLOCK_FOBTOCAR_SENDLEN (PADDINGLEN + NONCELEN + UNLOCK_FOBTOCAR_ENCRYPTMESSAGE_LEN + PADDINGLEN)

//If token matches, an unlock_byte is received indicating the unlock process is completed
#define UNLOCK_ACK 0b01010101


void unlock_process(){

    int32_t result;
    uint8_t associated_data_temp[1];

    random_mini_delay();
    //Generate a random key id byte
    uint8_t key_id = (uint8_t)(random_number() % TOTAL_UNLOCK_KEYS);
    //set start byte
    uint8_t unlock_start_byte = UNLOCK_FOBTOCAR_STARTBYTE;

    uint8_t unlock_start_message[UNLOCK_FOBTOCAR_STARTLEN];
    unlock_start_message[0] = unlock_start_byte;
    unlock_start_message[1] = key_id;

    uint8_t decrypt_key[KEYLEN];
    uint8_t encrypt_key[KEYLEN];
    retrieve_unlockkey(key_id, 0, decrypt_key);
    retrieve_unlockkey(key_id, 1, encrypt_key);  

    //Send the 'start_unlock' message: {start_byte, key_id}
    uart_write(UART1_BASE, unlock_start_message, UNLOCK_FOBTOCAR_STARTLEN);  

    //Message to be sent from car to fob
    //message: {token}
    //Message received = {padding, nonce, cipher_text, padding}

    uint8_t token_cartofob_message[UNLOCK_CARTOFOB_RECEIVELEN];
    result = uart_read(UART1_BASE, token_cartofob_message, UNLOCK_CARTOFOB_RECEIVELEN, 250);
    
    //If message is not fully received return
    if (result != 0)
        return;

    // If the first and last byte are not expected, indicating misalignment
    if(token_cartofob_message[0] != PADDING)
        return;
    if(token_cartofob_message[UNLOCK_CARTOFOB_RECEIVELEN - 1] != PADDING)
        return;

    //{padding, nonce, cipher_text, padding}
    //Get Nonce from received message
    uint8_t nonce_receive[NONCELEN];
    for (uint8_t i = 0; i < NONCELEN; i++)
        nonce_receive[i] = token_cartofob_message[PADDINGLEN + i];

    //Get cipher_text from received message
    uint8_t ciphertext[UNLOCK_CARTOFOB_DECRYPTMESSAGELEN];
    for (uint8_t i = 0; i < (UNLOCK_CARTOFOB_DECRYPTMESSAGELEN); i++)
        ciphertext[i] = token_cartofob_message[PADDINGLEN + NONCELEN + i];

    //Decrypt the cipher_text to get the token
    uint8_t token[UNLOCK_CARTOFOB_TOKENLEN];
    uint32_t token_length_check;
    result = crypto_aead_decrypt(token, &token_length_check, ciphertext, UNLOCK_CARTOFOB_DECRYPTMESSAGELEN, associated_data_temp, 0, nonce_receive, decrypt_key);
    erase_stack_data(decrypt_key, KEYLEN);
    
    random_mini_delay();
    //Authentication of message failed
    if (result != 0){
        large_delay();
        SysCtlReset();
    }

    //If the expected message length is not the same as received
    if(token_length_check != UNLOCK_CARTOFOB_TOKENLEN)
        return;

    //get random 16 bytes nonce
    uint8_t nonce_send[NONCELEN];
    random_mini_delay();
    get_nonce(nonce_send);

    //Retrieve CAR ID, Feature IDs and valid feature list
    uint8_t carid = retrieve_carid();
    uint8_t feature1id = retrieve_feature1();
    uint8_t feature2id = retrieve_feature2();
    uint8_t feature3id = retrieve_feature3();
    uint8_t featurelist = retrieve_featurelist();

    //{token, car_id, feature1id, feature2id, feature3id, featurelist, random_byte, random_byte}
    uint8_t token_fobtocar_message[UNLOCK_FOBTOCAR_MESSAGELEN]; 
    for(uint8_t i=0 ; i < UNLOCK_FOBTOCAR_TOKENLEN; i++)
        token_fobtocar_message[i] = token[i];
    token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN] = carid;
    token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN] = feature1id;
    token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN] = feature2id;
    token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN] = feature3id;
    token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN + FEATURE3LEN] = featurelist;
    for(uint8_t i=0; i < UNLOCK_FOBTOCAR_RANDOMLEN; i++)
        token_fobtocar_message[UNLOCK_FOBTOCAR_TOKENLEN + CARIDLEN + FEATURE1LEN + FEATURE2LEN + FEATURE3LEN + FEATURECHECKLEN + i] = (uint8_t)random_number();
    
    //Encrypt the message to be sent
    uint8_t encrypted_token_message[UNLOCK_FOBTOCAR_ENCRYPTMESSAGE_LEN];
    uint32_t encrypted_token_message_len;
    crypto_aead_encrypt(encrypted_token_message,  &encrypted_token_message_len, token_fobtocar_message, UNLOCK_FOBTOCAR_MESSAGELEN, associated_data_temp, 0, nonce_send, encrypt_key);
    erase_stack_data(encrypt_key, KEYLEN);

    //If the encrypted message length is not the same as expected
    if(encrypted_token_message_len != UNLOCK_FOBTOCAR_ENCRYPTMESSAGE_LEN)
        return;
    
    //{padding, nonce, cipher_text, padding}
    uint8_t send_encrypt_message[UNLOCK_FOBTOCAR_SENDLEN];
    send_encrypt_message[0] = (uint8_t)PADDING;
    send_encrypt_message[UNLOCK_FOBTOCAR_SENDLEN - 1] = (uint8_t)PADDING;
    for (uint8_t i=0; i < NONCELEN; i++)
        send_encrypt_message[PADDINGLEN + i] = nonce_send[i];
    for (uint8_t i=0; i < UNLOCK_FOBTOCAR_ENCRYPTMESSAGE_LEN; i++)
        send_encrypt_message[PADDINGLEN + NONCELEN + i] = encrypted_token_message[i];
    
    //Send the message to the car
    uart_write(UART1_BASE, send_encrypt_message, UNLOCK_FOBTOCAR_SENDLEN);





    //Received the acknowledgement byte indicating unlocking process is complete
    uint8_t unlock_ack;
    result = uart_read(UART1_BASE, &unlock_ack, 1, 250);

    //If message is not fully received return
    if (result != 0)
        return;

    //If the acknowledgement_byte is not the expected one, then return
    if (unlock_ack != UNLOCK_ACK){
        return;
    }
}






#define PAIRING_ACK 0b00100110

/*
Call this function when pairing process starts for a paired fob
*/
void pairing_process_pairedfob(){

    uart_write(UART0_BASE, (uint8_t*)"P", 1);

    int32_t result;
    uint8_t ack;

    //Receive the pairing pin from host_tools through UART
    uint8_t received_pin[PAIRINGPINLEN];
    result = uart_read(UART0_BASE, received_pin, PAIRINGPINLEN, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;

    random_mini_delay();
    //Retrieve the pairing pin from EEPROM
    uint8_t pairing_pin[PAIRINGPINLEN];
    retrieve_pair_pin(pairing_pin);
    //If the pairing_pin is same as the received pin, then proceed forward with pairing process
    bool correct_pin = true;
    for(uint8_t i = 0; i < PAIRINGPINLEN; i++){   
        random_micro_delay(); 
        if (received_pin[i] != pairing_pin[i])
            correct_pin = false;
    }
    random_mini_delay();
    if(correct_pin == false){
        large_delay();
        SysCtlReset();
    }

    uint8_t package_key[KEYLEN];
    retrieve_packagekey(package_key);

    //Send the pairing pin to the unpairied fob
    uart_write(UART1_BASE, pairing_pin, PAIRINGPINLEN);
    erase_stack_data(pairing_pin, PAIRINGPINLEN);

    //Wait for acknowledgment from unpaired fob
    result = uart_read(UART1_BASE, &ack, 1, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;
    //If the acknowledgement_byte is not the expected one, then return
    if (ack != PAIRING_ACK) 
        return;


    uint8_t car_id = retrieve_carid();
    //Send the Car ID to the unpairied fob
    uart_write(UART1_BASE, &car_id, CARIDLEN);
    erase_stack_data(&car_id, CARIDLEN);

    //Wait for acknowledgment from unpaired fob
    result = uart_read(UART1_BASE, &ack, 1, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;
    //If the acknowledgement_byte is not the expected one, then return
    if (ack != PAIRING_ACK) 
        return;



    //Send all the unlock keys to the unpairied fob
    uint8_t key[TOTAL_UNLOCK_KEYS][2][KEYLEN]; 
    for (int i = 0; i < TOTAL_UNLOCK_KEYS; i++){

        retrieve_unlockkey(i, 0, key[i][0]);

        //Retrieve the key 0 for keyID 'i' from EEPROM
        //Send the key to the unpaired fob
        uart_write(UART1_BASE, key[i][0], KEYLEN/2);
        result = uart_read(UART1_BASE, &ack, 1, 1000);
        if(result != 0) return;
        if(ack != PAIRING_ACK) return;

        uart_write(UART1_BASE, key[i][0]+KEYLEN/2, KEYLEN/2);
        erase_stack_data(key[i][0], KEYLEN);
        result = uart_read(UART1_BASE, &ack, 1, 1000);
        if(result != 0) return;
        if(ack != PAIRING_ACK) return;

        retrieve_unlockkey(i, 1, key[i][1]);

        //Retrieve the key 1 for keyID 'i'
        //Send the key to the unpaired fob
        uart_write(UART1_BASE, key[i][1], KEYLEN/2);
        //Wait for acknowledgment from unpaired fob
        result = uart_read(UART1_BASE, &ack, 1, 1000);
        //If message is not fully received then return
        if (result != 0) return;
        //If the acknowledgement_byte is not the expected one, then return
        if (ack != PAIRING_ACK) return;

        uart_write(UART1_BASE, key[i][1]+KEYLEN/2, KEYLEN/2);
        erase_stack_data(key[i][1], KEYLEN);
        result = uart_read(UART1_BASE, &ack, 1, 1000);
        if(result != 0) return;
        if(ack != PAIRING_ACK) return;
    }


    //Retrieve the key used for packaging from EEPROM
    //Send the key to the unpaired fob
    uart_write(UART1_BASE, package_key, KEYLEN/2);
    //Wait for acknowledgment from unpaired fob
    result = uart_read(UART1_BASE, &ack, 1, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;
    //If the acknowledgement_byte is not the expected one, then return
    if (ack != PAIRING_ACK) 
        return;

    uart_write(UART1_BASE, package_key+KEYLEN/2, KEYLEN/2);
    erase_stack_data(package_key, KEYLEN);
    result = uart_read(UART1_BASE, &ack, 1, 1000);
    if(result != 0) return;
    if(ack != PAIRING_ACK) return;
    
    // Change LED color: green
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g

    //Pairing process complete
}






/**
 * @brief 
 * Call this function when pairing process starts for paired fob
 */
void pairing_process_unpairedfob(){

    int32_t result;   
    uint8_t ack = PAIRING_ACK;

    uint8_t pairing_pin[PAIRINGPINLEN];
    
    //Receive the pairing pin from paired fob through UART
    result = uart_read(UART1_BASE, pairing_pin, PAIRINGPINLEN, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;
    //Send Acknowledgment 
    uart_write(UART1_BASE, &ack, 1);


    uint8_t car_id;
    //Receive the car ID from paired fob through UART
    result = uart_read(UART1_BASE, &car_id, CARIDLEN, 1000);
    //If message is not fully received then return
    if (result != 0) 
        return;    
    //Send Acknowledgment 
    uart_write(UART1_BASE, &ack, 1);


    //Receiving and Storing the unlock keys into EEPROM
    uint8_t key[TOTAL_UNLOCK_KEYS][2][KEYLEN]; 
    for (int i = 0; i < TOTAL_UNLOCK_KEYS; i++){

        result = uart_read(UART1_BASE, key[i][0], KEYLEN/2, 1000);
        //If message is not fully received then return
        if (result != 0) return;
        uart_write(UART1_BASE, &ack, 1);

        result = uart_read(UART1_BASE, key[i][0]+KEYLEN/2, KEYLEN/2, 1000);
        //If message is not fully received then return
        if (result != 0) return;
        uart_write(UART1_BASE, &ack, 1);

        result = uart_read(UART1_BASE, key[i][1], KEYLEN/2, 1000);
        //If message is not fully received then return
        if (result != 0) return;
        uart_write(UART1_BASE, &ack, 1);

        result = uart_read(UART1_BASE, key[i][1]+KEYLEN/2, KEYLEN/2, 1000);
        //If message is not fully received then return
        if (result != 0) return;
        uart_write(UART1_BASE, &ack, 1);
    }

    //Receive the packaging key from UART
    uint8_t package_key[KEYLEN];
    result = uart_read(UART1_BASE, package_key, KEYLEN/2, 1000);
    //If message is not fully received then return
    if (result != 0) return;
    uart_write(UART1_BASE, &ack, 1);

    result = uart_read(UART1_BASE, package_key+KEYLEN/2, KEYLEN/2, 1000);
    //If message is not fully received then return
    if (result != 0) return;
    uart_write(UART1_BASE, &ack, 1);

    //Pairing process done

    // Change LED color: red
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g

    uart_write(UART0_BASE, (uint8_t*)"P", 1);

    store_pair_pin(pairing_pin);
    erase_stack_data(pairing_pin, PAIRINGPINLEN);
    store_carid(car_id);
    erase_stack_data(&car_id, CARIDLEN);

    // EEPROMProgram((uint32_t *)key, KEYPAIR_START, TOTAL_UNLOCK_KEYS * 2 * KEYLEN);
    for(int i=0; i < TOTAL_UNLOCK_KEYS; i++){
        store_unlockkey(i, 0, key[i][0]);
        erase_stack_data(key[i][0], KEYLEN);
        store_unlockkey(i, 1, key[i][1]);
        erase_stack_data(key[i][1], KEYLEN);
    }
    store_packagekey(package_key);
    erase_stack_data(package_key, KEYLEN);
    //Fob is paired. Store the information
    store_pair_bool(true);

}









// message: {car_id, feature_id, random_byte, random_byte, random_byte, random_byte}
#define ENABLEFEATURE_RANDOMLEN 4
#define ENABLEFEATURE_MESSAGELEN (CARIDLEN + FEATUREIDLEN +  ENABLEFEATURE_RANDOMLEN)
#define ENABLEFEATURE_DECRYPTMESSAGELEN (ENABLEFEATURE_MESSAGELEN + AUTHENTICATED_TAG_LEN)
// Received message : {nonce, cipher_text}
#define ENABLEFEATURE_RECEIVELEN (NONCELEN + ENABLEFEATURE_DECRYPTMESSAGELEN)


/**
 * @brief 
 * This function is used to enable a feature
 */
void enablefeature_process(){

    int32_t result;
    uint8_t associated_data_temp[1];

    //If the fob is not paired, then return
    random_mini_delay();
    if(!retrieve_pair_bool()){
        large_delay();
        SysCtlReset();
    }


    //Receive the packaged feature
    uint8_t receive_message[ENABLEFEATURE_RECEIVELEN];
    result = uart_read(UART0_BASE, receive_message, 8, 150);
    if (result != 0) 
        return;
    result = uart_read(UART0_BASE, receive_message+8, 8, 150);
    if (result != 0) 
        return;
    result = uart_read(UART0_BASE, receive_message+16, 8, 150);
    if (result != 0) 
        return;
    result = uart_read(UART0_BASE, receive_message+24, 8, 150);
    if (result != 0) 
        return;
    result = uart_read(UART0_BASE, receive_message+32, 6, 150);
    if (result != 0) 
        return;


    //Copy the nonce from the received message
    uint8_t nonce[NONCELEN];
    for (uint8_t i = 0; i < NONCELEN; i++)
        nonce[i] = receive_message[i];

    //Copy the cipher_text from the received message
    uint8_t cipher_text[ENABLEFEATURE_DECRYPTMESSAGELEN];    
    for (uint8_t i = 0; i < ENABLEFEATURE_DECRYPTMESSAGELEN; i++)
        cipher_text[i] = receive_message[NONCELEN + i];

    //Retrieve the key used to package the feature
    uint8_t key[KEYLEN];
    retrieve_packagekey(key);


    //Start the decrypting process
    uint8_t decrypt_plaintext[ENABLEFEATURE_MESSAGELEN];
    uint32_t decrypt_plaintext_len;
    result = crypto_aead_decrypt(decrypt_plaintext, &decrypt_plaintext_len, cipher_text, ENABLEFEATURE_DECRYPTMESSAGELEN, associated_data_temp, 0, nonce, key); 
    
    //Since 'key' is not required anymore, erase them.
    erase_stack_data(key, KEYLEN);   
    
    //If Authentication fails, then return
    random_mini_delay();
    if (result != 0) {
        large_delay();
        SysCtlReset();
    }
    
    //if the received message length is not the one we expected
    if(decrypt_plaintext_len != ENABLEFEATURE_MESSAGELEN)
        return;


    //Get car_id and feature_id from the received message
    uint8_t received_carid = decrypt_plaintext[0];
    uint8_t featureid = decrypt_plaintext[1];

    random_mini_delay();
    //If retrieved car_id doesn't match, then return
    if (received_carid != retrieve_carid()){
        large_delay();
        SysCtlReset();
    }
    
    // If the feature list is full, then return
    // Only LSB 3 bits of feature list are valid
    // 0b000001xx indicates first feature is valid
    // 0b00000x1x indicates second feature is valid
    // 0b00000xx1 indicates third feature is valid
    random_mini_delay();
    if (retrieve_featurelist() == 0b00000111)
        return;


    //If featureid is already present then return 
    random_mini_delay();
    if ((retrieve_featurelist() & 0b00000100) == 0b00000100 && featureid == 1)
        return;
    random_mini_delay();
    if ((retrieve_featurelist() & 0b00000010) == 0b00000010 && featureid == 2)
        return;
    random_mini_delay();
    if ((retrieve_featurelist() & 0b00000001) == 0b00000001 && featureid == 3)
        return;

    //Store the feature in the EEPROM. 
    random_mini_delay();
    if (featureid == 1 && (retrieve_featurelist() & 0b00000100) == 0b00000000){
        store_feature1(featureid);
        uart_write(UART0_BASE, (uint8_t *)"Enabled", 7);
        return;
    }
    random_mini_delay();
    if (featureid == 2 && (retrieve_featurelist() & 0b00000010) == 0b00000000){
        store_feature2(featureid);
        uart_write(UART0_BASE, (uint8_t *)"Enabled", 7);
        return;
    }
    random_mini_delay();
    if (featureid == 3 && (retrieve_featurelist() & 0b00000001) == 0b00000000){
        store_feature3(featureid);
        uart_write(UART0_BASE, (uint8_t *)"Enabled", 7);
        return;
    }

    //Enabling process is complete
}



void setup()
{
    set_processor_clock();
    srand(random_seed_generator());
    set_brownout_protection();
    start_time();
    eeprom_init();

    uart_board_init();
    uart_hosttools_init();
    switch_setup();
}


#define PAIRING_START_BYTE 'P'
#define ENABLING_START_BYTE 'E'

void loop()
{
    uint8_t previous_sw_state = GPIO_PIN_4;
    uint8_t debounce_sw_state = GPIO_PIN_4;
    uint8_t current_sw_state = GPIO_PIN_4;
    while(true){
        current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
        if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)){
            // Debounce switch
            for (int i = 0; i < 10000; i++);
            debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
            if (debounce_sw_state == current_sw_state){
                unlock_process();
            }
        }
        previous_sw_state = current_sw_state;

        if (uart_read_avail(UART0_BASE)){
            uint8_t pair_or_enable;
            uart_read(UART0_BASE, &pair_or_enable, 1, 20);
            if (pair_or_enable == (uint8_t)PAIRING_START_BYTE){
                random_mini_delay();
                if (retrieve_pair_bool())
                    pairing_process_pairedfob();
                else
                    pairing_process_unpairedfob();
            }
            else if (pair_or_enable == (uint8_t)ENABLING_START_BYTE){
                enablefeature_process();
            }
        }
    }

}


int main(void){
    setup();
    loop();
}

