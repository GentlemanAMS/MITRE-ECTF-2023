/**
 * @file firmware.c
 * @authors HackieBird
 * @brief eCTF Car Secured Design Implementation
 * @date 2023
 */

#include "firmware.h"

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {
  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // EEPROM Protetcion
  EEPROMBlockProtectSet(0, EEPROM_PROT_NA_LNA_URW);
  EEPROMBlockPasswordSet(0, (uint32_t *)EEPROM_PASSWORD, 3);
  EEPROMBlockLock(0);

  // Change LED color: red
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  timer_set_start();

  while (true) {
    unlockCar();
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(void) {
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // ==== Handshake protocol ====
  /* Step 1: Receive packet which is encrypted NONCE1 and decrypt it*/
  receive_board_message_by_type(&message, UNLOCK_MAGIC, 256);
  message.buffer[message.message_len] = 0;
  decrypt(message.buffer, CAR_PASSWORD);

  /* Step 2 : Produce NONCE-2 and encrypt NONCE-1 + NONCE-2. Send to fob */
  uint8_t nonce2[16];
  getRandomNumber(nonce2, 2);

  uint8_t nonce_1_2_combined[32];
  for(int i=0;i<16;i++)
    nonce_1_2_combined[i]=message.buffer[i];

  for(int i=0;i<16;i++)
    nonce_1_2_combined[i+16]=nonce2[i];

  encrypt(nonce_1_2_combined, CAR_PASSWORD);

  message.message_len = 32;
  message.magic = UNLOCK_MAGIC;
  message.buffer =  nonce_1_2_combined ; 
  send_board_message(&message);


  /* Step 3: Recieve nonce2 and check for correctness */
  memset(buffer, 0, 256);
  message.buffer = buffer;
  receive_board_message_by_type(&message, UNLOCK_MAGIC, 256);
  message.buffer[message.message_len] = 0;
  decrypt(message.buffer, CAR_PASSWORD);

  /* If nonce2 is correct, unlock */
  if (!strncmp((char*)message.buffer, (char*)nonce2, 16)){

    uint8_t eeprom_message[64];

    // Read last 64B of EEPROM
    EEPROMBlockUnlock(0, (uint32_t *)EEPROM_PASSWORD, 3);
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);          
    EEPROMBlockLock(0);

    // Write out full flag if applicable
    uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);
   
    sendAckSuccess();
    startCar();
  }
  else{
    // busy-waiting instead of calling sleep in case of failure
    volatile uint32_t sleep_time = -1;
    for (uint32_t i=0; i<sleep_time; i++);
    sendAckFailure();
  }

}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(void) {
  // Create a message struct variable for receiving data

  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // Receive start message
  receive_board_message_by_type(&message, START_MAGIC, 256);
  decrypt(message.buffer, CAR_PASSWORD);
  FEATURE_DATA *feature_info = (FEATURE_DATA *)message.buffer;

  // Verify correct car id
  if (strcmp((char *)car_id, (char *)feature_info->car_id)) {
    // busy-waiting instead of calling sleep in case of failure
    volatile uint32_t sleep_time = -1;
    for (uint32_t i=0; i<sleep_time; i++);
    return;
  }

  // Print out features for all active features
  for (int i = 0; i < feature_info->num_active; i++) {
    uint8_t eeprom_message[64];

    uint32_t offset = feature_info->features[i] * FEATURE_SIZE;
    
    EEPROMBlockUnlock(0, (uint32_t *)EEPROM_PASSWORD, 3);

    if (offset > FEATURE_END) {
        offset = FEATURE_END;
    }

    EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);
    EEPROMBlockLock(0);
    uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
  }

  // Change LED color: green
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void) {
  // Create packet for successful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_SUCCESS;
  message.message_len = 1;

  send_board_message(&message);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void) {
  // Create packet for unsuccessful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_FAIL;
  message.message_len = 1;

  send_board_message(&message);
}



// /* Write to UART. Returns False on failure */
// static bool debug_print(const char *text)
// {
//   return false;
//   int len = strlen(text);
//   if (len != uart_write(HOST_UART, text, len))
//     return false;
//   return true;
// }

/* Given the key name, read respective key using defined address Macro and return uint_8[16] array */
static uint8_t* read_key(key_type key_name){
  switch (key_name)
  {
  case CAR_PASSWORD:
    return PASSWORD; 
  
  default:
    return NULL;
  }
  
}


/* Encrypts the given plaintext in-place after reading `key_name` from EEPROM */
static void encrypt(uint8_t* plaintext, key_type key_name){

  uint8_t *key = read_key(key_name); // safely read
  struct AES_ctx ctx;  
  AES_init_ctx(&ctx, key); 
  AES_ECB_encrypt(&ctx, plaintext);          

}


/* Decrypts the given ciphertext in-place after reading `key_name` from EEPROM */
static void decrypt(uint8_t* ciphertext, key_type key_name){

  uint8_t *key = read_key(key_name);
  struct AES_ctx ctx;  
  AES_init_ctx(&ctx, key);
  AES_ECB_decrypt(&ctx, ciphertext);              

}


/* Generating NONCE of length = `bytes_length`. Returns uint8_t[bytes_length]  */
static void getRandomNumber(uint8_t dest[], uint8_t bytes_length)
{

  for (int i = 0; i < 8 * bytes_length; i++) {
    uint32_t timer_val = TimerValueGet(TIMER0_BASE, TIMER_B);
    uint8_t rand_num = (uint8_t)(timer_val % 65536);
    dest[i] = rand_num;
  }

}


// Configure Timer0B as a 16-bit periodic counter with an interrupt
// every 1ms.
void timer_set_start(void)
{

    // The Timer0 peripheral must be enabled for use.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER0);

    // Configure Timer0B as a 16-bit periodic timer.
    TimerConfigure(TIMER0_BASE, TIMER_CFG_B_PERIODIC);

    // Set the Timer0B load value to 1ms.
    TimerLoadSet(TIMER0_BASE, TIMER_B, SysCtlClockGet() / 1000);

    // Enable Timer0B.
    TimerEnable(TIMER0_BASE, TIMER_B);
}