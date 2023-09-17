/**
 * @file firmware.c
 * @authors HackieBird
 * @brief eCTF Fob Secured Design Implementation
 * @date 2023
 */

#include "firmware.h"

// /* Write to UART. Returns False on failure */
// static bool debug_print(const char *text)
// {
//   return false;
//   int len = strlen(text);
//   if (len != uart_write(HOST_UART, text, len))
//     return false;
//   return true;
// }


/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void)
{
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // EEPROM Protetcion
  EEPROMBlockProtectSet(0, EEPROM_PROT_NA_LNA_URW);
  EEPROMBlockPasswordSet(0, (uint32_t *)EEPROM_PASSWORD, 3);
  EEPROMBlockLock(0);

  FOB_DATA fob_state_ram;


// If paired fob, initialize the system information
#if PAIRED == 1
    strcpy((char *)(fob_state_ram.pair_info.password), PASSWORD);
    strcpy((char *)(fob_state_ram.pair_info.pin_hash), PAIR_PIN_HASH);
    strcpy((char *)(fob_state_ram.pair_info.car_id), CAR_ID);
    strcpy((char *)(fob_state_ram.feature_info.car_id), CAR_ID);
    fob_state_ram.paired = FLASH_PAIRED;
  
#else

  EEPROMBlockUnlock(0, (uint32_t *)EEPROM_PASSWORD, 3);
  EEPROMRead((uint32_t *)&fob_state_ram, EEPROM_PASSWORD , sizeof(FOB_DATA));
  EEPROMBlockLock(0);

#endif


  // This will run on first boot to initialize features
  if (fob_state_ram.feature_info.num_active > 3)
  {
    fob_state_ram.feature_info.num_active = 0;
  }

  // Initialize UART
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

  // Change LED color: white
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g

  // Declare a buffer for reading and writing to UART
  uint8_t uart_buffer[10];
  uint8_t uart_buffer_index = 0;

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

  timer_set_start();

  // Infinite loop for polling UART
  while (true)
  {

    // Non blocking UART polling
    if (uart_avail(HOST_UART))
    {
      uint8_t uart_char = (uint8_t)uart_readb(HOST_UART);

      if ((uart_char != '\r') && (uart_char != '\n') && (uart_char != '\0') &&
          (uart_char != 0xD))
      {
        uart_buffer[uart_buffer_index] = uart_char;
        uart_buffer_index++;
      }
      else
      {
        uart_buffer[uart_buffer_index] = 0x00;
        uart_buffer_index = 0;

        if (!(strcmp((char *)uart_buffer, "enable")))
        {
          enableFeature(&fob_state_ram);
        }
        else if (!(strcmp((char *)uart_buffer, "pair")))
        {
          pairFob(&fob_state_ram);
        }
      }
    }


    current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if ((current_sw_state != previous_sw_state) && (current_sw_state == 0))
    {
      // Debounce switch
      for (int i = 0; i < 10000; i++)
        ;
      debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
      if (debounce_sw_state == current_sw_state)
      {
        unlockCar(&fob_state_ram);
        if (receiveAck())
        {
          startCar(&fob_state_ram);
        }
      }
    }
    previous_sw_state = current_sw_state;
  }
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void pairFob(FOB_DATA *fob_state_ram)
{
  MESSAGE_PACKET message;
  volatile uint32_t sleep_time = -1;

  // Start pairing transaction - fob is already paired
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    int16_t bytes_read;
    uint8_t uart_buffer[8];
    uart_write(HOST_UART, (uint8_t *)"P", 1);
    bytes_read = uart_readline(HOST_UART, uart_buffer);
    #define DIGEST_BYTES (256/8)
    uint8_t message_hash[DIGEST_BYTES]; // the output of SHA256 will be stored here
    size_t len = 6;
    sha256_ctx cx[1];

    sha256_begin(cx);
    sha256(message_hash, uart_buffer, len, cx);
    
    uint8_t received_hash[32];
    for (int i = 0; i < 64; i=i+2) {
      char hex[2];
      strncpy(hex, fob_state_ram->pair_info.pin_hash + i, 2);
      received_hash[i/2] = (uint8_t)strtol(hex, 0, 16);
    }
    
    if (bytes_read != 6)
      goto handle_failure;
    
    if (0!=(strncmp((char *)message_hash,
                  (char *)received_hash, DIGEST_BYTES)))
      goto handle_failure;
    
    // If the pin_hash is correct
    // Pair the new key by sending a PAIR_PACKET structure
    // with required information to unlock door
    message.message_len = sizeof(PAIR_PACKET);
    message.magic = PAIR_MAGIC;
    message.buffer = (uint8_t *)&fob_state_ram->pair_info;
    send_board_message(&message);
      
  }

  // Start pairing transaction - fob is not paired
  else
  {
    message.buffer = (uint8_t *)&fob_state_ram->pair_info;
    receive_board_message_by_type(&message, PAIR_MAGIC, sizeof(fob_state_ram->pair_info));
    fob_state_ram->paired = FLASH_PAIRED;
    strcpy((char *)fob_state_ram->feature_info.car_id,
           (char *)fob_state_ram->pair_info.car_id);

    // Store the fob state in EEPROM and lock it
    EEPROMBlockUnlock(0, (uint32_t *)EEPROM_PASSWORD, 3);
    EEPROMProgram((uint32_t *)fob_state_ram, (uint32_t *)EEPROM_PASSWORD , sizeof(FOB_DATA));
    
    uart_write(HOST_UART, (uint8_t *)"Paired", 6);

  }
  return ;

  handle_failure:
    for (uint32_t i=0; i<sleep_time; i++);

}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FOB_DATA *fob_state_ram)
{
  volatile uint32_t sleep_time = -1;
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    
    uint8_t uart_buffer[sizeof(ENABLE_PACKET)];
    uart_readline(HOST_UART, uart_buffer);

    ENABLE_PACKET *enable_message = (ENABLE_PACKET *)uart_buffer;
    if (strcmp((char *)fob_state_ram->pair_info.car_id,
               (char *)enable_message->car_id))
      goto handle_failure;
    

    // Feature list full
    if (fob_state_ram->feature_info.num_active == NUM_FEATURES)
      goto handle_failure;
    

    // Search for feature in list - already enabled!
    for (int k = 0; k < fob_state_ram->feature_info.num_active; k++)
      if (fob_state_ram->feature_info.features[k] == enable_message->feature)
        goto handle_failure;

    // get the data to be hashed : car_id + feature
    unsigned char data[sizeof(enable_message->car_id) + sizeof(enable_message->feature)];
    strncpy(data, enable_message->car_id,sizeof(enable_message->car_id));
    data[sizeof(enable_message->car_id)] = enable_message->feature;

    // calculate hash
    #define DIGEST_BYTES (256/8)
    uint8_t message_hash[DIGEST_BYTES]; // the output of SHA256 will be stored here
    size_t len = sizeof(data);
    sha256_ctx cx[1];

    sha256_begin(cx);
    sha256(message_hash, data, len, cx);
    uint8_t public_key_x[64];
    uint8_t public_key_y[64];    
    strcpy((char *)(public_key_x), X);
    strcpy((char *)(public_key_y), Y);

    // get the public key : x and y concatenated
    uint8_t public_key[64];
    for (int i = 0; i < 64; i=i+2) {
      char hex[2];
      strncpy(hex, public_key_x + i, 2);
      public_key[i/2] = (uint8_t)strtol(hex, 0, 16);
    }
    for (int i = 0; i < 64; i=i+2) {
      char hex[2];
      strncpy(hex, public_key_y + i, 2);
      public_key[(i/2)+32] = (uint8_t)strtol(hex, 0, 16);
    }

    // get the signature from the buffer.
    // buffer has signature as a hex string, convert it.
    uint8_t sig[64];
    for (int i = 0; i < 128; i=i+2) {
      char hex[2];
      strncpy(hex, enable_message->signature + i, 2);
      sig[i/2] = (uint8_t)strtol(hex, 0, 16);
    }

    int verify_result = uECC_verify(public_key, message_hash, DIGEST_BYTES, sig, uECC_secp256k1());

    if (verify_result == 0) 
      goto handle_failure;

    fob_state_ram->feature_info
        .features[fob_state_ram->feature_info.num_active] =
        enable_message->feature;
    fob_state_ram->feature_info.num_active++;

    uart_write(HOST_UART, (uint8_t *)"Enabled", 7);
  }

  return ;

  handle_failure:
    for (uint32_t i=0; i<sleep_time; i++);
}

/**
 * @brief Function that handles the fob unlocking a car
 *
 * 
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FOB_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    MESSAGE_PACKET message;

    // Step-1 : Send NONCE-1
    message.message_len = 16;
    message.magic = UNLOCK_MAGIC;
    uint8_t nonce1[16];
    getRandomNumber(nonce1, 2);

    // encrypt nonce1
    #if PAIRED == 1
      encrypt(nonce1, CAR_PASSWORD, fob_state_ram);
    #else 
      encrypt(nonce1, FOB_PASSWORD, fob_state_ram);
    #endif

    message.buffer = nonce1; 
    send_board_message(&message);

    /* Step-2 : Recieve combined nonce */
    uint8_t buffer[256];
    message.buffer = buffer;
    receive_board_message_by_type(&message, UNLOCK_MAGIC, 256);
    message.buffer[message.message_len] = 0;

    #if PAIRED == 1
      decrypt(message.buffer, CAR_PASSWORD, fob_state_ram);
    #else 
      decrypt(message.buffer, FOB_PASSWORD, fob_state_ram);
    #endif

    uint8_t nonce2[16];
    for (int i = 0; i < 16; i++)
      nonce2[i] = message.buffer[i + 16];

    /* Step-3 : Send back nonce2 */
    message.message_len = 16;
    message.magic = UNLOCK_MAGIC;
    #if PAIRED == 1
      encrypt(nonce2, CAR_PASSWORD, fob_state_ram);
    #else 
      encrypt(nonce2, FOB_PASSWORD, fob_state_ram);
    #endif
    message.buffer = nonce2;
    send_board_message(&message);
  }
}

/**
 * @brief Function that handles the fob starting a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void startCar(FOB_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    MESSAGE_PACKET message;
    message.magic = START_MAGIC;
    
    // encrypt before sending
    FEATURE_DATA feature_list = fob_state_ram->feature_info;
    #if PAIRED == 1
      encrypt((uint8_t*)&feature_list, CAR_PASSWORD, fob_state_ram);
    #else 
      encrypt((uint8_t*)&feature_list, FOB_PASSWORD, fob_state_ram);
    #endif

    message.buffer = (uint8_t *)&feature_list;
    message.message_len = 16;
    send_board_message(&message);
  }
}


/**
 * @brief Function that receives an ack and returns whether ack was
 * success/failure
 *
 * @return uint8_t Ack success/failure
 */
uint8_t receiveAck()
{
  MESSAGE_PACKET message;
  uint8_t buffer[255];
  message.buffer = buffer;
  receive_board_message_by_type(&message, ACK_MAGIC, 255);
  return message.buffer[0];
}

/* Given the key name, read respective key using defined address */
static uint8_t *read_key(key_type key_name, FOB_DATA* fob_state_ram)
{
  switch (key_name)
  {
  case CAR_PASSWORD:
    return PASSWORD;
  case FOB_PASSWORD:    
    return fob_state_ram->pair_info.password;  
  default:
    return 0;  
  }
}

/* Encrypts the given plaintext in-place after reading `key_name` from EEPROM */
static void encrypt(uint8_t *plaintext, key_type key_name, FOB_DATA* fob_state_ram)
{

  uint8_t *key = read_key(key_name, fob_state_ram);
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, plaintext);

}

/* Decrypts the given ciphertext in-place after reading `key_name` from EEPROM */
static void decrypt(uint8_t *ciphertext, key_type key_name, FOB_DATA * fob_state_ram)
{

  uint8_t *key = read_key(key_name, fob_state_ram);
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key); 
  AES_ECB_decrypt(&ctx, ciphertext);

}


/* Generating NONCE of length = `bytes_length`. Returns uint8_t[bytes_length]  */
static void getRandomNumber(uint8_t dest[], uint8_t bytes_length)
{

  for (int i = 0; i < 8 * bytes_length; i++) {
    uint32_t timer_val = TimerValueGet(TIMER0_BASE, TIMER_A);
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

    // Configure Timer0A as a 16-bit periodic timer.
    TimerConfigure(TIMER0_BASE, TIMER_CFG_A_PERIODIC);

    // Set the Timer0B load value to 1ms.
    TimerLoadSet(TIMER0_BASE, TIMER_A, SysCtlClockGet() / 1000);

    // Enable Timer0A.
    TimerEnable(TIMER0_BASE, TIMER_A);
}