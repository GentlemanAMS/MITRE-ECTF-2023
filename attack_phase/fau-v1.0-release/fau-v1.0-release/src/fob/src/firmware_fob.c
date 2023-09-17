/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"
#include "inc/hw_sysctl.h"
#include "inc/hw_nvic.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"

#include "driverlib/adc.h"
#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"
#include "driverlib/debug.h"

#include "secrets.h"

#include "firmware.h"
#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "secure.h"
#include "aes.h"

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
  FLASH_DATA fob_state_ram;
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

// If paired fob, initialize the system information
#if PAIRED == 1
  if (fob_state_flash->paired == FLASH_UNPAIRED)
  {
    strcpy((char *)(fob_state_ram.pair_info.password), PASSWORD);
    strcpy((char *)(fob_state_ram.pair_info.pin), PAIR_PIN);
    strcpy((char *)(fob_state_ram.pair_info.car_id), CAR_ID);
    strcpy((char *)(fob_state_ram.feature_info.car_id), CAR_ID);
    fob_state_ram.paired = FLASH_PAIRED;

    saveFobState(&fob_state_ram);
  }
#else
  fob_state_ram.paired = FLASH_UNPAIRED;
#endif

  if (fob_state_flash->paired == FLASH_PAIRED)
  {
    memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  }

  // This will run on first boot to initialize features
  if (fob_state_ram.feature_info.num_active == 0xFF)
  {
    fob_state_ram.feature_info.num_active = 0;
    saveFobState(&fob_state_ram);
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

  // EEPROM init
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Declare a buffer for reading and writing to UART
  uint8_t uart_buffer[10];
  uint8_t uart_buffer_index = 0;

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

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
void pairFob(FLASH_DATA *fob_state_ram)
{
  MESSAGE_PACKET message;
  // Start pairing transaction - fob is already paired
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    int16_t bytes_read;
    uint8_t uart_buffer_pin[8];
    uart_write(HOST_UART, (uint8_t *)"P", 1);
    bytes_read = uart_readline(HOST_UART, uart_buffer_pin);

    if (bytes_read == 6)
    {
      // If the pin is correct
      if (!(strcmp((char *)uart_buffer_pin,
                   (char *)fob_state_ram->pair_info.pin)))
      {
        // Pair the new key by sending a pairing key
        uint8_t session_key[16] = {0};
        aes_sharedkey_tx(session_key,AES_BYTES);
        aes_pair_paired(session_key); 
        receiveAck();       
        // Pair the new key by sending a PAIR_PACKET structure
        // with required information to unlock door
        message.message_len = sizeof(PAIR_PACKET);
        message.magic = PAIR_MAGIC;
        message.buffer = (uint8_t *)&fob_state_ram->pair_info;
        send_board_message(&message);
      }
    }
  }

  // Start pairing transaction - fob is not paired
  else
  {
    uint8_t session_key[16] = {0};
    aes_sharedkey_rx(session_key);
    aes_pair_unpaired(session_key);  

    message.buffer = (uint8_t *)&fob_state_ram->pair_info;
    sendAckSuccess();
    receive_board_message_by_type(&message, PAIR_MAGIC);
    fob_state_ram->paired = FLASH_PAIRED;
    strcpy((char *)fob_state_ram->feature_info.car_id,
           (char *)fob_state_ram->pair_info.car_id);
    

    uart_write(HOST_UART, (uint8_t *)"Paired", 6);

    saveFobState(fob_state_ram);
  }
}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FLASH_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    uint8_t uart_buffer[20];
    uint8_t ciphertext[AES_BYTES];
    uint32_t key[AES_BYTES/4];

    uart_readline(HOST_UART, uart_buffer);

    EEPROMRead(key, 2*AES_BYTES, AES_BYTES);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, (uint8_t *)key);

    memcpy(ciphertext, uart_buffer, AES_BYTES);
    AES_ECB_decrypt(&ctx, ciphertext);

    ENABLE_PACKET *enable_message = (ENABLE_PACKET *)ciphertext;
    if (strcmp((char *)fob_state_ram->pair_info.car_id,
               (char *)enable_message->car_id))
    {
      return;
    }

    // Feature list full
    if (fob_state_ram->feature_info.num_active == NUM_FEATURES)
    {
      return;
    }

    // Search for feature in list
    for (int i = 0; i < fob_state_ram->feature_info.num_active; i++)
    {
      if (fob_state_ram->feature_info.features[i] == enable_message->feature)
      {
        return;
      }
    }

    fob_state_ram->feature_info
        .features[fob_state_ram->feature_info.num_active] =
        enable_message->feature;
    fob_state_ram->feature_info.num_active++;

    saveFobState(fob_state_ram);
    uart_write(HOST_UART, (uint8_t *)"Enabled", 7);
  }
}

/**
 * @brief Function that handles the fob unlocking a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FLASH_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    uint8_t session_key[16] = {0};

    aes_sharedkey_tx(session_key,2*AES_BYTES);
    aes_unlock_fob(fob_state_ram->pair_info.password, 6, session_key);
  }
}

/**
 * @brief Function that handles the fob starting a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void startCar(FLASH_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    uint8_t session_key[16] = {0};

    aes_sharedkey_tx(session_key,2*AES_BYTES);
    aes_unlock_fob(fob_state_ram->pair_info.password, 6, session_key);

    MESSAGE_PACKET message;
    message.magic = START_MAGIC;
    message.message_len = sizeof(FEATURE_DATA);
    message.buffer = (uint8_t *)&fob_state_ram->feature_info;
    send_board_message(&message);
  }
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data)
{
  FlashErase(FOB_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
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
  receive_board_message_by_type(&message, ACK_MAGIC);

  return message.buffer[0];
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