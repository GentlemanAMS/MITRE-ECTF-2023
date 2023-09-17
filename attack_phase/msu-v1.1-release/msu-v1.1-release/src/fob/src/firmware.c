/**
 * @file firmware.c
 * @author Spartan State Security Team
 * @brief Secure Key Fob Implementation
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 * 
 * It implements the primary functionality of the keyfob device.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"
#include "driverlib/timer.h"

#include "sb_all.h"

#include "secrets.h"

#include "board_link.h"
#include "uart.h"
#include "firmware.h"

/*** Macros ***/
#define ZERO(M) memset(&M, 0, sizeof(M))

/*** Globals ***/
// Handle Hardware Switch
uint8_t previous_sw_state = GPIO_PIN_4;
uint8_t debounce_sw_state = GPIO_PIN_4;
uint8_t current_sw_state = GPIO_PIN_4;
// CSPRNG State
sb_hmac_drbg_state_t drbg;
bool DRBG_INITIALIZED = false;

/**
 * @brief Main function for the Secure Fob design
 *
 * Listens to SW1 Button for an unlock command.
 * If unlock command presented (button pressed),
 *   attempts to unlock and start car.
 * 
 * Listens over Host UART for commands, including:
 *   Enable Feature, Pair Fob (Primary), Pair Fob (Replica)
 * 
 * @return -1 if an error occurs.
 */
int main(void)
{
  // Configure Clock
  SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_OSC_MAIN | SYSCTL_XTAL_16MHZ);

  // Configure LED
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0);
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0);

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Establish Entropy if Needed
  if(((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[1] &&
     ((uint32_t*)ENTROPY_FLASH)[2] == ((uint32_t*)ENTROPY_FLASH)[3] &&
     ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[4]) {

    if( FlashErase(ENTROPY_FLASH)
     || FlashProgram((uint32_t *)&S_ENTROPY, ENTROPY_FLASH, sizeof(ENTROPY))
    ) return -1;
    
  }

  // Initialize SysTick
  SysTickPeriodSet(16000000);
  SysTickEnable();

  // Initialize HOST UART
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

  // Infinite loop to register and handle commands
  while (true)
  {

    // Check for command from HOST
    tryHostCmd();

    // Check for button press
    tryButton();

  }
}

/**
 * @brief Checks whether the Host has issued a command.
 * If a command has been issued, then perform the corresponding
 * action if it is deemed appropriate.
 */
void tryHostCmd(void) {
  // Non blocking UART polling
  if (uart_avail(HOST_UART))
  {
    uint8_t cmd = (uint8_t)uart_readb(HOST_UART);

    if(cmd == ENABLE_CMD) {
      // if fob is paired, enable feature
      if(PFOB) {
        enableFeature();
      }
    }
    if(cmd == P_PAIR_CMD) {
      // if fob is paired, pair another fob
      if(PFOB) {
        pPairFob();
      }
    }
    if(cmd == U_PAIR_CMD) {
      // if fob is unpaired, pair fob
      if(UFOB && OG_UFOB) {
        uPairFob();
      }
    }

  }
}

/**
 * @brief Checks whether a button press occurs on SW1.
 * If so, attempts to unlock the attached car device.
 */
void tryButton(void) {
  // Check for Button Press
  current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
  if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)) {
    // Debounce Switch
    SysCtlDelay(20000);
    debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if (debounce_sw_state == current_sw_state) {
      // Switch Pressed, Unlock Car if Paired
      if(PFOB) {
        unlockCar();
      }
    }
  }
  previous_sw_state = current_sw_state;
}

/**
 * @brief Initialize the CSPRNG.
 * 
 * @return true if operation succeeds, false if an error occurs
 */
bool init_drbg(void)
{
  ENTROPY temp_entropy;
  sb_sw_private_t car_privkey;
  volatile uint32_t tick;

  // Check for Entropy Error
  if(((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[1] &&
     ((uint32_t*)ENTROPY_FLASH)[2] == ((uint32_t*)ENTROPY_FLASH)[3] &&
     ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[4])
     return false;

  // Initialize DRBG
  tick = SysTickValueGet();
  if(!(
    get_secret(&car_privkey, NULL) &&
    sb_hmac_drbg_init(&drbg, (void *)ENTROPY_FLASH, sizeof(ENTROPY), (sb_byte_t *)&car_privkey, sizeof(sb_sw_private_t), (sb_byte_t *)&tick, sizeof(tick)) == SB_SUCCESS
  )) return false;

  // Clear private key
  ZERO(car_privkey);

  //Checkout Entropy
  memcpy(&temp_entropy, (void *)ENTROPY_FLASH, sizeof(temp_entropy));

  // Update Entropy
  if(sb_hmac_drbg_generate(&drbg, (sb_byte_t *)&temp_entropy, sizeof(temp_entropy))
    != SB_SUCCESS) return false;

  // Commit Entropy
  if(FlashErase(ENTROPY_FLASH) || FlashProgram((uint32_t *)&temp_entropy, ENTROPY_FLASH, sizeof(ENTROPY))) return false;
  
  // Success
  return true;
}

/**
 * @brief Sleeps for 5 seconds
 */
void SLEEP(void) {
  SysCtlDelay(SPEED/3*5);
}

/**
 * @brief Check whether this device is a paired fob
 * 
 * @return true if fob is paired, false if fob is unpaired
*/
bool pfob(void)
{
  return OG_PFOB || FOB_FLASH->paired==YES_PAIRED;
}

/**
 * @brief Loads a secret value from storage.
 * 
 * If the device was originally a paired fob,
 * load the value from EEPROM.
 * If the device was origynally an unpaired fob,
 * load the value from FLASH.
 * 
 * @param priv [out] Where to write the car private key, or NULL if key is not wanted
 * @param pin  [out] Where to write the pairing pin, or NULL if pin is not wanted
 * 
 * @return true if operation succeeds, false if an eeprom error occurs
 */
bool get_secret(sb_sw_private_t *priv, uint32_t *pin) {
  #if OG_PFOB == 1
    if(EEPROMInit() != EEPROM_INIT_OK){
      return false;
    }
    if(priv) {
      EEPROMRead((uint32_t *)priv, offsetof(FOB_DATA, car_privkey), sizeof(sb_sw_private_t));
    }
    if(pin) {
      EEPROMRead(pin, offsetof(FOB_DATA, pin), sizeof(uint32_t));
    }
    return true;
  #endif
  #if OG_UFOB == 1
    if(priv) {
      memcpy(priv, &FOB_FLASH->car_privkey, sizeof(sb_sw_private_t));
    }
    if(pin) {
      *pin = FOB_FLASH->pin;
    }
    return true;
  #endif
}

/**
 * @brief Function that pairs the attached unpaired fob,
 * if the Host supplies the correct pin.
 * 
 * If the supplied pin is incorrect, SLEEPs for a while.
 */
void pPairFob(void)
{
  PAIR_PACKET pair_packet;
  uint32_t true_pin;
  uint32_t host_pin;
  
  // Paired fob only
  if(!PFOB) return;

  // Receive PIN attempt from host
  uart_read(HOST_UART, (uint8_t *)&host_pin, sizeof(host_pin));

  // Verify PIN attempt
  if(!get_secret(NULL, &true_pin)) return;
  if(host_pin != true_pin) {
    // If pin is invalid, sleep and return
    SLEEP();
    return;
  }
  
  // PIN Successful, Do Pairing
  if(!get_secret(&pair_packet.car_privkey, &pair_packet.pin)) return;
  uart_writeb(UFOB_UART, PAIR_START);
  uart_write(UFOB_UART, (uint8_t *)&pair_packet, sizeof(pair_packet));
}

/**
 * @brief Function that pairs this fob,
 * becoming a paired fob device
 * rather than an unpaired fob device.
 */
void uPairFob(void)
{
  FOB_DATA temp_flash;
  PAIR_PACKET pair_packet;

  // Original unpaired fob only
  if(!(UFOB && OG_UFOB)) {
    return;
  }

  // Get pairing packet from paired fob
  while(uart_readb(PFOB_UART) != PAIR_START);
  uart_read(PFOB_UART, (uint8_t *)&pair_packet, sizeof(pair_packet));

  // Save the newly received values
  loadFobState(&temp_flash);
  temp_flash.pin = pair_packet.pin;
  memcpy(&temp_flash.car_privkey, &pair_packet.car_privkey, sizeof(temp_flash.car_privkey));
  temp_flash.paired = YES_PAIRED;
  saveFobState(&temp_flash);
}

/**
 * @brief Function that handles enabling a new feature on the fob
 * by storing the package according to its feature number.
 */
void enableFeature(void)
{
  PACKAGE package;
  FOB_DATA temp_flash;
  
  // Paired fob only
  if(!PFOB) return;

  // Get the feature number from the host
  uint8_t feature_num = (uint8_t)uart_readb(HOST_UART) - 1;

  // Get the package for the feature from the host
  uart_read(HOST_UART, (uint8_t *)&package, sizeof(PACKAGE));

  // Store the feature package
  if(feature_num < NUM_FEATURES) {
    loadFobState(&temp_flash);
    memcpy(&temp_flash.feature[feature_num], &package, sizeof(PACKAGE));
    saveFobState(&temp_flash);
  }
}

/**
 * @brief Request the Secure Car device to unlock and start
 * 
 * Responds to the car's challenge, and sends the packaged features.
 */
void unlockCar(void)
{
  CHALLENGE challenge;
  RESPONSE response;

  // Paired fob only
  if(!PFOB) return;

  ZERO(response);

  // Request the Car to Unlock
  request_unlock();

  // Receive Unlock Challenge from Car
  get_challenge(&challenge);
  
  // Generate Response
  gen_response(&challenge, &response);
  
  // Prepare Feature Requests
  memcpy(&response.feature, FOB_FLASH->feature, sizeof(response.feature));

  // Send Response with Features
  finalize_unlock(&response);
}

/**
 * @brief Generate a response to the car's challenge
 * 
 * @param challenge [in]  The car's challenge to which we must respond
 * @param response  [out] The response being written
 */
void gen_response(CHALLENGE *challenge, RESPONSE *response)
{
  sb_sw_context_t sb_ctx;
  sb_sw_message_digest_t _hash;
  sb_sw_private_t priv;

  // Initialize DRBG
  if (!DRBG_INITIALIZED) {
    if(!init_drbg()) return;
    DRBG_INITIALIZED = true;
  }

  // Only paired fobs respond to challenges
  if(!PFOB) return;

  // Clear empy data
  ZERO(sb_ctx);

  // Get signing key
  if(!get_secret(&priv, NULL))return;
  
  // Generate response
  sb_sw_sign_message_sha256(&sb_ctx, &_hash, &response->unlock, &priv, (sb_byte_t *)&challenge->data, sizeof(challenge->data), &drbg, SB_SW_CURVE_P256, ENDIAN);

  // Clear key
  ZERO(priv);
}

/**
 * @brief Load fob data from FLASH into RAM
 * 
 * @param fob_data [out] The fob data structure to write
 */
void loadFobState(FOB_DATA *fob_data)
{
  memcpy(fob_data, FOB_FLASH, sizeof(FOB_DATA));
}

/**
 * @brief Saves fob data structure into FLASH
 * 
 * @param fob_data [in] The fob data structure to save
 * 
 * @return true if operation succeeds, false if an eeprom error occurs
 */
bool saveFobState(FOB_DATA *fob_data)
{
  return
  !FlashErase(FOB_STATE_PTR)
  &&
  !FlashProgram((uint32_t *)fob_data, FOB_STATE_PTR, sizeof(FOB_DATA));
}