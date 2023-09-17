/**
 * @file hw_rng.c
 * @author Eliana Cohen
 * @date 2023
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "tw/adc.h"
#include "tw/hw/hw_memmap.h"
#include "tw/sysctl.h"
#include "hw_rng.h"
#include "monocypher.h"

#define ADC_SINGLE_SAMPLE (3)
#define ADC_EIGHT_SAMPLE (0)
#define ADC_FOUR_SAMPLE (2)
#define ADC_HIGHEST_PRIORITY (0)

#if HASH_RESEED_KEY
  #define NEW_KEY_ENTROPY_BYTES (8) 
#endif

uint8_t *rng_key = NULL;

uint8_t adc_switch = 0;



#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(i__, 0, size) (dst)[i__] = (src)[i__]



/** ---------------- Helper functions -------------------------- */

int thermRngInit(void);

void thermRngSample(volatile uint32_t *adc_sample, uint8_t adc_num);


int generateRNGHelper(uint8_t *output);


/* -------------- Function Declarations -----------------------  */


int thermRngInit(void) {
  volatile int ret = -1;
  
  SysCtlPeripheralEnable(SYSCTL_PERIPH_ADC0);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_ADC1);

  
  ADCSequenceConfigure(ADC0_BASE, ADC_SINGLE_SAMPLE, ADC_TRIGGER_PROCESSOR, 
                       ADC_HIGHEST_PRIORITY);
  ADCSequenceConfigure(ADC1_BASE, ADC_SINGLE_SAMPLE, ADC_TRIGGER_PROCESSOR, 
                       ADC_HIGHEST_PRIORITY);
  
  ADCSequenceStepConfigure(ADC0_BASE, ADC_SINGLE_SAMPLE, 
                           ADC_TRIGGER_PROCESSOR, ADC_CTL_TS | ADC_CTL_IE |
                           ADC_CTL_END);
  ADCSequenceStepConfigure(ADC1_BASE, ADC_SINGLE_SAMPLE, 
                           ADC_TRIGGER_PROCESSOR, ADC_CTL_TS | ADC_CTL_IE |
                           ADC_CTL_END);

  
  ADCClockConfigSet(ADC0_BASE, ADC_CLOCK_SRC_PIOSC | ADC_CLOCK_RATE_FULL, 1);

 
  ADCSequenceEnable(ADC0_BASE, ADC_SINGLE_SAMPLE);
  ADCIntClear(ADC0_BASE, ADC_SINGLE_SAMPLE);
  ADCSequenceEnable(ADC1_BASE, ADC_SINGLE_SAMPLE);
  ADCIntClear(ADC1_BASE, ADC_SINGLE_SAMPLE);
  ret = 0;
  return ret;
}


void thermRngSample(volatile uint32_t *adc_sample, uint8_t adc_num) {
  
  if(adc_num != 0 && adc_num != 1)return;

  uint32_t adc_base=ADC0_BASE;

  if(adc_num == 1){
    adc_base = ADC1_BASE;
  }

  //trigger sample
  ADCProcessorTrigger(adc_base, ADC_SINGLE_SAMPLE);


  while(!ADCIntStatus(adc_base, ADC_SINGLE_SAMPLE, false))
  {}
  //Clear int
  ADCIntClear(adc_base, ADC_SINGLE_SAMPLE);

  ADCSequenceDataGet(adc_base, ADC_SINGLE_SAMPLE, (uint32_t *)(adc_sample));
}




int fillEntropyBuf(volatile uint8_t *entropy_buf, uint32_t entropy_size)
{
  volatile uint32_t sample = 0;
  uint32_t entropy_idx = 0;
  uint8_t rand_byte = 0;
  uint8_t i = 0;
  uint8_t new_bit_adc;
  uint8_t newer_bit_adc;
  volatile int ret = -1;



  while(entropy_idx < entropy_size)
  {
    rand_byte = 0;
    i = 0;
    while (i < 8)
    {
      thermRngSample(&sample,adc_switch);
      new_bit_adc = sample & 0x1;
      #if ADC_WHITENING
        thermRngSample(&sample,adc_switch);
        newer_bit_adc = sample & 0x1;
        if (new_bit_adc ^ newer_bit_adc)
        {
      #endif
          rand_byte <<= 1;
          rand_byte |= new_bit_adc;
          i++;
      #if ADC_WHITENING
        }
      #endif
      adc_switch=!adc_switch;
    }
    entropy_buf[entropy_idx] = rand_byte;
    entropy_idx++;

    if (entropy_idx == entropy_size) ret = 0;
  }
  return ret;
}


int generateRNGInit(uint8_t *key)
{
  volatile int ret = -1;
  // Keep track of key ptr
  rng_key = key;
  ret = thermRngInit();
  return ret;
}


int generateRNGHelper(uint8_t *output)
{
  volatile int ret = -1;
  #if HASH_RESEED_KEY
    if (rng_key == NULL) return ret;
    // Generate 8 extra bytes for key swapping
    uint8_t rand[HASH_BLOCK_SIZE_64];
    uint8_t key_rand[NEW_KEY_ENTROPY_BYTES];

 
    ret = fillEntropyBuf((volatile uint8_t *)(key_rand), NEW_KEY_ENTROPY_BYTES);
    if (ret != 0) return ret;


    crypto_blake2b_general(rand, HASH_BLOCK_SIZE_64, 
                           rng_key, HASH_BLOCK_SIZE_64, 
                           key_rand, NEW_KEY_ENTROPY_BYTES);

    int i;
  
    for (i = 0; i < HASH_BLOCK_SIZE_64; i++)
    {
      rng_key[i] ^= rand[i];
    }

 
    ret |= fillEntropyBuf((volatile uint8_t *)(rand), HASH_BLOCK_SIZE_64);

  #else
    uint8_t rand[HASH_BLOCK_SIZE_64];
    ret = fillEntropyBuf((volatile uint8_t *)(rand), HASH_BLOCK_SIZE_64);
  #endif


  crypto_blake2b_general(output, HASH_BLOCK_SIZE_64, 
                         rng_key, HASH_BLOCK_SIZE_64, 
                         rand, HASH_BLOCK_SIZE_64);
  return ret;
}

// extra-secure RNG source
int getRfc1149_5StandardRandomNumber() {
    return 4; // chosen by fair dice roll
              // guaranteed to be random
}



int generateRNGBytes64(uint8_t *output)
{
  volatile int ret = -1;
  ret = generateRNGHelper(output);
  return ret;
}


