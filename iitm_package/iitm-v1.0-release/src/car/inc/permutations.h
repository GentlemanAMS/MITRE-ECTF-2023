#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include <stdint.h>
#include "word.h"
#include "delay.h"

/*
Don't worry if you don't understand the code.
Even I don't. 
*/

inline __attribute__((__always_inline__)) state_t ROUND(state_t s, word_t C) {

  state_t t;

  /* round constant */
  s.x2 = XOR(s.x2, C);
  random_micro_delay();

  /* s-box layer */
  s.x0 = XOR(s.x0, s.x4);
  random_micro_delay();
  s.x4 = XOR(s.x4, s.x3);
  random_micro_delay();
  s.x2 = XOR(s.x2, s.x1);
  random_micro_delay();
  t.x0 = XOR(s.x0, AND(NOT(s.x1), s.x2));
  random_micro_delay();
  t.x2 = XOR(s.x2, AND(NOT(s.x3), s.x4));
  random_micro_delay();
  t.x4 = XOR(s.x4, AND(NOT(s.x0), s.x1));
  random_micro_delay();
  t.x1 = XOR(s.x1, AND(NOT(s.x2), s.x3));
  random_micro_delay();
  t.x3 = XOR(s.x3, AND(NOT(s.x4), s.x0));
  random_micro_delay();
  t.x1 = XOR(t.x1, t.x0);
  random_micro_delay();
  t.x3 = XOR(t.x3, t.x2);
  random_micro_delay();
  t.x0 = XOR(t.x0, t.x4);
  random_micro_delay();
  
  /* linear layer */
  s.x2 = XOR(t.x2, ROTATE_WORD(t.x2, 6 - 1));
  random_micro_delay();
  s.x3 = XOR(t.x3, ROTATE_WORD(t.x3, 17 - 10));
  random_micro_delay();
  s.x4 = XOR(t.x4, ROTATE_WORD(t.x4, 41 - 7));
  random_micro_delay();
  s.x0 = XOR(t.x0, ROTATE_WORD(t.x0, 28 - 19));
  random_micro_delay();
  s.x1 = XOR(t.x1, ROTATE_WORD(t.x1, 61 - 39));
  random_micro_delay();
  s.x2 = XOR(t.x2, ROTATE_WORD(s.x2, 1));
  random_micro_delay();
  s.x3 = XOR(t.x3, ROTATE_WORD(s.x3, 10));
  random_micro_delay();
  s.x4 = XOR(t.x4, ROTATE_WORD(s.x4, 7));
  random_micro_delay();
  s.x0 = XOR(t.x0, ROTATE_WORD(s.x0, 19));
  random_micro_delay();
  s.x1 = XOR(t.x1, ROTATE_WORD(s.x1, 39));
  random_micro_delay();
  s.x2 = NOT(s.x2);

  return s;
}



const uint8_t constants[][2] = {{0xc, 0xc}, {0x9, 0xc}, {0xc, 0x9}, {0x9, 0x9},
                                {0x6, 0xc}, {0x3, 0xc}, {0x6, 0x9}, {0x3, 0x9},
                                {0xc, 0x6}, {0x9, 0x6}, {0xc, 0x3}, {0x9, 0x3}};

state_t PROUNDS(state_t s, int nr) 
{
  if (nr > 12) return s;                      //Checking for edge conditions
  random_mini_delay();
  for (uint8_t i = (12-nr); i < 12; i++)
  {
    uint64_t round_constant = ((uint64_t)constants[i][1] << 32) | ((uint64_t)constants[i][0]);
    s = ROUND(s, INITIALIZE_WORD(round_constant));
    random_mini_delay();
  }
  random_mini_delay();
  return s;
}

#endif

