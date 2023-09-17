/*
------------------------------------------------------------------------------
rand.h: definitions for a random number generator
By Bob Jenkins, 1996, Public Domain
MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: renamed seed to flag
  980605: recommend RANDSIZL=4 for noncryptography.
  010626: note this is public domain
------------------------------------------------------------------------------
*/
#ifndef RAND
#define RAND
#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

/* a ub4 is an unsigned 4-byte quantity */
typedef  unsigned long int  ub4;

/* external results */
extern ub4 randrsl[256], randcnt;

/*
------------------------------------------------------------------------------
 If (flag==TRUE), then use the contents of randrsl[0..RANDSIZ-1] as the seed.
------------------------------------------------------------------------------
*/
void randinit(int flag);

void isaac(void);


/*
------------------------------------------------------------------------------
 Call rand() to retrieve a single 32-bit random value
------------------------------------------------------------------------------
*/
#define rand() \
   (!randcnt-- ? \
     (isaac(), randcnt=RANDSIZ-1, randrsl[randcnt]) : \
     randrsl[randcnt])

#endif  /* RAND */


