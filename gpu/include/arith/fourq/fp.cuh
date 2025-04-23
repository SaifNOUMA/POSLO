
#ifndef FP_H
#define FP_H

#include "fourq/fp_params.h"

// Constants

#define RADIX64         64
#define NWORDS64_FIELD  2                 // Number of 64-bit words of a field element 
#define NWORDS64_ORDER  4                 // Number of 64-bit words of an element in Z_r 

/************* Public API for arithmetic functions modulo the curve order **************/

// Converting to Montgomery representation
__device__ __forceinline__ void d_to_Montgomery(const digit_t* ma, digit_t* c);

// Converting from Montgomery to standard representation
__device__ __forceinline__ void d_from_Montgomery(const digit_t* a, digit_t* mc);

// 256-bit Montgomery multiplication modulo the curve order
__device__ __forceinline__ void d_Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc);

// (Non-constant time) Montgomery inversion modulo the curve order
__device__ __forceinline__ void d_Montgomery_inversion_mod_order(const digit_t* ma, digit_t* mc);

// Addition modulo the curve order, c = a+b mod order
__device__ __forceinline__ void d_add_mod_order(const digit_t* a, const digit_t* b, digit_t* c);

// Subtraction modulo the curve order, c = a-b mod order
__device__ __forceinline__ void d_subtract_mod_order(const digit_t* a, const digit_t* b, digit_t* c);

// Reduction modulo the order using Montgomery arithmetic internally
__device__ __forceinline__ void d_modulo_order(digit_t* __restrict__ a, digit_t* __restrict__ c);

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

__device__ static __forceinline__ unsigned int d_is_digit_nonzero_ct(digit_t x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

__device__ static __forceinline__ unsigned int d_is_digit_zero_ct(digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ d_is_digit_nonzero_ct(x));
}

__device__ static __forceinline__ unsigned int d_is_digit_lessthan_ct(digit_t x, digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1)); 
}

/********************** Macros for digit operations **********************/

// Digit multiplication
#define D_MUL(multiplier, multiplicand, hi, lo)                                             \
    { asm volatile ("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(multiplier), "l"(multiplicand));  \
      asm volatile ("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(multiplier), "l"(multiplicand));  \
    }
    
// Digit addition with carry
#define D_ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
    (sumOut) = (addend2) + tempReg;                                                               \
    (carryOut) = (d_is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | d_is_digit_lessthan_ct((sumOut), tempReg)); }

// Digit subtraction with borrow
#define D_SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { digit_t tempReg = (minuend) - (subtrahend);                                                 \
    unsigned int borrowReg = (d_is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & d_is_digit_zero_ct(tempReg)));  \
    (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
    (borrowOut) = borrowReg; }
    
// Shift right with flexible datatype
#define D_SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

// shift left with flexible datatype
#define D_SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

// 64x64-bit multiplication
#define D_MUL128(multiplier, multiplicand, product)                                                 \
    d_mp_mul((digit_t*)&(multiplier), (digit_t*)&(multiplicand), (digit_t*)&(product), NWORDS_FIELD/2);

// 128-bit addition, inputs < 2^127
#define D_ADD128(addend1, addend2, addition)                                                        \
    d_mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

// 128-bit addition with output carry
#define D_ADC128(addend1, addend2, carry, addition)                                                 \
    (carry) = d_mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

// ---- PTX instructions ----
__device__ __forceinline__ uint32_t add_cc(uint32_t a, uint32_t b) {
  uint32_t r;

  asm volatile ("add.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b));
  return r;
}

__device__ __forceinline__ uint32_t addc_cc(uint32_t a, uint32_t b) {
  uint32_t r;

  asm volatile ("addc.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b));
  return r;
}

__device__ __forceinline__ uint32_t addc(uint32_t a, uint32_t b) {
  uint32_t r;

  asm volatile ("addc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b));
  return r;
}

__device__ __forceinline__ uint64_t madlo(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("mad.lo.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madlo_cc(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("mad.lo.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madloc_cc(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("madc.lo.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madloc(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("madc.lo.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madhi(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("mad.hi.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madhi_cc(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("mad.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madhic_cc(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("madc.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

__device__ __forceinline__ uint64_t madhic(uint64_t a, uint64_t b, uint64_t c) {
  uint64_t r;

  asm volatile ("madc.hi.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
  return r;
}

#include "fp.cu"

#endif // FP_H