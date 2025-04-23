
#ifndef CPU_FP
#define CPU_FP

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "fp_params.h"
#include "FourQ_tables.h"

// Constants

#define RADIX64         64
#define NWORDS64_FIELD  2                 // Number of 64-bit words of a field element 
#define NWORDS64_ORDER  4                 // Number of 64-bit words of an element in Z_r 


/**************** Public ECC API ****************/

// Set generator G = (x,y)
void eccset(point_t G);

// Variable-base scalar multiplication Q = k*P
bool ecc_mul(point_t P, digit_t* k, point_t Q, bool clear_cofactor);

// Fixed-base scalar multiplication Q = k*G, where G is the generator
bool ecc_mul_fixed(digit_t* k, point_t Q);

// Double scalar multiplication R = k*G + l*Q, where G is the generator
bool ecc_mul_double(digit_t* k, point_t Q, digit_t* l, point_t R);


/************* Public API for arithmetic functions modulo the curve order **************/

// Converting to Montgomery representation
void to_Montgomery(const digit_t* ma, digit_t* c);

// Converting from Montgomery to standard representation
void from_Montgomery(const digit_t* a, digit_t* mc);

// 256-bit Montgomery multiplication modulo the curve order
void Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc);

// (Non-constant time) Montgomery inversion modulo the curve order
void Montgomery_inversion_mod_order(const digit_t* ma, digit_t* mc);

// Addition modulo the curve order, c = a+b mod order
void add_mod_order(const digit_t* a, const digit_t* b, digit_t* c);

// Subtraction modulo the curve order, c = a-b mod order
void subtract_mod_order(const digit_t* a, const digit_t* b, digit_t* c);

// Reduction modulo the order using Montgomery arithmetic internally
void modulo_order(digit_t* a, digit_t* c);

/************ Curve and recoding functions *************/

// Normalize projective twisted Edwards point Q = (X,Y,Z) -> P = (x,y)
void eccnorm(point_extproj_t P, point_t Q);

// Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT), where T = Ta*Tb
void R1_to_R2(point_extproj_t P, point_extproj_precomp_t Q);

// Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,Z,T), where T = Ta*Tb 
void R1_to_R3(point_extproj_t P, point_extproj_precomp_t Q);  
 
// Conversion from representation (X+Y,Y-X,2Z,2dT) to (2X,2Y,2Z,2dT)
void R2_to_R4(point_extproj_precomp_t P, point_extproj_t Q);     

// Point doubling 2P
void eccdouble_ni(point_extproj_t P);
void eccdouble(point_extproj_t P);

// Complete point addition P = P+Q or P = P+P
void eccadd_ni(point_extproj_precomp_t Q, point_extproj_t P);

void eccadd(point_extproj_precomp_t Q, point_extproj_t P);

void eccadd_core(point_extproj_precomp_t P, point_extproj_precomp_t Q, point_extproj_t R); 

// Psi mapping of a point, P = psi(P)
void ecc_psi(point_extproj_t P); 

// Phi mapping of a point, P = phi(P)
void ecc_phi(point_extproj_t P);

// Scalar decomposition
void decompose(uint64_t* k, uint64_t* scalars);

// Recoding sub-scalars for use in the variable-base scalar multiplication
void recode(uint64_t* scalars, unsigned int* digits, unsigned int* sign_masks);

// Computes the fixed window representation of scalar
void fixed_window_recode(uint64_t* scalar, unsigned int* digits, unsigned int* sign_masks);

// Convert scalar to odd if even using the prime subgroup order r
void conversion_to_odd(digit_t* k, digit_t* k_odd);

// Co-factor clearing
void cofactor_clearing(point_extproj_t P);

// Precomputation function
void ecc_precomp(point_extproj_t P, point_extproj_precomp_t *T);

// Constant-time table lookup to extract an extended twisted Edwards point (X+Y:Y-X:2Z:2T) from the precomputed table
void table_lookup_1x8(point_extproj_precomp_t* table, point_extproj_precomp_t P, unsigned int digit, unsigned int sign_mask);
void table_lookup_1x8_a(point_extproj_precomp_t* table, point_extproj_precomp_t P, unsigned int* digit, unsigned int* sign_mask);

// Modular correction of input coordinates and conversion to representation (X,Y,Z,Ta,Tb) 
void point_setup(point_t P, point_extproj_t Q);
void point_setup_ni(point_t P, point_extproj_t Q);
    
// Point validation: check if point lies on the curve     
bool ecc_point_validate(point_extproj_t P);

// Output error/success message for a given ECCRYPTO_STATUS
const char* FourQ_get_error_message(ECCRYPTO_STATUS Status);

// Mixed point addition P = P+Q or P = P+P
void eccmadd_ni(point_precomp_t Q, point_extproj_t P);

// Constant-time table lookup to extract a point represented as (x+y,y-x,2t)
void table_lookup_fixed_base(point_precomp_t* table, point_precomp_t P, unsigned int digit, unsigned int sign);

//  Computes the modified LSB-set representation of scalar
void mLSB_set_recode(uint64_t* scalar, unsigned int *digits);

// Generation of the precomputation table used internally by the double scalar multiplication function ecc_mul_double()
void ecc_precomp_double(point_extproj_t P, point_extproj_precomp_t* Table, unsigned int npoints);

// Computes wNAF recoding of a scalar
void wNAF_recode(uint64_t scalar, unsigned int w, int* digits);

// Encode point P
void encode(point_t P, unsigned char* Pencoded);

// Decode point P
ECCRYPTO_STATUS decode(const unsigned char* Pencoded, point_t P);


/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static unsigned int is_digit_nonzero_ct(digit_t x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

static unsigned int is_digit_zero_ct(digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static unsigned int is_digit_lessthan_ct(digit_t x, digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1)); 
}

/********************** Macros for digit operations **********************/

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    digit_x_digit((multiplier), (multiplicand), &(lo));
    
// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
    (sumOut) = (addend2) + tempReg;                                                               \
    (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { digit_t tempReg = (minuend) - (subtrahend);                                                 \
    unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));  \
    (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
    (borrowOut) = borrowReg; }
    
// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

// shift left with flexible datatype
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product)                                                 \
    mp_mul((digit_t*)&(multiplier), (digit_t*)&(multiplicand), (digit_t*)&(product), NWORDS_FIELD/2);

// 128-bit addition, inputs < 2^127
#define ADD128(addend1, addend2, addition)                                                        \
    mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition)                                                 \
    (carry) = mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

#endif
