
#include "fp.h"
#include "FourQ_tables.h"
#include <string.h>

const digit_t mask_7fff = (digit_t)(-1) >> 1;
static digit_t mask4000 = (digit_t)1 << (sizeof(digit_t)*8 - 2);
const digit_t prime1271_0 = (digit_t)(-1);
#define prime1271_1 mask_7fff


void digit_x_digit(digit_t a, digit_t b, digit_t* c)
{ // Digit multiplication, digit * digit -> 2-digit result    
    digit_t al, ah, bl, bh, temp;
    digit_t albl, albh, ahbl, ahbh, res1, res2, res3, carry;
    digit_t mask_low = (digit_t)(-1) >> (sizeof(digit_t)*4), mask_high = (digit_t)(-1) << (sizeof(digit_t)*4);

    al = a & mask_low;                        // Low part
    ah = a >> (sizeof(digit_t) * 4);          // High part
    bl = b & mask_low;
    bh = b >> (sizeof(digit_t) * 4);

    albl = al*bl;
    albh = al*bh;
    ahbl = ah*bl;
    ahbh = ah*bh;
    c[0] = albl & mask_low;                   // C00

    res1 = albl >> (sizeof(digit_t) * 4);
    res2 = ahbl & mask_low;
    res3 = albh & mask_low;  
    temp = res1 + res2 + res3;
    carry = temp >> (sizeof(digit_t) * 4);
    c[0] ^= temp << (sizeof(digit_t) * 4);    // C01   

    res1 = ahbl >> (sizeof(digit_t) * 4);
    res2 = albh >> (sizeof(digit_t) * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    c[1] = temp & mask_low;                   // C10 
    carry = temp & mask_high; 
    c[1] ^= (ahbh & mask_high) + carry;       // C11
}

__inline void fpcopy1271(felm_t a, felm_t c)
{ // Copy of a field element, c = a
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++)
        c[i] = a[i];
}


static __inline void fpzero1271(felm_t a)
{ // Zeroing a field element, a = 0
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++)
        a[i] = 0;
}


__inline void fpadd1271(felm_t a, felm_t b, felm_t c)
{ // Field addition, c = a+b mod p  
    unsigned int i;    
    unsigned int carry = 0;
    
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], b[i], carry, c[i]); 
    }
    carry = (unsigned int)(c[NWORDS_FIELD-1] >> (RADIX-1));
    c[NWORDS_FIELD-1] &= mask_7fff; 
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, c[i], 0, carry, c[i]); 
    }
}


__inline void fpsub1271(felm_t a, felm_t b, felm_t c)
{ // Field subtraction, c = a-b mod p  
    unsigned int i;
    unsigned int borrow = 0;
    
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]); 
    }
    borrow = (unsigned int)(c[NWORDS_FIELD-1] >> (RADIX-1));
    c[NWORDS_FIELD-1] &= mask_7fff; 
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, c[i], 0, borrow, c[i]); 
    }
}


__inline void fpneg1271(felm_t a)
{ // Field negation, a = -a mod p
    unsigned int i;
    unsigned int borrow = 0;
    
    for (i = 0; i < (NWORDS_FIELD-1); i++) {
        SUBC(borrow, prime1271_0, a[i], borrow, a[i]); 
    }
    a[NWORDS_FIELD-1] = prime1271_1 - a[NWORDS_FIELD-1];
}


void fpmul1271(felm_t a, felm_t b, felm_t c)
{ // Field multiplication using schoolbook method, c = a*b mod p  
    unsigned int i, j;
    digit_t u, v, UV[2], temp, bit_mask;
    digit_t t[2*NWORDS_FIELD] = {0};
    unsigned int carry = 0;
    
    for (i = 0; i < NWORDS_FIELD; i++) {
         u = 0;
         for (j = 0; j < NWORDS_FIELD; j++) {
              MUL(a[i], b[j], UV+1, UV[0]); 
              ADDC(0, UV[0], u, carry, v); 
              u = UV[1] + carry;
              ADDC(0, t[i+j], v, carry, v); 
              u = u + carry;
              t[i+j] = v;
         }
         t[NWORDS_FIELD+i] = u;
    }
    bit_mask = (t[NWORDS_FIELD-1] >> (RADIX-1));
    t[NWORDS_FIELD-1] &= mask_7fff; 
    carry = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        temp = (t[NWORDS_FIELD+i] >> (RADIX-1));
        t[NWORDS_FIELD+i] = (t[NWORDS_FIELD+i] << 1) + bit_mask;
        bit_mask = temp; 
        ADDC(carry, t[i], t[NWORDS_FIELD+i], carry, t[i]); 
    }
    carry = (unsigned int)(t[NWORDS_FIELD-1] >> (RADIX-1));
    t[NWORDS_FIELD-1] &= mask_7fff; 
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, t[i], 0, carry, c[i]); 
    }
}


void fpsqr1271(felm_t a, felm_t c)
{ // Field squaring using schoolbook method, c = a^2 mod p  
    
    fpmul1271(a, a, c);
}


void mod1271(felm_t a)
{ // Modular correction, a = a mod (2^127-1)  
    digit_t mask;
    unsigned int i;
    unsigned int borrow = 0;
    
    for (i = 0; i < (NWORDS_FIELD-1); i++) {
        SUBC(borrow, a[i], prime1271_0, borrow, a[i]); 
    }
    SUBC(borrow, a[NWORDS_FIELD-1], prime1271_1, borrow, a[NWORDS_FIELD-1]); 

    mask = 0 - (digit_t)borrow;    // If result < 0 then mask = 0xFF...F else sign = 0x00...0
    borrow = 0;
    for (i = 0; i < (NWORDS_FIELD-1); i++) {
        ADDC(borrow, a[i], mask, borrow, a[i]); 
    }
    ADDC(borrow, a[NWORDS_FIELD-1], (mask >> 1), borrow, a[NWORDS_FIELD-1]); 
}


__inline void fpexp1251(felm_t a, felm_t af)
{ // Exponentiation over GF(p), af = a^(125-1)
    int i;
    felm_t t1, t2, t3, t4, t5;

    fpsqr1271(a, t2);                              
    fpmul1271(a, t2, t2); 
    fpsqr1271(t2, t3);  
    fpsqr1271(t3, t3);                          
    fpmul1271(t2, t3, t3);
    fpsqr1271(t3, t4);  
    fpsqr1271(t4, t4);   
    fpsqr1271(t4, t4);  
    fpsqr1271(t4, t4);                         
    fpmul1271(t3, t4, t4);  
    fpsqr1271(t4, t5);
    for (i=0; i<7; i++) fpsqr1271(t5, t5);                      
    fpmul1271(t4, t5, t5); 
    fpsqr1271(t5, t2); 
    for (i=0; i<15; i++) fpsqr1271(t2, t2);                    
    fpmul1271(t5, t2, t2); 
    fpsqr1271(t2, t1); 
    for (i=0; i<31; i++) fpsqr1271(t1, t1);                         
    fpmul1271(t2, t1, t1); 
    for (i=0; i<32; i++) fpsqr1271(t1, t1);    
    fpmul1271(t1, t2, t1); 
    for (i=0; i<16; i++) fpsqr1271(t1, t1);                         
    fpmul1271(t5, t1, t1);    
    for (i=0; i<8; i++) fpsqr1271(t1, t1);                           
    fpmul1271(t4, t1, t1);    
    for (i=0; i<4; i++) fpsqr1271(t1, t1);                          
    fpmul1271(t3, t1, t1);    
    fpsqr1271(t1, t1);                           
    fpmul1271(a, t1, af);
}


void fpinv1271(felm_t a)
{ // Field inversion, af = a^-1 = a^(p-2) mod p
  // Hardcoded for p = 2^127-1
    felm_t t;

    fpexp1251(a, t);    
    fpsqr1271(t, t);     
    fpsqr1271(t, t);                             
    fpmul1271(a, t, a); 
}


void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Schoolbook multiprecision multiply, c = a*b   
    unsigned int i, j;
    digit_t u, v, UV[2];
    unsigned int carry = 0;

     for (i = 0; i < (2*nwords); i++) c[i] = 0;

     for (i = 0; i < nwords; i++) {
          u = 0;
          for (j = 0; j < nwords; j++) {
               MUL(a[i], b[j], UV+1, UV[0]); 
               ADDC(0, UV[0], u, carry, v); 
               u = UV[1] + carry;
               ADDC(0, c[i+j], v, carry, v); 
               u = u + carry;
               c[i+j] = v;
          }
          c[nwords+i] = u;
     }
}


unsigned int mp_add(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
    unsigned int i, carry = 0;

    for (i = 0; i < nwords; i++) {
        ADDC(carry, a[i], b[i], carry, c[i]);
    }
    
    return carry;
}


static __inline void multiply(const digit_t* a, const digit_t* b, digit_t* c)
{ // Schoolbook multiprecision multiply, c = a*b 

    mp_mul(a, b, c, NWORDS_ORDER);
}


unsigned char subtract(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision subtraction, c = a-b. Returns the borrow bit 
    unsigned int i;
    unsigned char borrow = 0;

    for (i = 0; i < nwords; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    return borrow;
}   


static __inline unsigned int add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
    
    return mp_add((digit_t*)a, (digit_t*)b, c, (unsigned int)nwords);
}

void subtract_mod_order(const digit_t* a, const digit_t* b, digit_t* c)
{ // Subtraction modulo the curve order, c = a-b mod order
	digit_t mask, carry = 0;
	digit_t* order = (digit_t*)curve_order;
	unsigned int i, bout;

	bout = subtract(a, b, c, NWORDS_ORDER);            // (bout, c) = a - b
	mask = 0 - (digit_t)bout;                          // if bout = 0 then mask = 0x00..0, else if bout = 1 then mask = 0xFF..F

	for (i = 0; i < NWORDS_ORDER; i++) {               // c = c + (mask & order)
		ADDC(carry, c[i], mask & order[i], carry, c[i]);
	}
}


void add_mod_order(const digit_t* a, const digit_t* b, digit_t* c)
{ // Addition modulo the curve order, c = a+b mod order

	add(a, b, c, NWORDS_ORDER);                        // c = a + b
	subtract_mod_order(c, (digit_t*)&curve_order, c);  // if c >= order then c = c - order
}


void Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc)
{ // 256-bit Montgomery multiplication modulo the curve order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1]
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the global value "Montgomery_rprime", where r is the order   
	unsigned int i;
	digit_t mask, P[2 * NWORDS_ORDER], Q[2 * NWORDS_ORDER], temp[2 * NWORDS_ORDER];
	digit_t* order = (digit_t*)curve_order;
	unsigned int cout = 0, bout = 0;

	multiply(ma, mb, P);                               // P = ma * mb
	multiply(P, (digit_t*)&Montgomery_rprime, Q);      // Q = P * r' mod 2^(log_2(r))
	multiply(Q, (digit_t*)&curve_order, temp);         // temp = Q * r
	cout = add(P, temp, temp, 2 * NWORDS_ORDER);         // (cout, temp) = P + Q * r     

	for (i = 0; i < NWORDS_ORDER; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
		mc[i] = temp[NWORDS_ORDER + i];
	}

	// Final, constant-time subtraction     
	bout = subtract(mc, (digit_t*)&curve_order, mc, NWORDS_ORDER);    // (cout, mc) = (cout, mc) - r
	mask = (digit_t)cout - (digit_t)bout;              // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

	for (i = 0; i < NWORDS_ORDER; i++) {               // temp = mask & r
		temp[i] = (order[i] & mask);
	}
	add(mc, temp, mc, NWORDS_ORDER);                   //  mc = mc + (mask & r)

	return;
}


void modulo_order(digit_t* a, digit_t* c)
{ // Reduction modulo the order using Montgomery arithmetic
  // ma = a*Montgomery_Rprime mod r, where a,ma in [0, r-1], a,ma,r < 2^256
  // c = ma*1*Montgomery_Rprime^(-1) mod r, where ma,c in [0, r-1], ma,c,r < 2^256
	digit_t ma[NWORDS_ORDER], one[NWORDS_ORDER] = { 0 };

	one[0] = 1;
	Montgomery_multiply_mod_order(a, (digit_t*)&Montgomery_Rprime, ma);
	Montgomery_multiply_mod_order(ma, one, c);
}


void conversion_to_odd(digit_t* k, digit_t* k_odd)
{// Convert scalar to odd if even using the prime subgroup order r
	digit_t i, mask;
	digit_t* order = (digit_t*)curve_order;
	unsigned int carry = 0;

	mask = ~(0 - (k[0] & 1));

	for (i = 0; i < NWORDS_ORDER; i++) {  // If (k is odd) then k_odd = k else k_odd = k + r 
		ADDC(carry, order[i] & mask, k[i], carry, k_odd[i]);
	}
}


__inline void fpdiv1271(felm_t a)
{ // Field division by two, c = a/2 mod p
    digit_t mask;
    unsigned int carry = 0;
    unsigned int i;

    mask = 0 - (a[0] & 1);  // if a is odd then mask = 0xFF...FF, else mask = 0
    
    for (i = 0; i < (NWORDS_FIELD-1); i++) {
        ADDC(carry, mask, a[i], carry, a[i]);
    }
    ADDC(carry, (mask >> 1), a[NWORDS_FIELD-1], carry, a[NWORDS_FIELD-1]);

    for (i = 0; i < (NWORDS_FIELD-1); i++) {
        SHIFTR(a[i+1], a[i], 1, a[i], RADIX);
    }
    a[NWORDS_FIELD-1] = (a[NWORDS_FIELD-1] >> 1);
}


void fp2div1271(f2elm_t a)
{ // GF(p^2) division by two c = a/2 mod p
    fpdiv1271(a[0]);
    fpdiv1271(a[1]);
}


/***********************************************/
/************* GF(p^2) FUNCTIONS ***************/

void fp2copy1271(f2elm_t a, f2elm_t c)
{// Copy of a GF(p^2) element, c = a
    fpcopy1271(a[0], c[0]);
    fpcopy1271(a[1], c[1]);
}


void fp2zero1271(f2elm_t a)
{// Zeroing a GF(p^2) element, a = 0
    fpzero1271(a[0]);
    fpzero1271(a[1]);
}


void fp2neg1271(f2elm_t a)
{// GF(p^2) negation, a = -a in GF((2^127-1)^2)
    fpneg1271(a[0]);
    fpneg1271(a[1]);
}


void fp2sqr1271(f2elm_t a, f2elm_t c)
{// GF(p^2) squaring, c = a^2 in GF((2^127-1)^2)

#ifdef ASM_SUPPORT
    fp2sqr1271_a(a, c);
#else
    felm_t t1, t2, t3;

    fpadd1271(a[0], a[1], t1);           // t1 = a0+a1 
    fpsub1271(a[0], a[1], t2);           // t2 = a0-a1
    fpmul1271(a[0], a[1], t3);           // t3 = a0*a1
    fpmul1271(t1, t2, c[0]);             // c0 = (a0+a1)(a0-a1)
    fpadd1271(t3, t3, c[1]);             // c1 = 2a0*a1
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t3, sizeof(felm_t)/sizeof(unsigned int));
#endif
#endif
}


void fp2mul1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) multiplication, c = a*b in GF((2^127-1)^2)

#if defined(ASM_SUPPORT)        
    fp2mul1271_a(a, b, c);
#else
    felm_t t1, t2, t3, t4;
    
    fpmul1271(a[0], b[0], t1);          // t1 = a0*b0
    fpmul1271(a[1], b[1], t2);          // t2 = a1*b1
    fpadd1271(a[0], a[1], t3);          // t3 = a0+a1
    fpadd1271(b[0], b[1], t4);          // t4 = b0+b1
    fpsub1271(t1, t2, c[0]);            // c[0] = a0*b0 - a1*b1
    fpmul1271(t3, t4, t3);              // t3 = (a0+a1)*(b0+b1)
    fpsub1271(t3, t1, t3);              // t3 = (a0+a1)*(b0+b1) - a0*b0
    fpsub1271(t3, t2, c[1]);            // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1    
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t3, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t4, sizeof(felm_t)/sizeof(unsigned int));
#endif
#endif
}


__inline void fp2add1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) addition, c = a+b in GF((2^127-1)^2)
    fpadd1271(a[0], b[0], c[0]);
    fpadd1271(a[1], b[1], c[1]);
}


__inline void fp2sub1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) subtraction, c = a-b in GF((2^127-1)^2) 
    fpsub1271(a[0], b[0], c[0]);
    fpsub1271(a[1], b[1], c[1]);
}


static __inline void fp2addsub1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) addition followed by subtraction, c = 2a-b in GF((2^127-1)^2)
    
#ifdef ASM_SUPPORT
    fp2addsub1271_a(a, b, c);
#else
    fp2add1271(a, a, a);
    fp2sub1271(a, b, c);
#endif 
}


void fp2inv1271(f2elm_t a)
{// GF(p^2) inversion, a = (a0-i*a1)/(a0^2+a1^2)
    f2elm_t t1;

    fpsqr1271(a[0], t1[0]);             // t10 = a0^2
    fpsqr1271(a[1], t1[1]);             // t11 = a1^2
    fpadd1271(t1[0], t1[1], t1[0]);     // t10 = a0^2+a1^2
    fpinv1271(t1[0]);                   // t10 = (a0^2+a1^2)^-1
    fpneg1271(a[1]);                    // a = a0-i*a1
    fpmul1271(a[0], t1[0], a[0]);
    fpmul1271(a[1], t1[0], a[1]);       // a = (a0-i*a1)*(a0^2+a1^2)^-1
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


bool is_zero_ct(digit_t* a, unsigned int nwords)
{ // Check if multiprecision element is zero
    digit_t x;
    unsigned int i;

    x = a[0];
    for (i = 1; i < nwords; i++) {
        x |= a[i];
    }

    return (bool)(1 ^ ((x | (0-x)) >> (RADIX-1)));
}


// Copy extended projective point Q = (X:Y:Z:Ta:Tb) to P
#define ecccopy(Q, P); fp2copy1271((Q)->x,  (P)->x);  \
                       fp2copy1271((Q)->y,  (P)->y);  \
                       fp2copy1271((Q)->z,  (P)->z);  \
                       fp2copy1271((Q)->ta, (P)->ta); \
                       fp2copy1271((Q)->tb, (P)->tb);

// Copy extended projective point Q = (X+Y,Y-X,2Z,2dT) to P
#define ecccopy_precomp(Q, P); fp2copy1271((Q)->xy, (P)->xy); \
                               fp2copy1271((Q)->yx, (P)->yx); \
                               fp2copy1271((Q)->z2, (P)->z2); \
                               fp2copy1271((Q)->t2, (P)->t2); 

// Copy extended affine point Q = (x+y,y-x,2dt) to P
#define ecccopy_precomp_fixed_base(Q, P); fp2copy1271((Q)->xy, (P)->xy); \
                                          fp2copy1271((Q)->yx, (P)->yx); \
                                          fp2copy1271((Q)->t2, (P)->t2);


void table_lookup_1x8(point_extproj_precomp_t* table, point_extproj_precomp_t P, unsigned int digit, unsigned int sign_mask)
{ // Constant-time table lookup to extract a point represented as (X+Y,Y-X,2Z,2dT) corresponding to extended twisted Edwards coordinates (X:Y:Z:T)
  // Inputs: sign_mask, digit, table containing 8 points
  // Output: P = sign*table[digit], where sign=1 if sign_mask=0xFF...FF and sign=-1 if sign_mask=0

    point_extproj_precomp_t point, temp_point;
    unsigned int i, j;
    digit_t mask;
                                  
    ecccopy_precomp(table[0], point);                                        // point = table[0]

    for (i = 1; i < 8; i++)
    {
        digit--;
        // While digit>=0 mask = 0xFF...F else sign = 0x00...0
        mask = (digit_t)(digit >> (8*sizeof(digit)-1)) - 1;
        ecccopy_precomp(table[i], temp_point);                               // temp_point = table[i] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < NWORDS_FIELD; j++) {
            point->xy[0][j] = (mask & (point->xy[0][j] ^ temp_point->xy[0][j])) ^ point->xy[0][j];
            point->xy[1][j] = (mask & (point->xy[1][j] ^ temp_point->xy[1][j])) ^ point->xy[1][j];
            point->yx[0][j] = (mask & (point->yx[0][j] ^ temp_point->yx[0][j])) ^ point->yx[0][j];
            point->yx[1][j] = (mask & (point->yx[1][j] ^ temp_point->yx[1][j])) ^ point->yx[1][j];
            point->z2[0][j] = (mask & (point->z2[0][j] ^ temp_point->z2[0][j])) ^ point->z2[0][j];
            point->z2[1][j] = (mask & (point->z2[1][j] ^ temp_point->z2[1][j])) ^ point->z2[1][j];
            point->t2[0][j] = (mask & (point->t2[0][j] ^ temp_point->t2[0][j])) ^ point->t2[0][j];
            point->t2[1][j] = (mask & (point->t2[1][j] ^ temp_point->t2[1][j])) ^ point->t2[1][j];
        }
    }
    
    fp2copy1271(point->t2, temp_point->t2);
    fp2copy1271(point->xy, temp_point->yx);                                  // point: x+y,y-x,2dt coordinate, temp_point: y-x,x+y,-2dt coordinate
    fp2copy1271(point->yx, temp_point->xy);                                   
    fpneg1271(temp_point->t2[0]);                                            // Negate 2dt coordinate
    fpneg1271(temp_point->t2[1]);             
    for (j = 0; j < NWORDS_FIELD; j++) {                                     // If sign_mask = 0 then choose negative of the point
        point->xy[0][j] = ((digit_t)((int)sign_mask) & (point->xy[0][j] ^ temp_point->xy[0][j])) ^ temp_point->xy[0][j];
        point->xy[1][j] = ((digit_t)((int)sign_mask) & (point->xy[1][j] ^ temp_point->xy[1][j])) ^ temp_point->xy[1][j];
        point->yx[0][j] = ((digit_t)((int)sign_mask) & (point->yx[0][j] ^ temp_point->yx[0][j])) ^ temp_point->yx[0][j];
        point->yx[1][j] = ((digit_t)((int)sign_mask) & (point->yx[1][j] ^ temp_point->yx[1][j])) ^ temp_point->yx[1][j];
        point->t2[0][j] = ((digit_t)((int)sign_mask) & (point->t2[0][j] ^ temp_point->t2[0][j])) ^ temp_point->t2[0][j];
        point->t2[1][j] = ((digit_t)((int)sign_mask) & (point->t2[1][j] ^ temp_point->t2[1][j])) ^ temp_point->t2[1][j];
    }                                  
    ecccopy_precomp(point, P); 
}


void table_lookup_fixed_base(point_precomp_t* table, point_precomp_t P, unsigned int digit, unsigned int sign)
{ // Constant-time table lookup to extract a point represented as (x+y,y-x,2t) corresponding to extended twisted Edwards coordinates (X:Y:Z:T) with Z=1
  // Inputs: sign, digit, table containing VPOINTS_FIXEDBASE = 2^(W_FIXEDBASE-1) points
  // Output: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]

    point_precomp_t point, temp_point;
    unsigned int i, j;
    digit_t mask;
                                   
    ecccopy_precomp_fixed_base(table[0], point);                             // point = table[0]

    for (i = 1; i < VPOINTS_FIXEDBASE; i++)
    {
        digit--;
        // While digit>=0 mask = 0xFF...F else sign = 0x00...0
        mask = (digit_t)(digit >> (8*sizeof(digit)-1)) - 1;
        ecccopy_precomp_fixed_base(table[i], temp_point);                    // temp_point = table[i] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < NWORDS_FIELD; j++) {
            point->xy[0][j] = (mask & (point->xy[0][j] ^ temp_point->xy[0][j])) ^ point->xy[0][j];
            point->xy[1][j] = (mask & (point->xy[1][j] ^ temp_point->xy[1][j])) ^ point->xy[1][j];
            point->yx[0][j] = (mask & (point->yx[0][j] ^ temp_point->yx[0][j])) ^ point->yx[0][j];
            point->yx[1][j] = (mask & (point->yx[1][j] ^ temp_point->yx[1][j])) ^ point->yx[1][j];
            point->t2[0][j] = (mask & (point->t2[0][j] ^ temp_point->t2[0][j])) ^ point->t2[0][j];
            point->t2[1][j] = (mask & (point->t2[1][j] ^ temp_point->t2[1][j])) ^ point->t2[1][j];
        }
    }
    
    fp2copy1271(point->t2, temp_point->t2);
    fp2copy1271(point->xy, temp_point->yx);                                  // point: x+y,y-x,2dt coordinate, temp_point: y-x,x+y,-2dt coordinate
    fp2copy1271(point->yx, temp_point->xy);                                   
    fpneg1271(temp_point->t2[0]);                                            // Negate 2dt coordinate
    fpneg1271(temp_point->t2[1]);             
    for (j = 0; j < NWORDS_FIELD; j++) {                                     // If sign = 0xFF...F then choose negative of the point
        point->xy[0][j] = ((digit_t)((int)sign) & (point->xy[0][j] ^ temp_point->xy[0][j])) ^ point->xy[0][j];
        point->xy[1][j] = ((digit_t)((int)sign) & (point->xy[1][j] ^ temp_point->xy[1][j])) ^ point->xy[1][j];
        point->yx[0][j] = ((digit_t)((int)sign) & (point->yx[0][j] ^ temp_point->yx[0][j])) ^ point->yx[0][j];
        point->yx[1][j] = ((digit_t)((int)sign) & (point->yx[1][j] ^ temp_point->yx[1][j])) ^ point->yx[1][j];
        point->t2[0][j] = ((digit_t)((int)sign) & (point->t2[0][j] ^ temp_point->t2[0][j])) ^ point->t2[0][j];
        point->t2[1][j] = ((digit_t)((int)sign) & (point->t2[1][j] ^ temp_point->t2[1][j])) ^ point->t2[1][j];
    }                                  
    ecccopy_precomp_fixed_base(point, P); 
}


void encode(point_t P, unsigned char* Pencoded)
{ // Encode point P
  // SECURITY NOTE: this function does not run in constant time.
    digit_t temp1 = (P->x[1][NWORDS_FIELD-1] & mask4000) << 1;
    digit_t temp2 = (P->x[0][NWORDS_FIELD-1] & mask4000) << 1;

    memcpy(Pencoded, P->y, 32);
    if (is_zero_ct((digit_t*)P->x, NWORDS_FIELD) == true) {
        ((digit_t*)Pencoded)[2*NWORDS_FIELD-1] |= temp1;
    } else {
        ((digit_t*)Pencoded)[2*NWORDS_FIELD-1] |= temp2;
    }
}


void point_setup(point_t P, point_extproj_t Q)
{ // Point conversion to representation (X,Y,Z,Ta,Tb) 
  // Input: P = (x,y) in affine coordinates
  // Output: P = (X,Y,1,Ta,Tb), where Ta=X, Tb=Y and T=Ta*Tb, corresponding to (X:Y:Z:T) in extended twisted Edwards coordinates

    fp2copy1271(P->x, Q->x);
    fp2copy1271(P->y, Q->y);
    fp2copy1271(Q->x, Q->ta);              // Ta = X1
    fp2copy1271(Q->y, Q->tb);              // Tb = Y1
    fp2zero1271(Q->z); Q->z[0][0]=1;       // Z1 = 1
}


__inline bool ecc_point_validate(point_extproj_t P)
{ // Point validation: check if point lies on the curve
  // Input: P = (x,y) in affine coordinates, where x, y in [0, 2^127-1]. 
  // Output: TRUE (1) if point lies on the curve E: -x^2+y^2-1-dx^2*y^2 = 0, FALSE (0) otherwise.
  // SECURITY NOTE: this function does not run in constant time (input point P is assumed to be public).
    f2elm_t t1, t2, t3;

    fp2sqr1271(P->y, t1);  
    fp2sqr1271(P->x, t2);
    fp2sub1271(t1, t2, t3);                     // -x^2 + y^2 
    fp2mul1271(t1, t2, t1);                     // x^2*y^2
    fp2mul1271((felm_t*)&PARAMETER_d, t1, t2);  // dx^2*y^2
    fp2zero1271(t1);  t1[0][0] = 1;             // t1 = 1
    fp2add1271(t2, t1, t2);                     // 1 + dx^2*y^2
    fp2sub1271(t3, t2, t1);                     // -x^2 + y^2 - 1 - dx^2*y^2
    
#if defined(GENERIC_IMPLEMENTATION)
    { unsigned int i, j;
    mod1271(t1[0]);
    mod1271(t1[1]);

    for (i = 0; i < 2; i++) {
        for (j = 0; j < NWORDS_FIELD; j++) {
            if (t1[i][j] != 0) return false;
        }
    }

    return true; }
#else
    return ((is_digit_zero_ct(t1[0][0] | t1[0][1]) || is_digit_zero_ct((t1[0][0]+1) | (t1[0][1]+1))) &
            (is_digit_zero_ct(t1[1][0] | t1[1][1]) || is_digit_zero_ct((t1[1][0]+1) | (t1[1][1]+1))));
#endif
}


ECCRYPTO_STATUS decode(const unsigned char* Pencoded, point_t P)
{ // Decode point P
  // SECURITY NOTE: this function does not run in constant time.
    felm_t r, t, t0, t1, t2, t3, t4;
    f2elm_t u, v, one = {0};
    digit_t sign_dec;
    point_extproj_t R;
    unsigned int i, sign;

    one[0][0] = 1;
    memcpy((unsigned char*)P->y, Pencoded, 32);    // Decoding y-coordinate and sign
    sign = (unsigned int)(Pencoded[31] >> 7);
    P->y[1][NWORDS_FIELD-1] &= mask_7fff;

    fp2sqr1271(P->y, u);
    fp2mul1271(u, (felm_t*)&PARAMETER_d, v);
    fp2sub1271(u, one, u);
    fp2add1271(v, one, v);

    fpsqr1271(v[0], t0);                            // t0 = v0^2
    fpsqr1271(v[1], t1);                            // t1 = v1^2
    fpadd1271(t0, t1, t0);                          // t0 = t0+t1   
    fpmul1271(u[0], v[0], t1);                      // t1 = u0*v0
    fpmul1271(u[1], v[1], t2);                      // t2 = u1*v1 
    fpadd1271(t1, t2, t1);                          // t1 = t1+t2  
    fpmul1271(u[1], v[0], t2);                      // t2 = u1*v0
    fpmul1271(u[0], v[1], t3);                      // t3 = u0*v1
    fpsub1271(t2, t3, t2);                          // t2 = t2-t3    
    fpsqr1271(t1, t3);                              // t3 = t1^2    
    fpsqr1271(t2, t4);                              // t4 = t2^2
    fpadd1271(t3, t4, t3);                          // t3 = t3+t4
    for (i = 0; i < 125; i++) {                     // t3 = t3^(2^125)
        fpsqr1271(t3, t3);
    }

    fpadd1271(t1, t3, t);                           // t = t1+t3
    mod1271(t);
    if (is_zero_ct(t, NWORDS_FIELD) == true) {
        fpsub1271(t1, t3, t);                       // t = t1-t3
    }
    fpadd1271(t, t, t);                             // t = 2*t            
    fpsqr1271(t0, t3);                              // t3 = t0^2      
    fpmul1271(t0, t3, t3);                          // t3 = t3*t0   
    fpmul1271(t, t3, t3);                           // t3 = t3*t
    fpexp1251(t3, r);                               // r = t3^(2^125-1)  
    fpmul1271(t0, r, t3);                           // t3 = t0*r          
    fpmul1271(t, t3, P->x[0]);                      // x0 = t*t3 
    fpsqr1271(P->x[0], t1);
    fpmul1271(t0, t1, t1);                          // t1 = t0*x0^2 
    fpdiv1271(P->x[0]);                             // x0 = x0/2         
    fpmul1271(t2, t3, P->x[1]);                     // x1 = t3*t2  

    fpsub1271(t, t1, t);
    mod1271(t);
    if (is_zero_ct(t, NWORDS_FIELD) == false) {        // If t != t1 then swap x0 and x1       
        fpcopy1271(P->x[0], t0);
        fpcopy1271(P->x[1], P->x[0]);
        fpcopy1271(t0, P->x[1]);
    }
    
    mod1271(P->x[0]);
    if (is_zero_ct((digit_t*)P->x, NWORDS_FIELD) == true) {
        sign_dec = ((digit_t*)&P->x[1])[NWORDS_FIELD-1] >> (sizeof(digit_t)*8 - 2);
    } else {
        sign_dec = ((digit_t*)&P->x[0])[NWORDS_FIELD-1] >> (sizeof(digit_t)*8 - 2);
    }

    if (sign != (unsigned int)sign_dec) {           // If sign of x-coordinate decoded != input sign bit, then negate x-coordinate
        fp2neg1271(P->x);
    }

    point_setup(P, R);
    if (ecc_point_validate(R) == false) {
        fpneg1271(R->x[1]);
        fpcopy1271(R->x[1], P->x[1]);
        if (ecc_point_validate(R) == false) {       // Final point validation
            return ECCRYPTO_ERROR;
        }
    }

    return ECCRYPTO_SUCCESS;
}


void to_Montgomery(const digit_t* ma, digit_t* c)
{ // Converting to Montgomery representation

    Montgomery_multiply_mod_order(ma, (digit_t*)&Montgomery_Rprime, c);
}


void from_Montgomery(const digit_t* a, digit_t* mc)
{ // Converting from Montgomery to standard representation
    digit_t one[NWORDS_ORDER] = {0};
    one[0] = 1;

    Montgomery_multiply_mod_order(a, one, mc);
}


void Montgomery_inversion_mod_order(const digit_t* ma, digit_t* mc)
{ // (Non-constant time) Montgomery inversion modulo the curve order using a^(-1) = a^(order-2) mod order
  // This function uses the sliding-window method
    sdigit_t i = 256;
    unsigned int j, nwords = NWORDS_ORDER;
    digit_t temp, bit = 0, count, mod2, k_EXPON = 5;       // Fixing parameter k to 5 for the sliding windows method
    digit_t modulus2[NWORDS_ORDER] = {0}, npoints = 16;
    digit_t input_a[NWORDS_ORDER];
    digit_t table[16][NWORDS_ORDER];                       // Fixing the number of precomputed elements to 16 (assuming k = 5)
    digit_t mask = (digit_t)1 << (sizeof(digit_t)*8 - 1);  // 0x800...000
    digit_t mask2 = ~((digit_t)(-1) >> k_EXPON);           // 0xF800...000, assuming k = 5

    // SECURITY NOTE: this function does not run in constant time because the modulus is assumed to be public.

    modulus2[0] = 2;
    subtract((digit_t*)&curve_order, modulus2, modulus2, nwords);       // modulus-2

    // Precomputation stage
    memcpy((unsigned char*)&table[0], (unsigned char*)ma, 32);         // table[0] = ma 
    Montgomery_multiply_mod_order(ma, ma, input_a);                     // ma^2
    for (j = 0; j < npoints - 1; j++) {
        Montgomery_multiply_mod_order(table[j], input_a, table[j+1]);   // table[j+1] = table[j] * ma^2
    }

    while (bit != 1) {                                                  // Shift (modulus-2) to the left until getting first bit 1
        i--;
        temp = 0;
        for (j = 0; j < nwords; j++) {
            bit = (modulus2[j] & mask) >> (sizeof(digit_t)*8 - 1);
            modulus2[j] = (modulus2[j] << 1) | temp;
            temp = bit;
        }
    }

    // Evaluation stage
    memcpy((unsigned char*)mc, (unsigned char*)ma, 32);
    bit = (modulus2[nwords-1] & mask) >> (sizeof(digit_t)*8 - 1);
    while (i > 0) {
        if (bit == 0) {                                       // Square accumulated value because bit = 0 and shift (modulus-2) one bit to the left
            Montgomery_multiply_mod_order(mc, mc, mc);        // mc = mc^2
            i--;
            for (j = (nwords - 1); j > 0; j--) {
                SHIFTL(modulus2[j], modulus2[j-1], 1, modulus2[j], RADIX);
            }
            modulus2[0] = modulus2[0] << 1;
        } else {                                              // "temp" will store the longest odd bitstring with "count" bits s.t. temp <= 2^k - 1 
            count = k_EXPON;
            temp = (modulus2[nwords-1] & mask2) >> (sizeof(digit_t)*8 - k_EXPON);  // Extracting next k bits to the left
            mod2 = temp & 1;
            while (mod2 == 0) {                               // if even then shift to the right and adjust count
                temp = (temp >> 1);
                mod2 = temp & 1;
                count--;
            }
            for (j = 0; j < count; j++) {                     // mc = mc^count
                Montgomery_multiply_mod_order(mc, mc, mc);
            }
            Montgomery_multiply_mod_order(mc, table[(temp-1) >> 1], mc);   // mc = mc * table[(temp-1)/2] 
            i = i - count;

            for (j = (nwords - 1); j > 0; j--) {              // Shift (modulus-2) "count" bits to the left
                SHIFTL(modulus2[j], modulus2[j-1], count, modulus2[j], RADIX);
            }
            modulus2[0] = modulus2[0] << count;
        }
        bit = (modulus2[nwords - 1] & mask) >> (sizeof(digit_t)*8 - 1);
    }
}



/***********************************************/
/**********  CURVE/SCALAR FUNCTIONS  ***********/

void eccset(point_t P)
{ // Set generator  
  // Output: P = (x,y)
    
    fp2copy1271((felm_t*)&GENERATOR_x, P->x);    // X1
    fp2copy1271((felm_t*)&GENERATOR_y, P->y);    // Y1
}


void eccnorm(point_extproj_t P, point_t Q)
{ // Normalize a projective point (X1:Y1:Z1), including full reduction
  // Input: P = (X1:Y1:Z1) in twisted Edwards coordinates    
  // Output: Q = (X1/Z1,Y1/Z1), corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
    
    fp2inv1271(P->z);                      // Z1 = Z1^-1
    fp2mul1271(P->x, P->z, Q->x);          // X1 = X1/Z1
    fp2mul1271(P->y, P->z, Q->y);          // Y1 = Y1/Z1
    mod1271(Q->x[0]); mod1271(Q->x[1]); 
    mod1271(Q->y[0]); mod1271(Q->y[1]); 
}


void R1_to_R2(point_extproj_t P, point_extproj_precomp_t Q) 
{ // Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT), where T = Ta*Tb
  // Input:  P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
    
    fp2add1271(P->ta, P->ta, Q->t2);                  // T = 2*Ta
    fp2add1271(P->x, P->y, Q->xy);                    // QX = X+Y
    fp2sub1271(P->y, P->x, Q->yx);                    // QY = Y-X 
    fp2mul1271(Q->t2, P->tb, Q->t2);                  // T = 2*T
    fp2add1271(P->z, P->z, Q->z2);                    // QZ = 2*Z
    fp2mul1271(Q->t2, (felm_t*)&PARAMETER_d, Q->t2); // QT = 2d*T
}


__inline void R1_to_R3(point_extproj_t P, point_extproj_precomp_t Q)      
{ // Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,Z,T), where T = Ta*Tb 
  // Input:  P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (X1+Y1,Y1-X1,Z1,T1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates 
    
    fp2add1271(P->x, P->y, Q->xy);         // XQ = (X1+Y1) 
    fp2sub1271(P->y, P->x, Q->yx);         // YQ = (Y1-X1) 
    fp2mul1271(P->ta, P->tb, Q->t2);       // TQ = T1
    fp2copy1271(P->z, Q->z2);              // ZQ = Z1 
}


void R2_to_R4(point_extproj_precomp_t P, point_extproj_t Q)      
{ // Conversion from representation (X+Y,Y-X,2Z,2dT) to (2X,2Y,2Z,2dT) 
  // Input:  P = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (2X1,2Y1,2Z1) corresponding to (X1:Y1:Z1) in twisted Edwards coordinates 
    
    fp2sub1271(P->xy, P->yx, Q->x);        // XQ = 2*X1
    fp2add1271(P->xy, P->yx, Q->y);        // YQ = 2*Y1
    fp2copy1271(P->z2, Q->z);              // ZQ = 2*Z1
}


__inline void eccadd_core(point_extproj_precomp_t P, point_extproj_precomp_t Q, point_extproj_t R)      
{ // Basic point addition R = P+Q or R = P+P
  // Inputs: P = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (X2+Y2,Y2-X2,Z2,T2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates    
  // Output: R = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2; 
          
    fp2mul1271(P->t2, Q->t2, R->z);        // Z = 2dT1*T2 
    fp2mul1271(P->z2, Q->z2, t1);          // t1 = 2Z1*Z2  
    fp2mul1271(P->xy, Q->xy, R->x);        // X = (X1+Y1)(X2+Y2) 
    fp2mul1271(P->yx, Q->yx, R->y);        // Y = (Y1-X1)(Y2-X2) 
    fp2sub1271(t1, R->z, t2);              // t2 = theta
    fp2add1271(t1, R->z, t1);              // t1 = alpha
    fp2sub1271(R->x, R->y, R->tb);         // Tbfinal = beta
    fp2add1271(R->x, R->y, R->ta);         // Tafinal = omega
    fp2mul1271(R->tb, t2, R->x);           // Xfinal = beta*theta
    fp2mul1271(t1, t2, R->z);              // Zfinal = theta*alpha
    fp2mul1271(R->ta, t1, R->y);           // Yfinal = alpha*omega
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


void eccadd(point_extproj_precomp_t Q, point_extproj_t P)      
{ // Complete point addition P = P+Q or P = P+P
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (X2+Y2,Y2-X2,2Z2,2dT2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates   
  // Output: P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal, 
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    point_extproj_precomp_t R;
    
    R1_to_R3(P, R);                        // R = (X1+Y1,Y1-Z1,Z1,T1)
    eccadd_core(Q, R, P);                  // P = (X2+Y2,Y2-X2,2Z2,2dT2) + (X1+Y1,Y1-Z1,Z1,T1)

#ifdef TEMP_ZEROING
    clear_words((void*)R, sizeof(point_extproj_precomp_t)/sizeof(unsigned int));
#endif
}


static __inline void R5_to_R1(point_precomp_t P, point_extproj_t Q)      
{ // Conversion from representation (x+y,y-x,2dt) to (X,Y,Z,Ta,Tb) 
  // Input:  P = (x1+y1,y1-x1,2dt1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates, where Z1=1
  // Output: Q = (x1,y1,z1,x1,y1), where z1=1, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates 
    
    fp2sub1271(P->xy, P->yx, Q->x);        // 2*x1
    fp2add1271(P->xy, P->yx, Q->y);        // 2*y1
    fp2div1271(Q->x);                      // XQ = x1
    fp2div1271(Q->y);                      // YQ = y1 
    fp2zero1271(Q->z); Q->z[0][0]=1;       // ZQ = 1
    fp2copy1271(Q->x, Q->ta);              // TaQ = x1
    fp2copy1271(Q->y, Q->tb);              // TbQ = y1
}


static __inline void eccmadd(point_precomp_t Q, point_extproj_t P)
{ // Mixed point addition P = P+Q or P = P+P
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (x2+y2,y2-x2,2dt2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates, where Z2=1  
  // Output: P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal, 
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2;
    
    fp2mul1271(P->ta, P->tb, P->ta);        // Ta = T1
    fp2add1271(P->z, P->z, t1);             // t1 = 2Z1        
    fp2mul1271(P->ta, Q->t2, P->ta);        // Ta = 2dT1*t2 
    fp2add1271(P->x, P->y, P->z);           // Z = (X1+Y1) 
    fp2sub1271(P->y, P->x, P->tb);          // Tb = (Y1-X1)
    fp2sub1271(t1, P->ta, t2);              // t2 = theta
    fp2add1271(t1, P->ta, t1);              // t1 = alpha
    fp2mul1271(Q->xy, P->z, P->ta);         // Ta = (X1+Y1)(x2+y2)
    fp2mul1271(Q->yx, P->tb, P->x);         // X = (Y1-X1)(y2-x2)
    fp2mul1271(t1, t2, P->z);               // Zfinal = theta*alpha
    fp2sub1271(P->ta, P->x, P->tb);         // Tbfinal = beta
    fp2add1271(P->ta, P->x, P->ta);         // Tafinal = omega
    fp2mul1271(P->tb, t2, P->x);            // Xfinal = beta*theta
    fp2mul1271(P->ta, t1, P->y);            // Yfinal = alpha*omega
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


void eccmadd_ni(point_precomp_t Q, point_extproj_t P)
{
    eccmadd(Q, P);
}



/***********************************************/
/**********  CURVE/SCALAR FUNCTIONS  ***********/


__inline void eccdouble(point_extproj_t P)
{ // Point doubling 2P
  // Input: P = (X1:Y1:Z1) in twisted Edwards coordinates
  // Output: 2P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2;  

    fp2sqr1271(P->x, t1);                  // t1 = X1^2
    fp2sqr1271(P->y, t2);                  // t2 = Y1^2
    fp2add1271(P->x, P->y, P->x);          // t3 = X1+Y1
    fp2add1271(t1, t2, P->tb);             // Tbfinal = X1^2+Y1^2      
    fp2sub1271(t2, t1, t1);                // t1 = Y1^2-X1^2      
    fp2sqr1271(P->x, P->ta);               // Ta = (X1+Y1)^2 
    fp2sqr1271(P->z, t2);                  // t2 = Z1^2  
    fp2sub1271(P->ta, P->tb, P->ta);       // Tafinal = 2X1*Y1 = (X1+Y1)^2-(X1^2+Y1^2)  
    fp2addsub1271(t2, t1, t2);             // t2 = 2Z1^2-(Y1^2-X1^2) 
    fp2mul1271(t1, P->tb, P->y);           // Yfinal = (X1^2+Y1^2)(Y1^2-X1^2)  
    fp2mul1271(t2, P->ta, P->x);           // Xfinal = 2X1*Y1*[2Z1^2-(Y1^2-X1^2)]
    fp2mul1271(t1, t2, P->z);              // Zfinal = (Y1^2-X1^2)[2Z1^2-(Y1^2-X1^2)]
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


void fixed_window_recode(uint64_t* scalar, unsigned int* digits, unsigned int* sign_masks)
{ // Converting scalar to the fixed window representation used by the variable-base scalar multiplication
  // Inputs: scalar in [0, order-1], where the order of FourQ's subgroup is 246 bits.
  // Outputs: "digits" array with (t_VARBASE+1) nonzero entries. Each entry is in the range [0, 7], corresponding to one entry in the precomputed table.
  //          where t_VARBASE+1 = ((bitlength(order)+w-1)/(w-1))+1 represents the fixed length of the recoded scalar using window width w. 
  //          The value of w is fixed to W_VARBASE = 5, which corresponds to a precomputed table with 2^(W_VARBASE-2) = 8 entries (see FourQ.h)
  //          used by the variable base scalar multiplication ecc_mul(). 
  //          "sign_masks" array with (t_VARBASE+1) entries storing the signs for their corresponding digits in "digits". 
  //          Notation: if the corresponding digit > 0 then sign_mask = 0xFF...FF, else if digit < 0 then sign_mask = 0.
    unsigned int val1, val2, i, j;
    uint64_t res, borrow;
    int64_t temp;

    val1 = (1 << W_VARBASE) - 1;
    val2 = (1 << (W_VARBASE-1));

    for (i = 0; i < t_VARBASE; i++)
    {
        temp = (scalar[0] & val1) - val2;    // ki = (k mod 2^w)/2^(w-1)
        sign_masks[i] = ~((unsigned int)(temp >> (RADIX64-1)));
        digits[i] = ((sign_masks[i] & (unsigned int)(temp ^ -temp)) ^ (unsigned int)-temp) >> 1;        
                 
        res = scalar[0] - temp;              // k = (k - ki) / 2^(w-1) 
        borrow = ((temp >> (RADIX64-1)) - 1) & (uint64_t)is_digit_lessthan_ct((digit_t)scalar[0], (digit_t)temp);
        scalar[0] = res;
  
        for (j = 1; j < NWORDS64_ORDER; j++)
        {
            res = scalar[j];
            scalar[j] = res - borrow;
            borrow = (uint64_t)is_digit_lessthan_ct((digit_t)res, (digit_t)borrow); 
        }    
  
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {           
            SHIFTR(scalar[j+1], scalar[j], (W_VARBASE-1), scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] = scalar[NWORDS64_ORDER-1] >> (W_VARBASE-1);

    } 
    sign_masks[t_VARBASE] = ~((unsigned int)(scalar[0] >> (RADIX64-1)));
    digits[t_VARBASE] = ((sign_masks[t_VARBASE] & (unsigned int)(scalar[0] ^ (0-scalar[0]))) ^ (unsigned int)(0-scalar[0])) >> 1;    // kt = k  (t_VARBASE+1 digits)
}


void ecc_precomp(point_extproj_t P, point_extproj_precomp_t *T)
{ // Generation of the precomputation table used by the variable-base scalar multiplication ecc_mul().
  // Input: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates.
  // Output: table T containing NPOINTS_VARBASE points: P, 3P, 5P, ... , (2*NPOINTS_VARBASE-1)P. NPOINTS_VARBASE is fixed to 8 (see FourQ.h).
  //         Precomputed points use the representation (X+Y,Y-X,2Z,2dT) corresponding to (X:Y:Z:T) in extended twisted Edwards coordinates.
    point_extproj_precomp_t P2;
    point_extproj_t Q;
    unsigned int i; 

    // Generating P2 = 2(X1,Y1,Z1,T1a,T1b) = (XP2+YP2,Y2P-X2P,ZP2,TP2) and T[0] = P = (X1+Y1,Y1-X1,2*Z1,2*d*T1)
    ecccopy(P, Q);
    R1_to_R2(P, T[0]);
    eccdouble(Q);
    R1_to_R3(Q, P2);

    for (i = 1; i < NPOINTS_VARBASE; i++) {
        // T[i] = 2P+T[i-1] = (2*i+1)P = (XP2+YP2,Y2P-X2P,ZP2,TP2) + (X_(2*i-1)+Y_(2*i-1), Y_(2*i-1)-X_(2*i-1), 2Z_(2*i-1), 2T_(2*i-1)) = (X_(2*i+1)+Y_(2*i+1), Y_(2*i+1)-X_(2*i+1), 2Z_(2*i+1), 2dT_(2*i+1))
        eccadd_core(P2, T[i-1], Q);
        R1_to_R2(Q, T[i]);
    }
}


void cofactor_clearing(point_extproj_t P)
{ // Co-factor clearing
  // Input: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: P = 392*P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    point_extproj_precomp_t Q;
     
    R1_to_R2(P, Q);                      // Converting from (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT)
    eccdouble(P);                        // P = 2*P using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
    eccadd(Q, P);                        // P = P+Q using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (X+Y,Y-X,2Z,2dT)
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
    eccadd(Q, P);
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
}


bool ecc_mul(point_t P, digit_t* k, point_t Q, bool clear_cofactor)
{ // Scalar multiplication Q = k*P
  // Inputs: scalar "k" in [0, 2^256-1],
  //         point P = (x,y) in affine coordinates,
  //         clear_cofactor = 1 (TRUE) or 0 (FALSE) whether cofactor clearing is required or not, respectively.
  // Output: Q = k*P in affine coordinates (x,y).
  // This function performs point validation and (if selected) cofactor clearing.
    point_extproj_t R;
    point_extproj_precomp_t S, Table[NPOINTS_VARBASE];
    unsigned int digits[t_VARBASE+1] = {0}, sign_masks[t_VARBASE+1] = {0};
    digit_t k_odd[NWORDS_ORDER];
    int i;

    point_setup(P, R);                                         // Convert to representation (X,Y,1,Ta,Tb)

    if (ecc_point_validate(R) == false) {                      // Check if point lies on the curve
        return false;
    }

    if (clear_cofactor == true) {
        cofactor_clearing(R);
    }

    modulo_order(k, k_odd);                                    // k_odd = k mod (order)      
    conversion_to_odd(k_odd, k_odd);                           // Converting scalar to odd using the prime subgroup order 
    ecc_precomp(R, Table);                                     // Precomputation of points T[0],...,T[npoints-1] 
    fixed_window_recode((uint64_t*)k_odd, digits, sign_masks); // Scalar recoding
    table_lookup_1x8(Table, S, digits[t_VARBASE], sign_masks[t_VARBASE]);       
    R2_to_R4(S, R);                                            // Conversion to representation (2X,2Y,2Z)
    
    for (i = (t_VARBASE-1); i >= 0; i--)
    {
        eccdouble(R);
        table_lookup_1x8(Table, S, digits[i], sign_masks[i]);  // Extract point in (X+Y,Y-X,2Z,2dT) representation
        eccdouble(R);
        eccdouble(R);
        eccdouble(R);                                          // P = 2*P using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
        eccadd(S, R);                                          // P = P+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (X+Y,Y-X,2Z,2dT)
    }
    eccnorm(R, Q);                                             // Convert to affine coordinates (x,y) 
    
#ifdef TEMP_ZEROING
    clear_words((void*)k_odd, NWORDS_ORDER*(sizeof(digit_t)/sizeof(unsigned int)));
    clear_words((void*)digits, t_VARBASE+1);
    clear_words((void*)sign_masks, t_VARBASE+1);
    clear_words((void*)S, sizeof(point_extproj_precomp_t)/sizeof(unsigned int));
#endif
    return true;
}


void mLSB_set_recode(uint64_t* scalar, unsigned int *digits)
{ // Computes the modified LSB-set representation of a scalar
  // Inputs: scalar in [0, order-1], where the order of FourQ's subgroup is 246 bits.
  // Output: digits, where the first "d" values (from index 0 to (d-1)) store the signs for the recoded values using the convention: -1 (negative), 0 (positive), and
  //         the remaining values (from index d to (l-1)) store the recoded values in mLSB-set representation, excluding their sign, 
  //         where l = d*w and d = ceil(bitlength(order)/(w*v))*v. The values v and w are fixed and must be in the range [1, 10] (see FourQ.h); they determine the size 
  //         of the precomputed table "FIXED_BASE_TABLE" used by ecc_mul_fixed(). 
    unsigned int i, j, d = D_FIXEDBASE, l = L_FIXEDBASE;
    uint64_t temp, carry;
    
    digits[d-1] = 0;

    // Shift scalar to the right by 1   
    for (j = 0; j < (NWORDS64_ORDER-1); j++) {
        SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
    }
    scalar[NWORDS64_ORDER-1] >>= 1;

    for (i = 0; i < (d-1); i++)
    {
        digits[i] = (unsigned int)((scalar[0] & 1) - 1);  // Convention for the "sign" row: 
                                                          // if scalar_(i+1) = 0 then digit_i = -1 (negative), else if scalar_(i+1) = 1 then digit_i = 0 (positive)
        // Shift scalar to the right by 1   
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] >>= 1;
    } 

    for (i = d; i < l; i++)
    {
        digits[i] = (unsigned int)(scalar[0] & 1);        // digits_i = k mod 2. Sign is determined by the "sign" row

        // Shift scalar to the right by 1  
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] >>= 1;

        temp = (0 - digits[i-(i/d)*d]) & digits[i];       // if (digits_i=0 \/ 1) then temp = 0, else if (digits_i=-1) then temp = 1 
            
        // floor(scalar/2) + temp
        scalar[0] = scalar[0] + temp;
        carry = (temp & (uint64_t)is_digit_zero_ct((digit_t)scalar[0]));       // carry = (scalar[0] < temp);
        for (j = 1; j < NWORDS64_ORDER; j++)
        {
            scalar[j] = scalar[j] + carry; 
            carry = (carry & (uint64_t)is_digit_zero_ct((digit_t)scalar[j]));  // carry = (scalar[j] < temp);
        }
    } 
    return;              
}


bool ecc_mul_fixed(digit_t* k, point_t Q)
{ // Fixed-base scalar multiplication Q = k*G, where G is the generator. FIXED_BASE_TABLE stores v*2^(w-1) = 80 multiples of G.
  // Inputs: scalar "k" in [0, 2^256-1].
  // Output: Q = k*G in affine coordinates (x,y).
  // The function is based on the modified LSB-set comb method, which converts the scalar to an odd signed representation
  // with (bitlength(order)+w*v) digits.
    unsigned int j, w = W_FIXEDBASE, v = V_FIXEDBASE, d = D_FIXEDBASE, e = E_FIXEDBASE;
    unsigned int digit = 0, digits[NBITS_ORDER_PLUS_ONE+(W_FIXEDBASE*V_FIXEDBASE)-1] = {0}; 
    digit_t temp[NWORDS_ORDER];
    point_extproj_t R;
    point_precomp_t S;
    int i, ii;

	modulo_order(k, temp);                                      // temp = k mod (order) 
	conversion_to_odd(temp, temp);                              // Converting scalar to odd using the prime subgroup order
	mLSB_set_recode((uint64_t*)temp, digits);                   // Scalar recoding

    // Extracting initial digit 
    digit = digits[w*d-1];
    for (i = (int)((w-1)*d-1); i >= (int)(2*d-1); i = i-d)           
    {
        digit = 2*digit + digits[i];
    }
    // Initialize R = (x+y,y-x,2dt) with a point from the table
	table_lookup_fixed_base(((point_precomp_t*)&FIXED_BASE_TABLE)+(v-1)*(1 << (w-1)), S, digit, digits[d-1]);
    R5_to_R1(S, R);                                             // Converting to representation (X:Y:1:Ta:Tb)

    for (j = 0; j < (v-1); j++)
    {
        digit = digits[w*d-(j+1)*e-1];
        for (i = (int)((w-1)*d-(j+1)*e-1); i >= (int)(2*d-(j+1)*e-1); i = i-d)           
        {
            digit = 2*digit + digits[i];
        }
        // Extract point in (x+y,y-x,2dt) representation
        table_lookup_fixed_base(((point_precomp_t*)&FIXED_BASE_TABLE)+(v-j-2)*(1 << (w-1)), S, digit, digits[d-(j+1)*e-1]);
        eccmadd(S, R);                                          // R = R+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (x+y,y-x,2dt) 
    }

    for (ii = (e-2); ii >= 0; ii--)
    {
        eccdouble(R);                                           // R = 2*R using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
        for (j = 0; j < v; j++)
        {
            digit = digits[w*d-j*e+ii-e];
            for (i = (int)((w-1)*d-j*e+ii-e); i >= (int)(2*d-j*e+ii-e); i = i-d)           
            {
                digit = 2*digit + digits[i];
            }
            // Extract point in (x+y,y-x,2dt) representation
            table_lookup_fixed_base(((point_precomp_t*)&FIXED_BASE_TABLE)+(v-j-1)*(1 << (w-1)), S, digit, digits[d-j*e+ii-e]);
            eccmadd(S, R);                                      // R = R+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (x+y,y-x,2dt)
        }        
    }     
    eccnorm(R, Q);                                              // Conversion to affine coordinates (x,y) and modular correction. 
    
#ifdef TEMP_ZEROING
    clear_words((void*)digits, NBITS_ORDER_PLUS_ONE+(W_FIXEDBASE*V_FIXEDBASE)-1);
    clear_words((void*)S, sizeof(point_precomp_t)/sizeof(unsigned int));
#endif
    return true;
}


static __inline void eccneg_extproj_precomp(point_extproj_precomp_t P, point_extproj_precomp_t Q)
{ // Point negation
  // Input : point P in coordinates (X+Y,Y-X,2Z,2dT)
  // Output: point Q = -P = (Y-X,X+Y,2Z,-2dT)
    fp2copy1271(P->t2, Q->t2);
    fp2copy1271(P->xy, Q->yx);
    fp2copy1271(P->yx, Q->xy);
    fp2copy1271(P->z2, Q->z2);
    fp2neg1271(Q->t2);
}


static __inline void eccneg_precomp(point_precomp_t P, point_precomp_t Q)
{ // Point negation
  // Input : point P in coordinates (x+y,y-x,2dt)
  // Output: point Q = -P = (y-x,x+y,-2dt)
    fp2copy1271(P->t2, Q->t2);
    fp2copy1271(P->xy, Q->yx);
    fp2copy1271(P->yx, Q->xy);
    fp2neg1271(Q->t2);
}


bool ecc_mul_double(digit_t* k, point_t Q, digit_t* l, point_t R)
{ // Double scalar multiplication R = k*G + l*Q, where the G is the generator. Uses DOUBLE_SCALAR_TABLE, which contains multiples of G, Phi(G), Psi(G) and Phi(Psi(G)).
  // Inputs: point Q in affine coordinates,
  //         scalars "k" and "l" in [0, 2^256-1].
  // Output: R = k*G + l*Q in affine coordinates (x,y).
  // The function uses wNAF with interleaving.
            
    // SECURITY NOTE: this function is intended for a non-constant-time operation such as signature verification. 

    point_t A;
    point_extproj_t T;
    point_extproj_precomp_t S;

    if (ecc_mul(Q, l, A, false) == false) {
        return false;
    }
    point_setup(A, T);
    R1_to_R2(T, S);

    ecc_mul_fixed(k, A);
    point_setup(A, T);
    eccadd(S, T);

    eccnorm(T, R);                                             // Output R = (x,y)
    
    return true;
}


void ecc_precomp_double(point_extproj_t P, point_extproj_precomp_t* Table, unsigned int npoints)
{ // Generation of the precomputation table used internally by the double scalar multiplication function ecc_mul_double().  
  // Inputs: point P in representation (X,Y,Z,Ta,Tb),
  //         Table with storage for npoints, 
  //         number of points "npoints".
  // Output: Table containing multiples of the base point P using representation (X+Y,Y-X,2Z,2dT).
    point_extproj_t Q;
    point_extproj_precomp_t PP;
    unsigned int i; 
    
    R1_to_R2(P, Table[0]);                     // Precomputed point Table[0] = P in coordinates (X+Y,Y-X,2Z,2dT)
    eccdouble(P);                              // A = 2*P in (X,Y,Z,Ta,Tb)
    R1_to_R3(P, PP);                           // Converting from (X,Y,Z,Ta,Tb) to (X+Y,Y-X,Z,T) 
    
    for (i = 1; i < npoints; i++) {
        eccadd_core(Table[i-1], PP, Q);        // Table[i] = Table[i-1]+2P using the representations (X,Y,Z,Ta,Tb) <- (X+Y,Y-X,2Z,2dT) + (X+Y,Y-X,Z,T)
        R1_to_R2(Q, Table[i]);                 // Converting from (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT)
    }
    
    return;
}


void wNAF_recode(uint64_t scalar, unsigned int w, int* digits)
{ // Computes wNAF recoding of a scalar, where digits are in set {0,+-1,+-3,...,+-(2^(w-1)-1)}
    unsigned int i;
    int digit, index = 0; 
    int val1 = (int)(1 << (w-1)) - 1;                  // 2^(w-1) - 1
    int val2 = (int)(1 << w);                          // 2^w;
    uint64_t k = scalar, mask = (uint64_t)val2 - 1;    // 2^w - 1 

    while (k != 0)
    {
        digit = (int)(k & 1); 

        if (digit == 0) {                         
            k >>= 1;                 // Shift scalar to the right by 1
            digits[index] = 0;
        } else {
            digit = (int)(k & mask); 
            k >>= w;                 // Shift scalar to the right by w            

            if (digit > val1) {
                digit -= val2; 
            }
            if (digit < 0) {         // scalar + 1
                k += 1;
            }
            digits[index] = digit; 
                       
            if (k != 0) {            // Check if scalar != 0
                for (i = 0; i < (w-1); i++) 
                {     
                    index++; 
                    digits[index] = 0;
                }
            }
        }
        index++;
    } 
    return;
}
