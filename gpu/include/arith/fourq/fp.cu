
// #define PRAGMA_UNROLL

__device__ __constant__ uint64_t d_curve_order[4]       = { 0x2FB2540EC7768CE7, 0xDFBD004DFE0F7999, 0xF05397829CBC14E5, 0x0029CBC14E5E0A72 };
__device__ __constant__ uint64_t d_Montgomery_Rprime[4] = { 0xC81DB8795FF3D621, 0x173EA5AAEA6B387D, 0x3D01B7C72136F61C, 0x0006A5F16AC8F9D3 };
__device__ __constant__ uint64_t d_Montgomery_rprime[4] = { 0xE12FE5F079BC3929, 0xD75E78B8D1FCDCF3, 0xBCE409ED76B5DB21, 0xF32702FDAFC1C074 };

__device__ __forceinline__ void d_mp_mul_ptx(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Schoolbook multiprecision multiply, c = a*b   
    unsigned int i, j;
    // digit_t u, v, UV[2];
    // unsigned int carry = 0;

#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
    for (i = 0; i < (2*nwords); i++) c[i] = 0;
#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
     for (i = 0; i < nwords; i++) {
        c[i+0] = madlo_cc(a[i], b[0], c[i+0]);
#ifdef PRAGMA_UNROLL
        #pragma unroll
#endif
        for (j = 1; j < nwords; j++) {
            c[i+j] = madloc_cc(a[i], b[j], c[i+j]);
        }
        c[i+nwords+1] = madlo(0, 0, 0);
    }
}

__device__ __forceinline__ void d_mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Schoolbook multiprecision multiply, c = a*b   
    unsigned int i, j;
    digit_t u, v, UV[2];
    digit_t carry = 0;

#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
    for (i = 0; i < (2*nwords); i++) c[i] = 0;

#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
     for (i = 0; i < nwords; i++) {
        u = 0;
#ifdef PRAGMA_UNROLL
        #pragma unroll
#endif
        for (j = 0; j < nwords; j++) {
            D_MUL(a[i], b[j], UV[1], UV[0]); 
            D_ADDC(0, UV[0], u, carry, v); 
            u = UV[1] + carry;

            // v = madlo(a[i], b[i],u);
            // u = madhi(a[i], b[i],u);
            // asm volatile ("add.u64 %0, %1, %2;" : "=l"(u) : "l"(u), "l"(carry));

            D_ADDC(0, c[i+j], v, carry, v); 
            u = u + carry;
            c[i+j] = v;
        }
        c[nwords+i] = u;
     }
}

__device__ __forceinline__ unsigned int d_mp_add(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
    digit_t carry;

    asm volatile ("add.cc.u64 %0, %1, %2;" : "=l"(c[0]) : "l"(a[0]), "l"(b[0]) );
#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
    for (int i = 1; i < nwords; i++) {
        asm volatile ("addc.cc.u64 %0, %1, %2;" : "=l"(c[i]) : "l"(a[i]), "l"(b[i]) );
    }
    asm volatile ("addc.u64 %0, 0, 0;" : "=l"(carry));
    
    return carry;
}

__device__ static __forceinline__ void d_multiply(const digit_t* a, const digit_t* b, digit_t* c)
{ // Schoolbook multiprecision multiply, c = a*b 

    d_mp_mul(a, b, c, NWORDS_ORDER);
}

__device__ __forceinline__ unsigned int d_subtract(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
    digit_t borrow = 0;

    asm volatile ("sub.cc.u64 %0, %1, %2;" : "=l"(c[0]) : "l"(a[0]), "l"(b[0]) );
#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
    for (int i = 1; i < nwords; i++) {
        asm volatile ("subc.cc.u64 %0, %1, %2;" : "=l"(c[i]) : "l"(a[i]), "l"(b[i]) );
    }
    asm volatile ("subc.u64 %0, 0, 0;" : "=l"(borrow) );
    
    return -borrow;
}

__device__ static __forceinline__ unsigned int d_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
    
    return d_mp_add((digit_t*)a, (digit_t*)b, c, (unsigned int)nwords);
}

__device__ __forceinline__ void d_subtract_mod_order(const digit_t* a, const digit_t* b, digit_t* c)
{ // Subtraction modulo the curve order, c = a-b mod order
	digit_t mask, carry = 0;
	digit_t* order = (digit_t*)d_curve_order;
	unsigned int i, bout;

	bout = d_subtract(a, b, c, NWORDS_ORDER);            // (bout, c) = a - b
	mask = 0 - (digit_t)bout;                          // if bout = 0 then mask = 0x00..0, else if bout = 1 then mask = 0xFF..F

	for (i = 0; i < NWORDS_ORDER; i++) {               // c = c + (mask & order)
		D_ADDC(carry, c[i], mask & order[i], carry, c[i]);
	}
}

__device__ __forceinline__ void d_add_mod_order(const digit_t* a, const digit_t* b, digit_t* c)
{
    d_add(a, b, c, NWORDS_ORDER);                        // c = a + b

    d_subtract_mod_order(c, (digit_t*)&d_curve_order, c);  // if c >= order then c = c - order
}
// { // Addition modulo the curve order, c = a+b mod order

// 	d_add(a, b, c, NWORDS_ORDER);                        // c = a + b
// 	d_subtract_mod_order(c, (digit_t*)&d_curve_order, c);  // if c >= order then c = c - order
// }

__device__ __forceinline__ void d_Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc)
{ // 256-bit Montgomery multiplication modulo the curve order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1]
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the global value "d_Montgomery_rprime", where r is the order   
	unsigned int i;
	digit_t mask, P[2 * NWORDS_ORDER], Q[2 * NWORDS_ORDER], temp[2 * NWORDS_ORDER];
	digit_t* order = (digit_t*)d_curve_order;
	unsigned int cout = 0, bout = 0;

	d_multiply(ma, mb, P);                               // P = ma * mb
	d_multiply(P, (digit_t*)&d_Montgomery_rprime, Q);      // Q = P * r' mod 2^(log_2(r))
	d_multiply(Q, (digit_t*)&d_curve_order, temp);         // temp = Q * r
	cout = d_add(P, temp, temp, 2 * NWORDS_ORDER);         // (cout, temp) = P + Q * r     

#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
	for (i = 0; i < NWORDS_ORDER; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
		mc[i] = temp[NWORDS_ORDER + i];
	}

	// Final, constant-time subtraction     
	bout = d_subtract(mc, (digit_t*)&d_curve_order, mc, NWORDS_ORDER);    // (cout, mc) = (cout, mc) - r
	mask = (digit_t)cout - (digit_t)bout;              // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

#ifdef PRAGMA_UNROLL
    #pragma unroll
#endif
	for (i = 0; i < NWORDS_ORDER; i++) {               // temp = mask & r
		temp[i] = (order[i] & mask);
	}
	d_add(mc, temp, mc, NWORDS_ORDER);                   //  mc = mc + (mask & r)

	return;
}

__device__ __forceinline__ void d_modulo_order(digit_t* __restrict__ a, digit_t* __restrict__ c)
{ // Reduction modulo the order using Montgomery arithmetic
  // ma = a*d_Montgomery_Rprime mod r, where a,ma in [0, r-1], a,ma,r < 2^256
  // c = ma*1*d_Montgomery_Rprime^(-1) mod r, where ma,c in [0, r-1], ma,c,r < 2^256
	digit_t ma[NWORDS_ORDER], one[NWORDS_ORDER] = { 0 };

	one[0] = 1;
	d_Montgomery_multiply_mod_order(a, (digit_t*)&d_Montgomery_Rprime, ma);
	d_Montgomery_multiply_mod_order(ma, one, c);
}
