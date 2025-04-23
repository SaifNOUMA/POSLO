/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: FourQ's curve parameters
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/ 

#ifndef __FOURQ_PARAMS_H__
#define __FOURQ_PARAMS_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Encoding of field elements, elements over Z_r and elements over GF(p^2):
// -----------------------------------------------------------------------
// Elements over GF(p) and Z_r are encoded with the least significant digit located in the leftmost position (i.e., little endian format). 
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as a||b, with a in the least significant position.

const uint64_t PARAMETER_d[4]       = { 0x0000000000000142, 0x00000000000000E4, 0xB3821488F1FC0C8D, 0x5E472F846657E0FC };
const uint64_t GENERATOR_x[4]       = { 0x286592AD7B3833AA, 0x1A3472237C2FB305, 0x96869FB360AC77F6, 0x1E1F553F2878AA9C };
const uint64_t GENERATOR_y[4]       = { 0xB924A2462BCBB287, 0x0E3FEE9BA120785A, 0x49A7C344844C8B5C, 0x6E1C4AF8630E0242 };
const uint64_t curve_order[4]       = { 0x2FB2540EC7768CE7, 0xDFBD004DFE0F7999, 0xF05397829CBC14E5, 0x0029CBC14E5E0A72 };
const uint64_t Montgomery_Rprime[4] = { 0xC81DB8795FF3D621, 0x173EA5AAEA6B387D, 0x3D01B7C72136F61C, 0x0006A5F16AC8F9D3 };
const uint64_t Montgomery_rprime[4] = { 0xE12FE5F079BC3929, 0xD75E78B8D1FCDCF3, 0xBCE409ED76B5DB21, 0xF32702FDAFC1C074 };


// #define TARGET TARGET_x86
// #define RADIX           32
// typedef uint32_t        digit_t;      // Unsigned 32-bit digit
// typedef int32_t         sdigit_t;     // Signed 32-bit digit
// #define NWORDS_FIELD    4             
// #define NWORDS_ORDER    8 

#define RADIX           64
typedef uint64_t        digit_t;      // Unsigned 64-bit digit
typedef int64_t         sdigit_t;     // Signed 64-bit digit
#define NWORDS_FIELD    2             // Number of words of a field element
#define NWORDS_ORDER    4             // Number of words of an element in Z_r 



// Definition of complementary cryptographic functions
#define RandomBytesFunction     random_bytes    
#define CryptoHashFunction      crypto_sha512        // Use SHA-512 by default


// Basic parameters for variable-base scalar multiplication (without using endomorphisms)
#define W_VARBASE             5 
#define NBITS_ORDER_PLUS_ONE  246+1 


// Basic parameters for fixed-base scalar multiplication
#define W_FIXEDBASE       5                            // Memory requirement: 7.5KB (storage for 80 points).
#define V_FIXEDBASE       5                  


// Basic parameters for double scalar multiplication
#define WP_DOUBLEBASE     8                            // Memory requirement: 24KB (storage for 256 points).
#define WQ_DOUBLEBASE     4  
   

// FourQ's basic element definitions and point representations
typedef digit_t felm_t[NWORDS_FIELD];                  // Datatype for representing 128-bit field elements
typedef felm_t f2elm_t[2];                             // Datatype for representing quadratic extension field elements
        
typedef struct { f2elm_t x; f2elm_t y; } point_affine; // Point representation in affine coordinates.
typedef point_affine point_t[1]; 


typedef enum {
    ECCRYPTO_ERROR,                            // 0x00
    ECCRYPTO_SUCCESS,                          // 0x01
    ECCRYPTO_ERROR_DURING_TEST,                // 0x02
    ECCRYPTO_ERROR_UNKNOWN,                    // 0x03
    ECCRYPTO_ERROR_NOT_IMPLEMENTED,            // 0x04
    ECCRYPTO_ERROR_NO_MEMORY,                  // 0x05
    ECCRYPTO_ERROR_INVALID_PARAMETER,          // 0x06
    ECCRYPTO_ERROR_SHARED_KEY,                 // 0x07
    ECCRYPTO_ERROR_SIGNATURE_VERIFICATION,     // 0x08
    ECCRYPTO_ERROR_HASH_TO_CURVE,              // 0x09
    ECCRYPTO_ERROR_END_OF_LIST
} ECCRYPTO_STATUS;


typedef uint64_t uint128_t[2];

// Constants for hash to FourQ function

#if (RADIX == 32)
    static felm_t con1 = { 6651107, 0, 4290264256, 2147483647 };
    static felm_t con2 = { 1725590130, 1719979744, 2225079900, 707200452 };
    static felm_t b0 = { 3738038324, 2664081113, 587564626, 1252475115 };
    static felm_t b1 = { 17, 0, 4294967284, 2147483647 };
    static felm_t A0 = { 1289, 0, 4294966384, 2147483647 };
    static felm_t A1 = { 1007904792, 2866591091, 4136083791, 1668973403 };
#elif (RADIX == 64)
    static felm_t con1 = { 6651107ULL, 9223372036850072768ULL };
    static felm_t con2 = { 7387256751988042354ULL, 3037402815281497692ULL };
    static felm_t b0 = { 11442141257964318772ULL, 5379339658566403666ULL };
    static felm_t b1 = { 17ULL, 9223372036854775796ULL };
    static felm_t A0 = { 1289ULL, 9223372036854774896ULL };
    static felm_t A1 = { 12311914987857864728ULL, 7168186187914912079ULL };
#endif



// Basic parameters for variable-base scalar multiplication (without using endomorphisms)
#define NPOINTS_VARBASE       (1 << (W_VARBASE-2)) 
#define t_VARBASE             ((NBITS_ORDER_PLUS_ONE+W_VARBASE-2)/(W_VARBASE-1))


// Basic parameters for fixed-base scalar multiplication
#define E_FIXEDBASE       (NBITS_ORDER_PLUS_ONE + W_FIXEDBASE*V_FIXEDBASE - 1)/(W_FIXEDBASE*V_FIXEDBASE)
#define D_FIXEDBASE       E_FIXEDBASE*V_FIXEDBASE
#define L_FIXEDBASE       D_FIXEDBASE*W_FIXEDBASE  
#define NPOINTS_FIXEDBASE V_FIXEDBASE*(1 << (W_FIXEDBASE-1))  
#define VPOINTS_FIXEDBASE (1 << (W_FIXEDBASE-1)) 
#if (NBITS_ORDER_PLUS_ONE-L_FIXEDBASE == 0)  // This parameter selection is not supported  
    #error -- "Unsupported parameter selection for fixed-base scalar multiplication"
#endif 


// Basic parameters for double scalar multiplication
#define NPOINTS_DOUBLEMUL_WP   (1 << (WP_DOUBLEBASE-2)) 
#define NPOINTS_DOUBLEMUL_WQ   (1 << (WQ_DOUBLEBASE-2)) 
   
// FourQ's point representations        

typedef struct { f2elm_t x; f2elm_t y; f2elm_t z; f2elm_t ta; f2elm_t tb; } point_extproj;  // Point representation in extended coordinates.
typedef point_extproj point_extproj_t[1];                                                              
typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t z2; f2elm_t t2; } point_extproj_precomp;   // Point representation in extended coordinates (for precomputed points).
typedef point_extproj_precomp point_extproj_precomp_t[1];  
typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t t2; } point_precomp;                       // Point representation in extended affine coordinates (for precomputed points).
typedef point_precomp point_precomp_t[1];

#endif
