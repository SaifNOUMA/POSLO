
#ifndef SHA256_H
#define SHA256_H

#include "types.cuh"

// #define USING_UNROLL
#define USING_PTX
#define USING_INTEGER
#define SHA_LBLOCK 16
#define SHA256_DIGEST_LENGTH 32
#define HASH_CBLOCK (SHA_LBLOCK * 4)

typedef struct self_SHA256state_st {
	u32 h[8];
	u32 Nl, Nh;
	u32 data[SHA_LBLOCK];
	u32 num, md_len;
} self_SHA256_CTX;

/** 
 * Initialize the SHA256 context on the device
 * 
 *  \param  ctx     Pointer to the context to initialize
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__device__ __forceinline__ void d_SHA256(const u8 *d, size_t n, u8 *md);

/** 
 * Update the SHA256 context on the device
 * 
 *  \param  ctx     Pointer to the context to update
 *  \param  data    Pointer to the data to hash
 *  \param  len     Length of the data
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__device__ __forceinline__ void d_sha256_i(const u8* in, u32 inlen, u8* hash, u32 counter);

/** 
 * Finalize the SHA256 context on the device
 * 
 *  \param  ctx     Pointer to the context to finalize
 *  \param  md      Pointer to the output hash
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__global__ void global_SHA256(const u8 *d, size_t n, u8 *md);

/** 
 * Compute the SHA256 hash of the given message
 * 
 *  \param  msg     Pointer to the message to hash
 *  \param  md      Pointer to the output hash
 *  \param  si      Length of the message
 *  \param  n       Number of iterations
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__global__ void global_parallel_SHA256(const u8 *msg, u8 *md,
				       size_t si, size_t n);

#include "sha256.cu"

#endif // SHA256_H