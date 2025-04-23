
#ifndef ECCRYPTO_OSLOT_H
#define ECCRYPTO_OSLOT_H

#include "types.cuh"
#include "fourq/fp_params.h"
#include "arith/fourq/fp.cuh"
#include "crypto/cipher/aes.cuh"
#include "crypto/hash/sha256.cuh"

/** 
 * Compute the seed value for the given input
 * 
 * @param  in         Pointer to the input to hash
 * @param  inlen      Length of the input
 * @param  out        Pointer to the output seed
 * @param  counter    Integer to be concatenate with the input message
 * @param  aes_rd_key Pointer to the AES round key
 * @param  aes_t0     Pointer to the AES T0 table
 * @param  aes_sbox   Pointer to the AES S-box
 * @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__device__ __forceinline__ ECCRYPTO_STATUS compute_seed(u8* __restrict__ in, u32 inlen, u8 *out, u32 counter, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32);

/** 
 * Compute the hash value for the given input
 * 
 * @param  in      Pointer to the input to hash
 * @param  inlen   Length of the input
 * @param  out     Pointer to the output hash
 * @param  counter Integer to be concatenate with the input message
 * @param  seed    Pointer to the seed value
 * @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__device__ __forceinline__ ECCRYPTO_STATUS compute_hash(u8* __restrict__ in, u32 inlen, u8* __restrict__ seed, u8 *out, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32);

/** Traverse the OSLO Tree-based structure from a source node to a destination node
 *  \param  src_ptr     pointer to the source node
 *  \param  src_height  Height of the source node in the OSLOT structure
 *  \param  src_index   Index of the source node in the OSLOT structure
 *  \param  dst_ptr     Pointer to the source node
 *  \param  dst_height  Height of the source node in the OSLOT structure
 *  \param  dst_index   Index of the source node in the OSLOT structure
 *  \param  dst_index   Index of the source node in the OSLOT structure
 *  \param  aes_rk      AES round key
 *  \param  aes_t0      AES T-box table
 *  \param  aes_sbox    AES S-box table
 * AES-128 Davies Mayes Construction 
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
__device__ __forceinline__ ECCRYPTO_STATUS d_OSLOT_SC(u8* __restrict__ src_ptr, u32 src_height, u32 src_index, u8* __restrict__ dst_ptr, u32 dst_height, u32 dst_index, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32);

#include "oslot.cu"

#endif // ECCRYPTO_OSLOT_H