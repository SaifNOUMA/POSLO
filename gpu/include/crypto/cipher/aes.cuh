
#include "aes_param.cuh"

/**
 * AES-128 key expansion
 * 
 * @param  user_key		Pointer to the user key
 * @param  rd_key		Pointer to the round key
 */
__device__ void d_AES128KeyExpansion(u8* __restrict__ user_key, u32* __restrict__ rd_key, u32* __restrict__ AES_T4_3, u32* __restrict__ AES_RCON32) ;

/**
 * AES-128 key expansion
 * 
 * @param  user_key		Pointer to the user key
 * @param  rd_key		Pointer to the round key
 */
__device__ __forceinline__ void d_AES128KeyExpansion(u8* user_key, u32* rd_key, u32 *AES_T4_0, u32 *AES_RCON32);
// __device__ void AES128KeyExpansion(u8* user_key, u32* rd_key);

/** 
 * Compute the AES-128 round key
 * 
 *  @param  x	Integer to be rotated
 *  @param  n   Number of bits to rotate
 *  @return nothing
 */
__device__ __forceinline__ static u32 d_rshift(u32 x, u32 n);

/** 
 * Encrypt a single block (i.e., 128-bit) of data
 * 
 * \param  in			Pointer to the input array to be encrypted
 * \param  out			Pointer to the encrypted output array
 * @param  rd_key		Pointer to the round key
 * @param  aes_t0		Pointer to the AES T0 table
 * @param  aes_sbox		Pointer to the AES SBOX table
 * @return nothing
 */
__device__  __forceinline__ void d_AES128EncryptBlock(u8* __restrict__ in, u8* __restrict__ out, u32* __restrict__ aes_rd_key, u32* __restrict__ aes_t0, u8* __restrict__ aes_sbox);

/** 
 * Encrypt a single block (i.e., 128-bit) of data
 * 
 * @param  in			Pointer to the input array to be encrypted
 * @param  out			Pointer to the encrypted output array
 * @param  rd_key		Pointer to the round key
 * @param  d_AES_T0		Pointer to the AES T0 table
 * @param  d_AES_SBOX	Pointer to the AES SBOX table
 * @return nothing
 */
// __global__ void g_AES128Encrypt(u8 *in, u8 *out, u32 *rd_key, u32 *d_AES_T0, u8 *d_AES_SBOX);
__global__ void g_AES128Encrypt(u8 *in, u8 *out, u8 *d_aes_key, u32 *d_AES_T0, u8 *d_AES_T4_3, u8 *d_AES_SBOX, u32 *AES_RCON32);

/**
 * AES-128 self test and comparison with OpenSSL implementation
 * 
 * @param blockDim		Number of blocks
 * @param threadDim		Number of threads
 * @return 0 on success and 1 otherwise
 */
int AES128SelfTest(u32 blockDim, u32 threadDim);

#include "aes.cu"