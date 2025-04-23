
#ifndef OSLO_SGN_CUH
#define OSLO_SGN_CUH

#include "types.cuh"

/** Compute the aggregate ephemeral key "e"
 *  \param  u32_in   array of words (unsigned int)
 *  \param  inlen    len of the array u32_in
 *  \param  u8_out   array of unsigned char
 *  \return nothing
 */
// __global__ void OSLO_Compute_ecc_e_agg(u8 *in, u32 inlen, u8 *ecc_e_agg, u8 oslot_root[SEED_SIZE], OSLOT_STATE oslot_st, u32 *aes_rd_key, u32 *aes_t0, u8 *aes_sbox);
__global__ void OSLO_Compute_ecc_e_agg(u8* __restrict__ in, u32 inlen, u8* __restrict__ ecc_e_agg, u8* __restrict__ oslot_root, OSLOT_STATE oslot_st, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32);

/** SOCOSLO GPU-based parallel batch verification
 *  \param  pk   array of words (unsigned int)
 *  \param  data    len of the array u32_in
 *  \param  inlen    len of the array u32_in
 *  \return nothing
 */
// __host__ void OSLO_BatchVer(OSLO_PK pk, u8 *data, u32 inlen, u32 *aes_rd_key, u32 *aes_t0, u8 *aes_sbox, bool *valid);
__host__ void OSLO_BatchVer(OSLO_PK pk, u8 *data, u32 inlen, u8 *aes_key, u32 *aes_t0, u32 *aes_t4_3, u8 *aes_sbox, u32 *aes_rcon32, bool *valid);

#endif // OSLO_SGN_CUH