
#include <nvToolsExt.h>
#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>
namespace cg = cooperative_groups;

#include "util.cuh"
#include "oslo.cuh"
#include "oslot.cuh"
#include "fourq/fp.h"
#include "arith/fourq/fp.cuh"
#define NUM_DIGITS (ORDER_SIZE / sizeof(digit_t))
#define BLOCK_SIZE 256
#define PAD 8

__global__ void OSLO_Compute_ecc_e_agg(u8* __restrict__ in, u32 inlen, u8* __restrict__ ecc_e_agg, u8* __restrict__ oslot_root, OSLOT_STATE oslot_st, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32)
{
	cg::thread_block cta = cg::this_thread_block();
	u32 tid = threadIdx.x;
    u32 offset = 0;
    u8 aes_key_local[AES128_USER_KEY_SIZE];

    // Local variables for node, current ecc_e, and prior hash.
	u8 	node_ptr[ORDER_SIZE] = { 0 }, ecc_e_curr[ORDER_SIZE] = { 0 }, prior_hash[64] = { 0 };

    u8 oslot_node[SEED_SIZE];
    __shared__ __align__(16) u8 e_sm[BLOCK_SIZE][ORDER_SIZE+PAD];
    __shared__ __align__(16) u8 oslot_root_sm[SEED_SIZE];

    // Copy the input data into shared memory.
	// memcpy(prior_hash, in + (blockIdx.x*blockDim.x+tid)*inlen, inlen);
    offset = (blockIdx.x * blockDim.x + tid) * inlen;
    if (inlen == 8)   *(uint2*)prior_hash = *(const uint2*)(&in[offset]);
    if (inlen == 16)  *(uint4*)prior_hash = *(const uint4*)(&in[offset]);
    if (inlen == 32) {
        ((uint4*)prior_hash)[0] = __ldg((const uint4*)(in+offset));
        ((uint4*)prior_hash)[1] = __ldg((const uint4*)(in+offset+16));
    }

    memcpy(aes_key_local, aes_key, AES128_USER_KEY_SIZE);
#if defined(SeedMethod_AES128)
    __shared__ u8  aes_sbox_sm[AES128_TABLE_SIZE];
    __shared__ u32 aes_t0_sm[AES128_TABLE_SIZE];
    __shared__ u32 aes_t4_3_sm[AES128_TABLE_SIZE];
    __shared__ u32 aes_rcon32_sm[AES128_RCN_SIZE];

    // Load T-boxes, S-box, and round keys into shared memory.
    // if (tid < AES128_TABLE_SIZE) {
        aes_t0_sm[tid] = aes_t0[tid];
        aes_t4_3_sm[tid] = aes_t4_3[tid];
        aes_sbox_sm[tid] = aes_sbox[tid];
    // }
    if (tid < AES128_RCN_SIZE) {
        aes_rcon32_sm[tid] = __ldg(&aes_rcon32[tid]);
    }

    if (tid < (SEED_SIZE / sizeof(u32))) {
        // Copy 4 bytes at a time for root seed
        reinterpret_cast<u32*>(oslot_root_sm)[tid] = 
            reinterpret_cast<const u32*>(oslot_root)[tid];
    }
    cg::sync(cta);
#else
    u8* aes_sbox_sm = nullptr;
    u32* aes_t0_sm = nullptr;
    u32* aes_t4_3_sm = nullptr;
    u32* aes_rcon32_sm = nullptr;
#endif

    // Load the root of the OSLOT structure into shared memory.
    d_OSLOT_SC(oslot_root_sm, 0, 1, oslot_node, oslot_st.n1, blockIdx.x+1, aes_key_local, aes_t0_sm, aes_t4_3_sm, aes_sbox_sm, aes_rcon32_sm);

    // Encrypt or hash the input data.
    compute_seed(oslot_node, SEED_SIZE, node_ptr, tid+1, aes_key_local, aes_t0_sm, aes_t4_3_sm, aes_sbox_sm, aes_rcon32_sm);

    // Compute the current ecc_e value.
    compute_hash(prior_hash, inlen, node_ptr, ecc_e_curr, aes_key_local, aes_t0_sm, aes_t4_3_sm, aes_sbox_sm, aes_rcon32_sm);

    // Copy the current ecc_e value to the shared memory.
    memcpy(e_sm[tid], ecc_e_curr, ORDER_SIZE);

	cg::sync(cta);

    for (u32 iter = blockDim.x / 2; iter > 32; iter >>= 1) {
        if (tid < iter) {
            d_add_mod_order((digit_t*)e_sm[tid], (digit_t*)e_sm[tid + iter], (digit_t*)e_sm[tid]);
        }
        cg::sync(cta);
    }

    cg::thread_block_tile<32> cg32 = cg::tiled_partition<32>(cta);
    for (u32 iter = 32; iter > 0; iter >>= 1) {
        if (tid < iter) {
            d_add_mod_order((digit_t*)e_sm[tid], (digit_t*)e_sm[tid + iter], (digit_t*)e_sm[tid]);
        }
        cg::sync(cg32);
    }

    if (cta.thread_rank() == 0) {
        ((uint4*)(ecc_e_agg + blockIdx.x * ORDER_SIZE))[0] = ((const uint4*)e_sm)[0];
        ((uint4*)(ecc_e_agg + blockIdx.x * ORDER_SIZE))[1] = ((const uint4*)e_sm)[1];
    }
}


__host__ void OSLO_BatchVer(OSLO_PK pk, u8 *data, u32 inlen, u8 *aes_key, u32 *aes_t0, u32* aes_t4_3, u8 *aes_sbox, u32 *aes_rcon32, bool *valid)
{
    point_t ecc_comm;
    u32 threads = pk.oslot_st.n2;
    u32 blocks  = 1 << pk.oslot_st.n1;
    u8 ecc_e_agg[ORDER_SIZE];

    CudaManagedPtr<__align__(16) u8> ecc_e_reduced((1 << pk.oslot_st.n1) * ORDER_SIZE), oslot_root(SEED_SIZE);
    cudaMemset(ecc_e_reduced.get(), 0, (1 << pk.oslot_st.n1) * ORDER_SIZE);

    memcpy(oslot_root.get(), pk.oslot_st.root, SEED_SIZE);

    OSLO_Compute_ecc_e_agg<<<blocks, threads>>>(data, inlen, ecc_e_reduced.get(), oslot_root.get(), pk.oslot_st, aes_key, aes_t0, aes_t4_3, aes_sbox, aes_rcon32);

    cudaDeviceSynchronize();
    CHECK(cudaGetLastError());

    memset(ecc_e_agg, 0, ORDER_SIZE);
    for (u32 blockid = 0 ; blockid < blocks ; blockid++) {
        add_mod_order((digit_t*) ecc_e_agg, (digit_t*) (ecc_e_reduced.get() + blockid * ORDER_SIZE), (digit_t*) ecc_e_agg);
    }

    ecc_mul_double((digit_t*) pk.ecc_sig_agg, pk.ecc_pk, (digit_t*) ecc_e_agg, ecc_comm);
    *valid = memcmp(pk.ecc_comm_agg, ecc_comm, sizeof(point_t));
}
