
__device__ __forceinline__ ECCRYPTO_STATUS compute_seed(u8* __restrict__ in, u32 inlen, u8 *out, u32 counter, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32)
{
#if defined (SeedMethod_AES128)
    u32 rdkey[44];
    d_AES128KeyExpansion(aes_key, rdkey, aes_t4_3, aes_rcon32);
	d_AES128EncryptBlock(in, out, rdkey, aes_t0, aes_sbox);
#elif defined (SeedMethod_SHA256)
	d_sha256_i(in, inlen, out, counter);
#endif
    return ECCRYPTO_SUCCESS;
}

__device__ __forceinline__ ECCRYPTO_STATUS compute_hash(u8* __restrict__ in, u32 inlen, u8* __restrict__ seed, u8 *out, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32)
{
#if defined(HashMethod_SHA256)
    // u8 prior_hash[64];
    // memcpy(prior_hash, in, inlen);
    memcpy(in + inlen, seed, SEED_SIZE);
    d_SHA256(in, inlen+SEED_SIZE, out);
    d_modulo_order((digit_t*) out, (digit_t*) out);
#elif defined(HashMethod_AES128)
    u32 rd_key[44];
    u8 intemp[16] = {0};
    memcpy(intemp, in, inlen);
    #pragma unroll
    for (int i = 0; i < (inlen+16)/16; i++) {
        d_AES128KeyExpansion(aes_key, rd_key, aes_t4_3, aes_rcon32);
        d_AES128EncryptBlock(intemp, out, rd_key, aes_t0, aes_sbox);
    }
#elif defined(HashMethod_ARITHM)
    if (inlen >= 30) {
        d_modulo_order((digit_t*) in, (digit_t*) out);
    } else {
        memset(out, 0, ORDER_SIZE);
        memcpy(out, in, inlen);
    }
#if defined(SeedMethod_SHA256)
digit_t temp_seed[NUM_DIGITS];
    memcpy(temp_seed, seed, ORDER_SIZE);
    d_modulo_order(temp_seed, temp_seed);
    d_add_mod_order((digit_t*) out, temp_seed, (digit_t*) out);
        d_modulo_order((digit_t*) seed, (digit_t*) seed);
#endif
    d_add_mod_order((digit_t*) out, (digit_t*) seed, (digit_t*) out);
#endif
    return ECCRYPTO_SUCCESS;
}

__device__ __forceinline__ ECCRYPTO_STATUS d_OSLOT_SC(u8* __restrict__ src_ptr, u32 src_height, u32 src_index, u8* __restrict__ dst_ptr, u32 dst_height, u32 dst_index, u8* __restrict__ aes_key, u32* __restrict__ aes_t0, u32* __restrict__ aes_t4_3, u8* __restrict__ aes_sbox, u32* __restrict__ aes_rcon32)
{
    u8 curr_ptr[SEED_SIZE];
	u32 local_height, local_index, local_leaves;
    
    local_height = dst_height - src_height;
    local_leaves = 1 << local_height;
    local_index  = dst_index - (src_index - 1) * local_leaves;

#if SEED_SIZE == 16
        *((uint4*)curr_ptr) = *((uint4*)src_ptr);
#elif SEED_SIZE == 32
        *((uint4*)curr_ptr) = *((uint4*)src_ptr);
        *((uint4*)(curr_ptr+16)) = *((uint4*)(src_ptr+16));
#endif
 
    for (u32 depth = 1 ; depth <= local_height ; depth++) {
        // local_leaves = local_leaves / 2;
        local_leaves >>= 1;
        bool isLeftChild = (local_index < local_leaves);

        compute_seed(curr_ptr, SEED_SIZE, curr_ptr, isLeftChild, aes_key, aes_t0, aes_t4_3, aes_sbox, aes_rcon32);
    }
    
    // memcpy(dst_ptr, curr_ptr, SEED_SIZE);
#if SEED_SIZE == 16
        *((uint4*)dst_ptr) = *((uint4*)curr_ptr);
#elif SEED_SIZE == 32
        *((uint4*)dst_ptr) = *((uint4*)curr_ptr);
        *((uint4*)(dst_ptr+16)) = *((uint4*)(curr_ptr+16));
#endif

    return ECCRYPTO_SUCCESS;
}
