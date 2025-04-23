
// #include "aes.cuh"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "../../../misc/helper_timer.h"

/**
 * AES-128 key expansion
 * 
 * @param  user_key		Pointer to the user key
 * @param  rd_key		Pointer to the round key
 */
__host__ void h_AES128KeyExpansion(u8* user_key, u32* rd_key)
{

	u32 rk0 = GETU32(user_key);
	u32 rk1 = GETU32(user_key + 4);
	u32 rk2 = GETU32(user_key + 8);
	u32 rk3 = GETU32(user_key + 12);

	// First 4 round keys are the user key itself.
	rd_key[0] = rk0;
	rd_key[1] = rk1;
	rd_key[2] = rk2;
	rd_key[3] = rk3;

	// Generate the remaining round keys.
	for (u8 roundCount = 0; roundCount < AES128_NUM_RNDS; roundCount++) {
		u32 temp = rk3;
		// Key schedule core operation and XOR with RCON.
		rk0 ^= 
			AES_T4_3[(temp >> 16) & 0xff] ^
			(AES_T4_3[(temp >> 8) & 0xff] >> 8) ^
			(AES_T4_3[(temp) & 0xff] >>16) ^ 
			(AES_T4_3[(temp >> 24)] >> 24) ^
			AES_RCON32[roundCount];
		
		// Derive the next round keys using previous round keys.
		rk1 ^= rk0;
		rk2 ^= rk1;
		rk3 = rk2 ^ rk3;

		// Store partial generated round keys.
		rd_key[roundCount * 4 + 4] = rk0;
		rd_key[roundCount * 4 + 5] = rk1;
		rd_key[roundCount * 4 + 6] = rk2;
		rd_key[roundCount * 4 + 7] = rk3;
	}
}


__device__  __forceinline__ static u32 d_rshift(u32 x, u32 n) {
    return __byte_perm(x, x, n);
}


/**
 * AES-128 key expansion
 * 
 * @param  user_key		Pointer to the user key
 * @param  rd_key		Pointer to the round key
 */
__device__ __forceinline__ void d_AES128KeyExpansion(u8* __restrict__ user_key, u32* __restrict__ rd_key, u32* __restrict__ AES_T4_3, u32* __restrict__ AES_RCON32)
{
	u32 rk0, rk1, rk2, rk3;
	uint4 raw_key = *(reinterpret_cast<const uint4*>(user_key));
	rd_key[0] = rk0 = __byte_perm(raw_key.x, 0, 0x0123);
	rd_key[1] = rk1 = __byte_perm(raw_key.y, 0, 0x0123);
	rd_key[2] = rk2 = __byte_perm(raw_key.z, 0, 0x0123);
	rd_key[3] = rk3 = __byte_perm(raw_key.w, 0, 0x0123);

	// Generate the remaining round keys.
	// #pragma unroll
	for (u8 roundCount = 0; roundCount < AES128_NUM_RNDS; roundCount++) {
		u32 temp = rk3;
		// Key schedule core operation and XOR with RCON.
		rk0 ^= 
			 AES_T4_3[(temp >> 16) & 0xff] ^
			d_rshift(AES_T4_3[(temp >> 8) & 0xff], RSHIFT_1) ^
			d_rshift(AES_T4_3[(temp) & 0xff], RSHIFT_2) ^ 
			d_rshift(AES_T4_3[(temp >> 24)], RSHIFT_3) ^
			AES_RCON32[roundCount];
		
		// Derive the next round keys using previous round keys.
		rk1 ^= rk0;
		rk2 ^= rk1;
		rk3 = rk2 ^ rk3;

		// Store partial generated round keys.
		rd_key[roundCount * 4 + 4] = rk0;
		rd_key[roundCount * 4 + 5] = rk1;
		rd_key[roundCount * 4 + 6] = rk2;
		rd_key[roundCount * 4 + 7] = rk3;
	}
}

__device__  __forceinline__ void d_AES128EncryptBlock(u8* __restrict__ in, u8* __restrict__ out, u32* __restrict__ aes_rd_key, u32* __restrict__ aes_t0, u8* __restrict__ aes_sbox) {
	u32 temp0, temp1, temp2, temp3;

	// u32 state0 = GETU32(in) ^ aes_rd_key[0];
	// u32 state1 = GETU32(in + 4) ^ aes_rd_key[1];
	// u32 state2 = GETU32(in + 8) ^ aes_rd_key[2];
	// u32 state3 = GETU32(in + 12) ^ aes_rd_key[3];
	const uint4* in_vec = reinterpret_cast<const uint4*>(in);
    u32 state0 = __byte_perm(in_vec->x, 0, 0x0123) ^ aes_rd_key[0];
    u32 state1 = __byte_perm(in_vec->y, 0, 0x0123) ^ aes_rd_key[1];
    u32 state2 = __byte_perm(in_vec->z, 0, 0x0123) ^ aes_rd_key[2];
    u32 state3 = __byte_perm(in_vec->w, 0, 0x0123) ^ aes_rd_key[3];

	// Main rounds.
#ifdef AES_OPTIMIZED
	// #pragma unroll
#endif
	for (u8 roundCount = 0; roundCount < AES128_ROUNDSMI; roundCount++) {
		u32 rk_offset = roundCount * 4 + 4;

		// Each temp variable represents a transformed word in the state.
		temp0 = 
			aes_t0[EXTRACT_BYTE(state0,3)] ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state1,2)], RSHIFT_1) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state2,1)], RSHIFT_2) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state3,0)], RSHIFT_3) 
			^ aes_rd_key[rk_offset];
		temp1 = 
			aes_t0[EXTRACT_BYTE(state1,3)] ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state2,2)], RSHIFT_1) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state3,1)], RSHIFT_2) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state0,0)], RSHIFT_3) ^ 
			aes_rd_key[rk_offset + 1];
		temp2 = 
			aes_t0[EXTRACT_BYTE(state2,3)] ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state3,2)], RSHIFT_1) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state0,1)], RSHIFT_2) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state1,0)], RSHIFT_3) ^ 
			aes_rd_key[rk_offset + 2];
		temp3 = 
			aes_t0[EXTRACT_BYTE(state3,3)] ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state0,2)], RSHIFT_1) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state1,1)], RSHIFT_2) ^ 
			d_rshift(aes_t0[EXTRACT_BYTE(state2,0)], RSHIFT_3) ^ 
			aes_rd_key[rk_offset + 3];
		// Update state with the results of this round.
		state0 = temp0;
		state1 = temp1;
		state2 = temp2;
		state3 = temp3;
	}

	state0 =
		((u32)aes_sbox[(temp0 >> 24) & 0xff] << 24) |
		((u32)aes_sbox[(temp1 >> 16) & 0xff] << 16) |
		((u32)aes_sbox[(temp2 >>  8) & 0xff] <<  8) |
		((u32)aes_sbox[(temp3      ) & 0xff]);
	state0 ^= aes_rd_key[40];

	state1 =
		((u32)aes_sbox[(temp1 >> 24) & 0xff] << 24) |
		((u32)aes_sbox[(temp2 >> 16) & 0xff] << 16) |
		((u32)aes_sbox[(temp3 >>  8) & 0xff] <<  8) |
		((u32)aes_sbox[(temp0      ) & 0xff]);
	state1 ^= aes_rd_key[41];

	state2 =
		((u32)aes_sbox[(temp2 >> 24) & 0xff] << 24) |
		((u32)aes_sbox[(temp3 >> 16) & 0xff] << 16) |
		((u32)aes_sbox[(temp0 >>  8) & 0xff] <<  8) |
		((u32)aes_sbox[(temp1      ) & 0xff]);
	state2 ^= aes_rd_key[42];

	state3 =
		((u32)aes_sbox[(temp3 >> 24) & 0xff] << 24) |
		((u32)aes_sbox[(temp0 >> 16) & 0xff] << 16) |
		((u32)aes_sbox[(temp1 >>  8) & 0xff] <<  8) |
		((u32)aes_sbox[(temp2      ) & 0xff]);
	state3 ^= aes_rd_key[43];

	// Store the final state in the output buffer.
	PUTU32(out, state0);
	PUTU32(out + 4, state1);
	PUTU32(out + 8, state2);
	PUTU32(out + 12, state3);
}

__global__ void g_AES128Encrypt(u8 *in, u8 *out, u8 *d_aes_key, u32 *d_AES_T0, u32 *d_AES_T4_3, u8 *d_AES_SBOX, u32 *AES_RCON32) {
	u8 in_curr[16];
	u8 aes_key[16];

	// Shared memory for AES tables and round keys.
	__shared__ u32 t0[AES128_TABLE_SIZE];
	__shared__ u32 t4_3[AES128_TABLE_SIZE];
	__shared__ u8  sbox[AES128_TABLE_SIZE];
	__shared__ u32 aes_rcon_32_sm[AES128_RCN_SIZE];

	// Load shared memory with T-boxes, S-box, and round keys.
	if (threadIdx.x < AES128_TABLE_SIZE) {
		t0[threadIdx.x] = d_AES_T0[threadIdx.x];
		t4_3[threadIdx.x] = d_AES_T4_3[threadIdx.x];
		sbox[threadIdx.x] = d_AES_SBOX[threadIdx.x];
		aes_rcon_32_sm[threadIdx.x % AES128_RCN_SIZE] = AES_RCON32[threadIdx.x % AES128_RCN_SIZE];
	}

	// Copy input block to local memory.
	memcpy(in_curr, in, 16);
	memcpy(aes_key, d_aes_key, 16);

	// Wait for all threads to finish copying input block to local memory.
	__syncthreads();

	if (threadIdx.x == 0 && blockIdx.x == 0) {
		// Perform key expansion in shared memory.
		d_print_hex_m("sbox: ", sbox, 16);
	}

	u32 round_key[44];
	d_AES128KeyExpansion(aes_key, round_key, t4_3, aes_rcon_32_sm);
	
	// Encrypt the block.
	d_AES128EncryptBlock(in_curr, out, round_key, t0, sbox);
}

int AES128SelfTest(u32 blockDim, u32 threadDim) {
	u8 aes_key[16], *d_aes_key, in[16], cpu_out[32], *gpu_out, ivec[16];
	u32 blocks = blockDim, threads = threadDim;
	u32 *rd_key, *d_AES_T0, *d_AES_T4_3, *d_AES_RCON32;
	u8  *d_AES_SBOX;
	u32 bench_loops = 1;
	int outlen;
	EVP_CIPHER_CTX *ssl_aes_ctx;

	StopWatchInterface *timer = NULL;
	sdkCreateTimer(&timer);

	// CPU encryption setup and execution
	memset(ivec, 0, 16);
	if (!RAND_bytes(aes_key, 16) || !RAND_bytes(in, 16)) 		{ return 1; }
	// memset(in, 0, 16);
	memset(aes_key, 0, 16);

	ssl_aes_ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit(ssl_aes_ctx, EVP_aes_128_ecb(), aes_key, NULL, 1);
	EVP_EncryptUpdate(ssl_aes_ctx, cpu_out, &outlen, in, 16);
	EVP_EncryptFinal(ssl_aes_ctx, cpu_out+outlen, &outlen);

	// GPU encryption setup and execution
	CHECK(cudaMallocManaged(&gpu_out, 16 * sizeof(u8)));
	CHECK(cudaMallocManaged(&rd_key, AES128_RD_KEY_SIZE * sizeof(u32)));
	CHECK(cudaMallocManaged(&d_AES_T0, AES128_TABLE_SIZE * sizeof(u32)));
	CHECK(cudaMallocManaged(&d_AES_SBOX, AES128_TABLE_SIZE * sizeof(u8)));
	CHECK(cudaMallocManaged(&d_AES_T4_3, AES128_TABLE_SIZE * sizeof(u32)));
	CHECK(cudaMallocManaged(&d_AES_RCON32, AES128_RCN_SIZE * sizeof(u32)));
	CHECK(cudaMallocManaged(&d_aes_key, 16 * sizeof(u8)));
	CHECK(cudaMemset(gpu_out, 0, 4 * sizeof(u32)));
	memcpy(d_AES_T0, AES_T0, AES128_TABLE_SIZE * sizeof(u32));
	memcpy(d_AES_T4_3, AES_T4_3, AES128_TABLE_SIZE * sizeof(u32));
	memcpy(d_AES_SBOX, AES_SBOX, AES128_TABLE_SIZE * sizeof(u8));
	memcpy(d_AES_RCON32, AES_RCON32, AES128_RCN_SIZE * sizeof(u32));

	// Convert input and key to u32 and perform key expansion
	// h_AES128KeyExpansion(aes_key, rd_key);
	memcpy(d_aes_key, aes_key, 16);
	// memset(in, 0, 16);

	sdkResetTimer(&timer);
	for (u32 i = 0; i < bench_loops; i++) {
		sdkStartTimer(&timer);
		// Launch GPU encryption kernel
		g_AES128Encrypt<<<blocks,threads>>>(in, gpu_out, d_aes_key, d_AES_T0, d_AES_T4_3, d_AES_SBOX, d_AES_RCON32);
		CHECK(cudaDeviceSynchronize());
		sdkStopTimer(&timer);
	}
	printf("\n\nAES128Encrypt<<<%d,%d>>> average time: %3f ms\n", blocks, threads, sdkGetAverageTimerValue(&timer));
	double aes_time = sdkGetAverageTimerValue(&timer);

	
	printf("in: ");
	for (int i = 0; i < 16; i++) {
		printf("%02x", in[i]);
	}
	printf("\n");

	printf("cpu_out: ");
	for (int i = 0; i < 16; i++) {
		// printf("%08x", cpu_out[i]);
		for (int bit = 7; bit >= 0; --bit) {
			printf("%d", (cpu_out[i] >> bit) & 1);
		}
		printf(" ");
	}
	printf("\n");

	printf("gpu_out: ");
	for (int i = 0; i < 16; i++) {
		for (int bit = 7; bit >= 0; --bit) {
			printf("%d", (gpu_out[i] >> bit) & 1);
		}
		printf(" ");
	}
	printf("\n");

	// Save into CSV
	FILE *fp = fopen("aes.csv", "a");
	fprintf(fp, "%d, %d, %.3f, %.3f, %d\n", blocks, threads, aes_time, aes_time, memcmp(cpu_out, gpu_out, 16));
	fclose(fp);

	// Compare CPU and GPU encryption results
	if (0 != memcmp(cpu_out, gpu_out, 16)) {
		fprintf(stderr, "AES-cuda output do not match AES-openssl\n");
		goto error;
	}

	goto cleanup;

error:
	CHECK(cudaFree(rd_key));
	CHECK(cudaFree(gpu_out));
	return 1;

cleanup:
	CHECK(cudaFree(rd_key));
	CHECK(cudaFree(gpu_out));
	return 0;
}
