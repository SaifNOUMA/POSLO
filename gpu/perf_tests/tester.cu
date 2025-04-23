
#ifndef OSLO_TEST_CUH
#define OSLO_TEST_CUH

#include "oslo.cuh"
#include "fourq/fp_params.h"
#include "crypto/cipher/aes_param.cuh"
#include "../misc/helper_timer.h"
#include "../misc/helper_string.h"
#include "util.cuh"

/**
 * Run the GPU-based batch verification algorithm
 * 
 * @param  pk				OSLO public key
 * @param  data				Pointer to the data
 * @param  inlen			Length of the input data
 * @param  valid			Validity of the batch verification
 * @param  gpu_time			Total time taken for the batch verification
 * @param  gpu_iterations	Number of iterations to run the batch verification
 * @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS OSLO_batch_ver_bench(OSLO_PK pk, u8 *data, u32 inlen, OSLOT_STATE oslot_st, u32 gpu_iterations);


ECCRYPTO_STATUS runGpuVerification(const OSLO_PK& pk, u8* data, u32 inlen, bool& valid, double& gpu_time, u32 gpu_iterations) {
    StopWatchInterface* timer = nullptr;
	u32 datalen, data_elements;
	data_elements = (1 << pk.oslot_st.n1) * pk.oslot_st.n2;
	datalen = data_elements * inlen;
    sdkCreateTimer(&timer);
    sdkResetTimer(&timer);

    // GPU memory allocations and initializations
	CudaManagedPtr<u8> d_data(datalen), d_oslot_root(SEED_SIZE), d_ecc_e_reduced((1 << pk.oslot_st.n1) * ORDER_SIZE);
	memcpy(d_oslot_root.get(), pk.oslot_st.root, SEED_SIZE * sizeof(u8));
	memcpy(d_data.get(), data, datalen * sizeof(u8));

	CudaManagedPtr<u8>  aes_sbox(AES128_TABLE_SIZE), aes_key(16);
	CudaManagedPtr<u32> aes_t0(AES128_TABLE_SIZE), aes_t4_3(AES128_TABLE_SIZE), aes_rd_key(AES128_RD_KEY_SIZE), aes_rcon32(AES128_TABLE_SIZE);
#if defined(SeedMethod_AES128)
        memcpy(aes_t0.get(), AES_T0, AES128_TABLE_SIZE * sizeof(u32));
		memcpy(aes_t4_3.get(), AES_T4_3, AES128_TABLE_SIZE * sizeof(u32));
        memcpy(aes_sbox.get(), AES_SBOX, AES128_TABLE_SIZE * sizeof(u8));
		memcpy(aes_rcon32.get(), AES_RCON32, AES128_RCN_SIZE * sizeof(u32));
		memcpy(aes_key.get(), pk.oslot_st.aes_key, 16);
#endif

    for (u32 iter = 0; iter < gpu_iterations; iter++) {
        sdkStartTimer(&timer);
		OSLO_BatchVer(pk, d_data.get(), inlen, aes_key.get(), aes_t0.get(), aes_t4_3.get(), aes_sbox.get(), aes_rcon32.get(), &valid);
        // cudaDeviceSynchronize();
        sdkStopTimer(&timer);
    }
    gpu_time = sdkGetAverageTimerValue(&timer);
    // Cleanup GPU resources
  	sdkDeleteTimer(&timer);

    return valid == 0 ? ECCRYPTO_SUCCESS : ECCRYPTO_ERROR;
}

ECCRYPTO_STATUS OSLO_batch_ver_bench(OSLO_PK pk, u8* data, u32 inlen, OSLOT_STATE oslot_st, u32 gpu_iterations) {
    bool gpu_valid = true;
    double gpu_time = 0.0;

    // Initialize pk.oslot_st.root from pk.oslot_ds
    Value sct_root = pk.oslot_ds.begin()->second;
    memcpy(pk.oslot_st.root, sct_root.parent_node, SEED_SIZE);

    // GPU Verification
    if (runGpuVerification(pk, data, inlen, gpu_valid, gpu_time, gpu_iterations) != ECCRYPTO_SUCCESS) {
        fprintf(stderr, "ERROR: OSLO GPU-based batch verification failed!\n");
        // return ECCRYPTO_ERROR;
    }
	printf("[INFO] GPU: avg batch ver time =  %.3f ms\n", gpu_time);
	
	// Write the results to a CSV file
	writeResults("out/gpu_bench.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
// 	writeResults("out/oslo_aes128_sha256.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
// 	writeResults("out/oslo_aes128_arithm.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
// 	writeResults("out/oslo_aes128_aes128.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
// 	writeResults("out/oslo_sha256_sha256.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
// 	writeResults("out/oslo_sha256_arithm.csv", inlen, oslot_st, gpu_time, gpu_valid);
// #endif

#if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
	writeResults("out/oslo_aes128_sha256.csv", inlen, oslot_st, gpu_time, gpu_valid);
#elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
	writeResults("out/oslo_aes128_arithm.csv", inlen, oslot_st, gpu_time, gpu_valid);
#elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
	writeResults("out/oslo_aes128_aes128.csv", inlen, oslot_st, gpu_time, gpu_valid);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
	writeResults("out/oslo_sha256_sha256.csv", inlen, oslot_st, gpu_time, gpu_valid);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
	writeResults("out/oslo_sha256_arithm.csv", inlen, oslot_st, gpu_time, gpu_valid);
#endif

	return ECCRYPTO_SUCCESS;
}

#endif // OSLO_TEST_CUH