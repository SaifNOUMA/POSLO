
#include "../misc/helper_timer.h"
#include "../misc/helper_string.h"
#include "oslo_test.hpp"

#define PRINT_TIME

// #define HashMethod_SHA256
// #define SeedMethod_SHA256

ECCRYPTO_STATUS SOCOSLO_sgn_test(u8 *data, u32 inlen, OSLOT_STATE oslot_st) {
	ECCRYPTO_STATUS status;
	OSLO_SK sk;
	OSLO_PK	pk;
	u32	total_epochs = 1 << oslot_st.n1;
	u32 data_elements = total_epochs * oslot_st.n2;

	OSLOT_DS ds[1 << oslot_st.n1];
	OSLO_SIG sig[1 << oslot_st.n1];
	bool valid;

#if defined(PRINT_TIME)
	StopWatchInterface *timer, *sgn_timer, *ver_timer, *distill_timer;
	double avg_time;
	sdkCreateTimer(&timer);
	sdkCreateTimer(&sgn_timer);
	sdkCreateTimer(&ver_timer);
	sdkCreateTimer(&distill_timer);
	sdkResetTimer(&timer);
	sdkResetTimer(&sgn_timer);
	sdkResetTimer(&ver_timer);
	sdkResetTimer(&distill_timer);
#endif

	// key generation
#if defined(PRINT_TIME)
	sdkStartTimer(&timer);
#endif
	if (ECCRYPTO_SUCCESS != (status = SOCOSLO_Kg(&sk, &pk, oslot_st))) {
		fprintf(stderr, "Key generation failed!\n");
		goto error;
	}
	
#if defined(PRINT_TIME)
	sdkStopTimer(&timer);
	printf("[INFO] CPU: key gen   (total = %.3f ms)\n", timer->getTime());
#endif

	// signature generation
	for (u32 epoch = 0 ; epoch < total_epochs ; epoch++) {
#if defined(PRINT_TIME)
		sdkStartTimer(&sgn_timer);
#endif
		for (u32 iter = 0 ; iter < oslot_st.n2 ; iter++) {
			u32 num_msg = epoch * oslot_st.n2 + iter;

			if (ECCRYPTO_SUCCESS != (status = SOCOSLO_Sign(&sk, pk, data + num_msg * inlen, inlen, &sig[epoch], &ds[epoch]))) {
				fprintf(stderr, "Signature generation failed during the epoch=%d at the iteration %d!\n", epoch, iter);
				goto error;
			}
		}
#if defined(PRINT_TIME)
		sdkStopTimer(&sgn_timer);
#endif
	}
#if defined(PRINT_TIME)
	printf("[INFO] CPU: sig gen   (total = %.3f ms) (average per batch [%u] = %.3f ms) (#data=%u)\n", sgn_timer->getTime(), oslot_st.n2, sgn_timer->getAverageTime(), data_elements);
#endif

	for (u32 epoch = 0 ; epoch < total_epochs ; epoch++) {
		valid = 1;
		u32 num_msg = epoch * oslot_st.n2;
		
		// signature verification
#if defined(PRINT_TIME)
		sdkStartTimer(&ver_timer);
#endif
		if (ECCRYPTO_SUCCESS != (status = SOCOSLO_Ver(&pk, data + num_msg * inlen, inlen, sig[epoch], ds[epoch], &valid)) || valid != 0) {
			fprintf(stderr, "Signature verification failed during the epoch=%d!\n", epoch);
			goto error;
		}
#if defined(PRINT_TIME)
		sdkStopTimer(&ver_timer);
#endif

		// signature distillation
#if defined(PRINT_TIME)
		sdkStartTimer(&distill_timer);
#endif
		if (ECCRYPTO_SUCCESS != (status = SOCOSLO_Distill(&pk, sig[epoch], valid))) {
			fprintf(stderr, "Signature distillation failed during the epoch=%d!\n", epoch);
			goto error;
		}

#if defined(PRINT_TIME)
		sdkStopTimer(&distill_timer);
#endif
	}

#if defined(PRINT_TIME)
	printf("[INFO] CPU: sig ver   (total = %.3f ms) (average per batch [%u] = %.3f ms) (#data=%u)\n", ver_timer->getTime(), oslot_st.n2, sgn_timer->getAverageTime(), data_elements);
	printf("[INFO] CPU: sig dstil (total = %.3f ms) (#data=%u)\n", distill_timer->getTime(), oslot_st.n2);
#endif

	// Batch verification
#if defined(PRINT_TIME)
	sdkResetTimer(&timer);
	sdkStartTimer(&timer);
#endif
	valid = 1;
	if (ECCRYPTO_SUCCESS != (status = SOCOSLO_BatchVer(pk, data, inlen, &valid))) {
		fprintf(stderr, "Batch verification failed (#failed items=%ld)!\n", pk.failed_indices.size());
		goto error;
	}
#if defined(PRINT_TIME)
	sdkStopTimer(&timer);
	printf("[INFO] CPU: batch ver (total = %.3f ms) (#data=%u)\n", timer->getTime(), data_elements);
	save_timing_to_csv(inlen, oslot_st, valid, sgn_timer->getTime(), ver_timer->getTime(), distill_timer->getTime(), timer->getTime());
#endif


	// save public key and associated data
	char crypto_data_path[256];
#if defined(SeedMethod_AES128) & defined(HashMethod_SHA256)
		sprintf(crypto_data_path, "../data/crypto/seed_method_aes128/hash_method_sha256/inlen_%u/n1_%u", inlen, oslot_st.n1);
#elif defined(SeedMethod_SHA256) & defined(HashMethod_SHA256)
		sprintf(crypto_data_path, "../data/crypto/seed_method_sha256/hash_method_sha256/inlen_%u/n1_%u", inlen, oslot_st.n1);
#elif defined(SeedMethod_AES128) & defined(HashMethod_ARITHM)
		sprintf(crypto_data_path, "../data/crypto/seed_method_aes128/hash_method_arithm/inlen_%u/n1_%u", inlen, oslot_st.n1);
#elif defined(SeedMethod_AES128) & defined(HashMethod_AES128)
		sprintf(crypto_data_path, "../data/crypto/seed_method_aes128/hash_method_aes128/inlen_%u/n1_%u", inlen, oslot_st.n1);
#elif defined(SeedMethod_SHA256) & defined(HashMethod_ARITHM)
		sprintf(crypto_data_path, "../data/crypto/seed_method_sha256/hash_method_arithm/inlen_%u/n1_%u", inlen, oslot_st.n1);
#endif
	save_pk(crypto_data_path, pk);

	goto cleanup;

error:
	pk.free_ecc_comm();
#if defined(PRINT_TIME)
	sdkDeleteTimer(&timer);
	sdkDeleteTimer(&sgn_timer);
	sdkDeleteTimer(&ver_timer);
	sdkDeleteTimer(&distill_timer);
#endif
	return ECCRYPTO_ERROR;

cleanup:
	pk.free_ecc_comm();
#if defined(PRINT_TIME)
	sdkDeleteTimer(&timer);
	sdkDeleteTimer(&sgn_timer);
	sdkDeleteTimer(&ver_timer);
	sdkDeleteTimer(&distill_timer);
#endif
	return ECCRYPTO_SUCCESS;
}
