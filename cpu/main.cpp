
#include "helper_timer.h"
#include "helper_string.h"
#include <memory>
#include "oslo/oslo_test.hpp"

void writeResults(char *filename, u32 inlen, OSLOT_STATE oslot_st, double cpu_time, bool cpu_valid);
ECCRYPTO_STATUS runCpuVerification(const OSLO_PK& pk, u8* data, u32 inlen, bool& valid, double& cpu_time, u32 cpu_iterations);

int main(int argc, char **argv)
{
	ECCRYPTO_STATUS status = ECCRYPTO_ERROR;
	const char path2log[50] = "../data/log.txt";
	std::string path2key = "../data/crypto/";
	u32 oslot_n1 = 10;
	u32 oslot_n2 = 256;
	u32 inlen = 32;
	u32 cpu_iterations = 1;
	OSLO_PK pk;

	// Parse command line arguments
    inlen 			= getCmdLineArgumentIntOrDefault(argc, argv, "inlen", inlen);
	oslot_n1 		= getCmdLineArgumentIntOrDefault(argc, argv, "n1", oslot_n1);
    oslot_n2 		= getCmdLineArgumentIntOrDefault(argc, argv, "n2", oslot_n2);
    cpu_iterations 	= getCmdLineArgumentIntOrDefault(argc, argv, "cpu_iterations", cpu_iterations);
	
	// Set up the OSLOT state
	OSLOT_STATE oslot_st{oslot_n1, oslot_n2};

	// Load data
	u32 data_elements = (1 << oslot_n1) * oslot_n2;
	u32 datalen = data_elements * inlen;
	std::unique_ptr<u8[]> data(new u8[datalen]);
    std::ifstream log_file(path2log, std::ifstream::binary);
    if (!log_file) {
        std::cerr << "ERROR: Data load failed!\n";
        return EXIT_FAILURE;
    }
	log_file.read(reinterpret_cast<char*>(data.get()), datalen);

	// // Test OSLO signature algorithms
	// status = SOCOSLO_sgn_test(data.get(), inlen, oslot_st);
	// if (status != ECCRYPTO_SUCCESS) {
	// 	std::cerr << "[INFO] OSLO signature scheme finished with failure!\n";
    //     return EXIT_FAILURE;
	// }

	// Load the public key
#if defined(SeedMethod_AES128)
	path2key += "seed_method_aes128";
#elif defined(SeedMethod_SHA256)
	path2key += "seed_method_sha256";
#endif
#if defined(HashMethod_SHA256)
	path2key += "/hash_method_sha256";
#elif defined(HashMethod_AES128)
	path2key += "/hash_method_aes128";
#elif defined(HashMethod_ARITHM)
	path2key += "/hash_method_arithm";
#endif
	path2key += "/inlen_" + std::to_string(inlen) + "/n1_" + std::to_string(oslot_n1);
	read_pk(path2key.c_str(), &pk);

	// Benchmark batch verification algorithms
    bool cpu_valid = true;
    double cpu_time = 0.0;

    // Initialize pk.oslot_st.root from pk.oslot_ds
    Value sct_root = pk.oslot_ds.begin()->second;
    memcpy(pk.oslot_st.root, sct_root.parent_node, SEED_SIZE);

    // CPU Verification
    if (runCpuVerification(pk, data.get(), inlen, cpu_valid, cpu_time, 1) != ECCRYPTO_SUCCESS) {
        fprintf(stderr, "ERROR: OSLO CPU-based verification failed!\n");
        return ECCRYPTO_ERROR;
    }

	printf("[INFO] CPU: avg batch ver time =  %.3f ms\n", cpu_time);

	// Write the results to a CSV file
	writeResults("cpu_bench.csv", inlen, oslot_st, cpu_time, cpu_valid);

	return 0;
}

void writeResults(char *filename, u32 inlen, OSLOT_STATE oslot_st, double cpu_time, bool cpu_valid) {
	FILE *output_file;
    output_file = fopen(filename, "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }

// #if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
//     fprintf(output_file, "AES128, SHA256, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, cpu_time, cpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
//     fprintf(output_file, "AES128, ARITHM, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, cpu_time, cpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
//     fprintf(output_file, "AES128, AES128, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, cpu_time, cpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
//     fprintf(output_file, "SHA256, SHA256, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, cpu_time, cpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
//     fprintf(output_file, "SHA256, ARITHM, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, cpu_time, cpu_valid);
// #endif

#if defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
    fprintf(output_file, "AES128ARIHM %.3f ", cpu_time);
#elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
    fprintf(output_file, "AESAES %.3f ", cpu_time);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
    fprintf(output_file, "SHASHA %.3f ", cpu_time);
#endif
    fclose(output_file);
}

ECCRYPTO_STATUS runCpuVerification(const OSLO_PK& pk, u8* data, u32 inlen, bool& valid, double& cpu_time, u32 cpu_iterations) {
    StopWatchInterface* timer = nullptr;
    sdkCreateTimer(&timer);
    sdkResetTimer(&timer);

    for (u32 iter = 0; iter < cpu_iterations; iter++) {
        sdkStartTimer(&timer);
        if (SOCOSLO_BatchVer(pk, data, inlen, &valid) != ECCRYPTO_SUCCESS) {
			fprintf(stderr, "ERROR: OSLO CPU-based batch verification failed!\n");
			return ECCRYPTO_ERROR;
		}
        sdkStopTimer(&timer);
    }
    cpu_time = sdkGetAverageTimerValue(&timer);
    sdkDeleteTimer(&timer);
    return valid == 0 ? ECCRYPTO_SUCCESS : ECCRYPTO_ERROR;
}
