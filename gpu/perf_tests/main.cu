
#include "misc/helper_timer.h"
#include "misc/helper_string.h"
#include "tester.cu"
#include "oslo.cuh"

int main(int argc, char **argv)
{
	ECCRYPTO_STATUS status = ECCRYPTO_ERROR;
	const char path2log[50] = "../../data/log.txt";
	string path2key = "../../data/crypto/";
	u32 oslot_n1 = 10;
	u32 oslot_n2 = 256;
	u32 inlen = 32;
	u32 gpu_iterations = 100;
	OSLO_PK pk;

	// Parse command line arguments
    inlen 			= getCmdLineArgumentIntOrDefault(argc, argv, "inlen", inlen);
	oslot_n1 		= getCmdLineArgumentIntOrDefault(argc, argv, "n1", oslot_n1);
    oslot_n2 		= getCmdLineArgumentIntOrDefault(argc, argv, "n2", oslot_n2);
    gpu_iterations 	= getCmdLineArgumentIntOrDefault(argc, argv, "gpu_iterations", gpu_iterations);
	
	// Set up the OSLOT state
	OSLOT_STATE oslot_st{oslot_n1, oslot_n2};

	// Load data
	u32 data_elements = (1 << oslot_n1) * oslot_n2;
	u32 datalen = data_elements * inlen;
	unique_ptr<u8[]> data(new u8[datalen]);
    ifstream log_file(path2log, ifstream::binary);
    if (!log_file) {
        cerr << "ERROR: Data load failed!\n";
        return EXIT_FAILURE;
    }
	log_file.read(reinterpret_cast<char*>(data.get()), datalen);

	// Load the public key
#if defined(OSLO_AES128_SHA256)
	path2key += "seed_method_aes128/hash_method_sha256";
#elif defined(OSLO_AES128_ARITHM)
    path2key += "seed_method_aes128/hash_method_arithm";
#elif defined(OSLO_AES128_AES128)
    path2key += "seed_method_aes128/hash_method_aes128";
#elif defined(OSLO_SHA256_SHA256)
    path2key += "seed_method_sha256/hash_method_sha256";
#elif defined(OSLO_SHA256_ARITHM)
    path2key += "seed_method_sha256/hash_method_arithm";
#endif

	if (oslot_n1 > 15) {
		path2key += "/inlen_" + std::to_string(inlen) + "/n1_" + std::to_string(15);
		read_pk(path2key.c_str(), &pk);
		pk.oslot_st.n1 = oslot_n1;
	} else {
		path2key += "/inlen_" + std::to_string(inlen) + "/n1_" + std::to_string(oslot_n1);
		read_pk(path2key.c_str(), &pk);
	}


	// Benchmark batch verification algorithms
	status = OSLO_batch_ver_bench(pk, data.get(), inlen, oslot_st, gpu_iterations);
	if (status == ECCRYPTO_ERROR) {
		cerr << "[INFO] OSLO signature scheme finished with failure!\n";
		return EXIT_FAILURE;
	}

	return 0;
}
