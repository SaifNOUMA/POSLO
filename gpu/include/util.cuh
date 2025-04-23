
#ifndef UTIL_CUH
#define UTIL_CUH

#include <memory>
#include <fstream>
#include <iostream>
#include "types.cuh"
using namespace std;

#define CHECK(call) \
	if ((call) != cudaSuccess) { \
		cudaError_t err = cudaGetLastError(); \
		cerr << "CUDA error calling \""#call "\", code is " << err << endl; }

// RAII-style resource manager for CUDA resources
template<typename T>
class CudaManagedPtr {
private:
    T* ptr;
public:
    CudaManagedPtr(size_t count = 1) {
        CHECK(cudaMallocManaged(&ptr, count * sizeof(T)));
    }
    ~CudaManagedPtr() {
        cudaFree(ptr);
    }
    T* get() const {
        return ptr;
    }
    // Disallow copy and assignment to ensure proper resource management
    CudaManagedPtr(const CudaManagedPtr&) = delete;
    CudaManagedPtr& operator=(const CudaManagedPtr&) = delete;
};

/** prints an array containing elements of type unsigned char
 *  \param  m     	 custom information message
 *  \param  arr      array to print out
 *  \param  len  	 number of elements in the array arr
 *  \return nothing
 */
__device__ void d_print_hex_m(char *m, u8* arr, u32 len);

/** prints an array containing elements of type unsigned char
 *  \param  m     	 custom information message
 *  \param  arr      array to print out
 *  \param  len  	 number of elements in the array arr
 *  \return nothing
 */
__host__ void print_hex_m(char *m, u8* arr, u32 len);


/**
 * Read the OSLO private key from a file
 * 
 * @param  root_path Path to the file
 * @param  sk        OSLO private key
 * @return Nothing
 */
__host__ void file2mapint(std::map<size_t, int> *data, char *path2file);

/**
 * Read the OSLO signature from a file
 * 
 * @param  root_path Path to the file
 * @param  sig       OSLO signature
 * @return Nothing
 */
__host__ void file2mapsig(std::map<size_t, OSLO_SIG> *data, char *path2file);

/**
 * Read the OSLO seed from a file
 * 
 * @param  root_path Path to the file
 * @param  seed      OSLO seed
 * @return Nothing
 */
__host__ void file2mapseed(std::map<Key, Value> *data, char *path2file);

/**
 * Compute the aggregate ephemeral key "e"
 * 
 * @param  u32_in   array of words (unsigned int)
 * @param  inlen    len of the array u32_in
 * @param  u8_out   array of unsigned char
 * @return Nothing
 */
__host__ void read_pk(const char *root_path, OSLO_PK *pk);

/**
 * Write the results of the OSLO batch verification algorithm to a file
 * 
 * @param  filename     Path to the file
 * @param  inlen        Length of the input data
 * @param  oslot_st     OSLOT state
 * @param  gpu_time     Time taken by the GPU
 * @param  gpu_valid    Whether the GPU results are valid
 * @return Nothing
 */
void writeResults(const char *filename, u32 inlen, OSLOT_STATE oslot_st, double gpu_time, bool gpu_valid);

/**
 * Print the content of a digit_t
 * 
 * @param  info  Custom information message
 * @param  digit Digit to print
 * @param  nwords Number of words in the digit
 * @return Nothing
 */
__device__ void print_digit(char *info, digit_t *digit, u32 nwords = 4);

#endif // UTIL_CUH