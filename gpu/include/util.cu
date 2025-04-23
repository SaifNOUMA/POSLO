
#include "util.cuh"

__device__ void d_print_hex_m(char *m, u8* arr, u32 len)
{
    int i;
    printf("%s", m);
    for(i = 0; i < len; i++)
        printf("%8x", (unsigned char) arr[i]);
    printf("\n");
}

__host__ void print_hex_m(char *m, u8* arr, u32 len)
{
    int i;
    printf("%s", m);
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}

__host__ void read4file(char *path2file, char *data, size_t datalen)
{
    std::ifstream input_file(path2file, std::ios::binary);
    input_file.read(data, datalen);

}

void file2mapint(std::map<size_t, int> *data, char *path2file) {
    std::ifstream   input_file;
    size_t          k;
    int             v;
    std::map<size_t, int> data_tmp;


    input_file.open(path2file);
    while (input_file >> k >> v) {
        data_tmp[k] = v;
    }
    input_file.close();
    *data = data_tmp;
}

__host__ void file2mapsig(std::map<size_t, OSLO_SIG> *data, char *path2file) {
    std::ifstream   input_file;
    size_t   k;
    OSLO_SIG v;
    std::map<size_t, OSLO_SIG> data_tmp;

    input_file.open(path2file);
    while (input_file) {
        input_file.read((char*) &k, sizeof(k));
        input_file.read((char*) &v, sizeof(v));
        data_tmp[k] = v;
    }

    input_file.close();
    *data = data_tmp;
}

__host__ void file2mapseed(std::map<Key, Value> *data, char *path2file) {
    std::ifstream   input_file;
    Key             k;
    Value           v;
    std::map<Key, Value> data_tmp;

    input_file.open(path2file);
    while (input_file.good()) {
        input_file.read((char*) &k, sizeof(k));
        input_file.read((char*) &v, sizeof(v));

        data_tmp[k] = v;
    }

    input_file.close();
    *data = data_tmp;
}

__host__ void read_pk(const char *root_path, OSLO_PK *pk)
{
    char pk_path[100] = { 0 };

    sprintf(pk_path, "%s/pk/ecc_pk", root_path);
    read4file(pk_path, reinterpret_cast<char*>(&pk->ecc_pk), sizeof(pk->ecc_pk));

    sprintf(pk_path, "%s/pk/ecc_sig_agg", root_path);
    read4file(pk_path, reinterpret_cast<char*>(&pk->ecc_sig_agg), sizeof(pk->ecc_sig_agg));
    
    sprintf(pk_path, "%s/pk/ecc_comm_agg", root_path);
    read4file(pk_path, reinterpret_cast<char*>(&pk->ecc_comm_agg), sizeof(pk->ecc_comm_agg));

    sprintf(pk_path, "%s/pk/oslot_st", root_path);
    read4file(pk_path, reinterpret_cast<char*>(&pk->oslot_st), sizeof(OSLOT_STATE));

    sprintf(pk_path, "%s/pk/oslot_ds", root_path);
    file2mapseed(&pk->oslot_ds, pk_path);

    sprintf(pk_path, "%s/pk/failed_indices", root_path);
    file2mapint(&pk->failed_indices, pk_path);
    
    sprintf(pk_path, "%s/pk/failed_sigs", root_path);
    file2mapsig(&pk->failed_sigs, pk_path);
}

void writeResults(const char *filename, u32 inlen, OSLOT_STATE oslot_st, double gpu_time, bool gpu_valid) {
	FILE *output_file;
    output_file = fopen(filename, "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }

#if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
    fprintf(output_file, "AES128, SHA256, %.3f, %d \n", gpu_time, gpu_valid);
#elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
    fprintf(output_file, "AES128, AES128, %.3f, %d \n", gpu_time, gpu_valid);
#elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
    fprintf(output_file, "AES128, ARITHM, %.3f, %d \n", gpu_time, gpu_valid);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
    fprintf(output_file, "SHA256, SHA256, %.3f, %d \n", gpu_time, gpu_valid);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
    fprintf(output_file, "SHA256, ARITHM, %.3f, %d \n", gpu_time, gpu_valid);
#endif

// #if defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
//     fprintf(output_file, "AES128ARIHM %.3f ", gpu_time);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
//     fprintf(output_file, "AESAES %.3f ", gpu_time);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
//     fprintf(output_file, "SHASHA %.3f ", gpu_time);
// #endif

// #if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
//     fprintf(output_file, "AES128, SHA256, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, gpu_time, gpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
//     fprintf(output_file, "AES128, AES128, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, gpu_time, gpu_valid);
// #elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
//     fprintf(output_file, "AES128, ARITHM, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, gpu_time, gpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
//     fprintf(output_file, "SHA256, SHA256, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, gpu_time, gpu_valid);
// #elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
//     fprintf(output_file, "SHA256, ARITHM, %u, %u, %u, %.3f, %d \n", inlen, oslot_st.n1, oslot_st.n2, gpu_time, gpu_valid);
// #endif
    fclose(output_file);
}

__device__ void print_digit(char *info, digit_t *digit, u32 nwords) {
    printf("%s:\n", info);
    for (int i = nwords-1 ; i >= 0 ; i--) {
        for (int bit = 0 ; bit < sizeof(digit_t)*8 ; bit++) {
            printf("%c", (digit[i] & (1ULL << (sizeof(digit_t)*8-bit-1))) ? '1' : '0');
        }
        printf("");
    }
    printf("\n");
}
