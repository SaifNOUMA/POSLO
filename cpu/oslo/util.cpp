
#include "util.hpp"

ECCRYPTO_STATUS sha256_i(const u8* in, u32 inlen, uint8_t* hash, u32 counter)
{
    u8 prior_hash[inlen+sizeof(u32)];

    memcpy(prior_hash, in, inlen);
    memcpy(prior_hash + inlen, (u8*) &counter, sizeof(counter));

    if (SHA256(prior_hash, inlen+sizeof(u32), hash) == nullptr) { return ECCRYPTO_ERROR; }

    return ECCRYPTO_SUCCESS;
}

void print_hex(u8* arr, u32 len)
{
    std::cout << "\n";
    for(u32 i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    std::cout << "\n";
}

void print_hex_m(char *info, u8* data_ptr, u32 data_len)
{
    std::cout << info;
    for(u32 i = 0; i < data_len; i++)
        printf("%x", static_cast<u8>(data_ptr[i]));
    std::cout << "\n";
}

void write2file(char *path2file, char *data, size_t datalen)
{
    std::ofstream output_file(path2file, std::ios::binary);
    output_file.write((char*) data, datalen);
}

void read4file(char *path2file, char *data, size_t datalen)
{
    std::ifstream input_file(path2file, std::ios::binary);
    input_file.read(data, datalen);

}

void mapint2file(std::map<size_t, int> data, char *path2file) {
    std::ofstream output_file(path2file); 

    for (const auto& p : data) {
        output_file << p.first << std::endl << p.second << std::endl;
    }
}

void mapsig2file(std::map<size_t, OSLO_SIG> data, char *path2file) {
    std::ofstream output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(size_t));
        output_file.write((char*) &p.second, sizeof(OSLO_SIG));
    }
    output_file.close();
}

void mapseed2file(std::map<Key, Value> data, char *path2file) {
    std::ofstream               output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(Key));
        output_file.write((char*) &p.second, sizeof(Value));
    }
    output_file.close();
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

void file2mapsig(std::map<size_t, OSLO_SIG> *data, char *path2file) {
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

void file2mapseed(std::map<Key, Value> *data, char *path2file) {
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

template<typename Map>
void printMap(const Map& map, char *title) {
    std::cout << title << "\n";
    for (const auto& p : map)
        std::cout<<p.first <<","<< p.second <<std::endl;
}

void save_pk(char *root_path, OSLO_PK pk)
{
    char pk_path[100] = { 0 };
    memset(pk_path, 0, sizeof(pk_path));

    sprintf(pk_path, "%s/pk/ecc_pk", root_path);
    write2file(pk_path, reinterpret_cast<char*>(&pk.ecc_pk), sizeof(pk.ecc_pk));

    sprintf(pk_path, "%s/pk/ecc_sig_agg", root_path);
    write2file(pk_path, reinterpret_cast<char*>(pk.ecc_sig_agg), sizeof(pk.ecc_sig_agg));

    sprintf(pk_path, "%s/pk/ecc_comm_agg", root_path);
    write2file(pk_path, reinterpret_cast<char*>(pk.ecc_comm_agg), sizeof(pk.ecc_comm_agg));

    sprintf(pk_path, "%s/pk/oslot_st", root_path);
    write2file(pk_path, reinterpret_cast<char*>(&pk.oslot_st), sizeof(OSLOT_STATE));

    sprintf(pk_path, "%s/pk/oslot_ds", root_path);
    mapseed2file(pk.oslot_ds, pk_path);

    sprintf(pk_path, "%s/pk/failed_indices", root_path);
    mapint2file(pk.failed_indices, pk_path);

    sprintf(pk_path, "%s/pk/failed_sigs", root_path);
    mapsig2file(pk.failed_sigs, pk_path);
}

void read_pk(const char *root_path, OSLO_PK *pk)
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

void save_timing_to_csv(u32 inlen, OSLOT_STATE oslot_st, bool valid, double sign_time, double ver_time, double distill_time, double batch_ver_time)
{
    FILE *output_file;

#if defined(SeedMethod_AES128) && defined(HashMethod_SHA256)
    output_file = fopen("oslo_aes128_sha256.csv", "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fprintf(output_file, "AES128, SHA256, %u, %u, %u, %u, %.3f, %.3f, %.3f, %.3f \n", inlen, oslot_st.n1, oslot_st.n2, valid, sign_time, ver_time, distill_time, batch_ver_time);
#elif defined(SeedMethod_AES128) && defined(HashMethod_ARITHM)
    output_file = fopen("oslo_aes128_arith.csv", "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fprintf(output_file, "AES128, ARITHM, %u, %u, %u, %u, %.3f, %.3f, %.3f, %.3f \n", inlen, oslot_st.n1, oslot_st.n2, valid, sign_time, ver_time, distill_time, batch_ver_time);
#elif defined(SeedMethod_AES128) && defined(HashMethod_AES128)
    output_file = fopen("oslo_aes128_aes128.csv", "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fprintf(output_file, "AES128, AES128, %u, %u, %u, %u, %.3f, %.3f, %.3f, %.3f \n", inlen, oslot_st.n1, oslot_st.n2, valid, sign_time, ver_time, distill_time, batch_ver_time);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_SHA256)
    output_file = fopen("oslo_sha256_sha256.csv", "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fprintf(output_file, "SHA256, SHA256, %u, %u, %u, %u, %.3f, %.3f, %.3f, %.3f \n", inlen, oslot_st.n1, oslot_st.n2, valid, sign_time, ver_time, distill_time, batch_ver_time);
#elif defined(SeedMethod_SHA256) && defined(HashMethod_ARITHM)
    output_file = fopen("oslo_sha256_arithm.csv", "a");
    if (output_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fprintf(output_file, "SHA256, ARITHM, %u, %u, %u, %u, %.3f, %.3f, %.3f, %.3f \n", inlen, oslot_st.n1, oslot_st.n2, valid, sign_time, ver_time, distill_time, batch_ver_time);
#endif
    fclose(output_file);
}

void free_OSLO_PK(OSLO_PK pk) {
    if (pk.ecc_comm_arr != NULL) {
        free(pk.ecc_comm_arr);
        pk.ecc_comm_arr = NULL;
    } 
}

ECCRYPTO_STATUS compute_seed(u8 *in, u32 inlen, u8 *out, OSLOT_STATE oslot_st, u32 counter)
{
#if defined(SeedMethod_AES128)
        AES_encrypt(in, out, &oslot_st.aes_rd_key);
        // MMO-AES128 Hash Fucntion
        // int outlen = 0;
        // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // EVP_CipherInit(ctx, EVP_aes_128_ecb(), oslot_st.aes_key, NULL, 1);
        // EVP_CipherUpdate(ctx, out, &outlen, in, inlen);

        // EVP_CipherFinal(ctx, out+outlen, &outlen);
#elif defined(SeedMethod_SHA256)
        if (ECCRYPTO_ERROR == sha256_i(in, inlen, out, counter)) {
            return ECCRYPTO_ERROR;
        }
#endif
    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS compute_hash(u8 *in, u32 inlen, u8 *seed, u8 *out, OSLOT_STATE oslot_st)
{
#if defined(HashMethod_SHA256)
    u8 prior_hash[inlen+SEED_SIZE];
    memcpy(prior_hash, in, inlen);
    memcpy(prior_hash + inlen, seed, SEED_SIZE);
    SHA256(prior_hash, inlen+SEED_SIZE, out);
    modulo_order((digit_t*) out, (digit_t*) out);
#elif defined(HashMethod_AES128)
    int outlen = 0;
    u8 intemp[32] = {0};
    memcpy(intemp, in, inlen);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    for (int i = 0 ; i < (inlen+SEED_SIZE)/16 ; i++) {
        EVP_CipherInit(ctx, EVP_aes_128_ecb(), oslot_st.aes_key, NULL, 1);
        EVP_CipherUpdate(ctx, out, &outlen, intemp, 16);
    }
    EVP_CIPHER_CTX_free(ctx);
#elif defined(HashMethod_ARITHM)
    if (inlen >= 30) {
        modulo_order((digit_t*) in, (digit_t*) out);
    } else {
        memset(out, 0, ORDER_SIZE);
        memcpy(out, in, inlen);
    }
#if defined(SeedMethod_SHA256)
        modulo_order((digit_t*) seed, (digit_t*) seed);
#endif
    add_mod_order((digit_t*) out, (digit_t*) seed, (digit_t*) out);
#endif
    return ECCRYPTO_SUCCESS;
}
