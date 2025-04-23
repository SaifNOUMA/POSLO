
#ifndef __OSLO_TYPES_H
#define __OSLO_TYPES_H

#include <stddef.h>
#include <map>
#include "fourq/fp.h"
#include <openssl/aes.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#if defined (OSLO_AES128_SHA256)
    #define SeedMethod_AES128
    #define HashMethod_SHA256
#elif defined (OSLO_AES128_ARITHM)
    #define SeedMethod_AES128
    #define HashMethod_ARITHM
#elif defined (OSLO_AES128_AES128)
    #define SeedMethod_AES128
    #define HashMethod_AES128
#elif defined (OSLO_SHA256_SHA256)
    #define SeedMethod_SHA256
    #define HashMethod_SHA256
#elif defined (OSLO_SHA256_ARITHM)
    #define SeedMethod_SHA256
    #define HashMethod_ARITHM
#endif

#if defined(SeedMethod_AES128)
    #define SEED_SIZE 16
#elif defined(SeedMethod_SHA256)
    #define SEED_SIZE 32
#endif
constexpr size_t SIG_SIZE = 32;
constexpr size_t ORDER_SIZE = 32;
constexpr size_t ECC_COMM_SIZE = 64;

struct Key {
    u32  start;
    u32  end;

    bool operator<(const Key &other) const {
        return start < other.start || end < other.end;
    }
    bool operator==(const Key &other) const {
        return start == other.start && end == other.end;
    }
};

struct Value {
    u32 height;
    u32 index;
    u8  parent_node[SEED_SIZE];
};

using OSLOT_DS = std::map<Key,Value>;

struct OSLOT_STATE
{
    u32 n1;
    u32 n2;
    u8  root[SEED_SIZE];
#if defined(SeedMethod_AES128)
    u8 aes_key[SEED_SIZE]; // AES user key
    AES_KEY aes_rd_key; // SSL-version AES round key
#endif
};

struct OSLO_SK
{
    u8 ecc_sk[ORDER_SIZE]; // EC private key
    u8 ecc_r[ORDER_SIZE]; // EC Private key nonce
    u8 ecc_sig_agg[ORDER_SIZE]; // Aggregate EC signature
    u8 oslot_root[ORDER_SIZE]; // Root of OSLOT structure
    u8 oslot_node[ORDER_SIZE]; // Current node in OSLOT structure
    u32 i; // Epoch value
    u32 j; // Iteration within the i^th epoch
};

struct OSLO_SIG
{
    u8  ecc_sig[ORDER_SIZE]; // EC signature component
    u32 epoch; // Epoch value
};

struct OSLO_PK
{
    point_t ecc_pk; // EC public key
    point_t ecc_comm_agg; // Product of the public ephemeral keys for valid signatures
    point_t *ecc_comm_arr; // Public commitments
    u8 ecc_sig_agg[ORDER_SIZE]; // Overall aggregate signature
    OSLOT_DS oslot_ds; // List of disclosed seeds
    OSLOT_STATE oslot_st; // OSLOT state containing related parameters 
    std::map<size_t, OSLO_SIG> failed_sigs; // list of failed signatures
    std::map<size_t, int> failed_indices; // list of failed items' indices

    // Constructor initializing ecc_comm_arr to nullptr
    OSLO_PK() : ecc_comm_arr(nullptr) {}

    // Dynamically allocate an array containing public commitments
    void allocate_ecc_comm_arr(u32 len) {
        ecc_comm_arr = new point_t[len];
    }

    // Free up dynamically allocated array of public commitments
    void free_ecc_comm() {
        delete[] ecc_comm_arr;
        ecc_comm_arr = nullptr;
    }
};

#endif // __OSLO_TYPES_H