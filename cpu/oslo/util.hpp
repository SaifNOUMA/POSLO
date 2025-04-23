
#pragma once

#include <cstring>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "fp.h"
#include "oslo_types.h"

#ifndef MIN
#define MIN(a, b) ((a < b) ? a : b)
#endif
#ifndef MAX
#define MAX(a, b) ((a > b) ? a : b)
#endif

/* for constant memory */
extern u32 this_K256[64];
extern u32 K256[64];

extern u64 this_K512[80];
extern u64 K512[80];

extern u64 dev_curve_order[4];
extern u64 dev_Montgomery_Rprime[4];
extern u64 dev_Montgomery_rprime[4];

/** 
 * Hash an input data concatenated with an unsigned integer
 * 
 *  @param  in      Pointer to the input to hash
 *  @param  inlen   Length of the input
 *  @param  hash    Pointer to the input to sign
 *  @param  counter Integer to be concatenate with the input message
 *  @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS sha256_i(const u8* in, u32 inlen, u8* hash, u32 counter);

/** 
 * Print an "unsigned char" data array
 * 
 *  @param  in      Pointer to the input to print
 *  @param  inlen   Length of the input
 *  @return Nothing
 */
void print_hex(u8* in, u32 inlen);

/** 
 * Print an information message followed by an "unsigned char" data array 
 * 
 *  @param  in      Pointer to the input to print
 *  @param  inlen   Length of the input
 *  @return Nothing
 */
void print_hex_m(char *info, u8* in, u32 inlen);

/** 
 * Write an "unsigned char" data array to a file 
 * 
 *  @param  path2file  Path to the file
 *  @param  data       Pointer to the input to print
 *  @param  datalen    Length of the input
 *  @return Nothing
 */
void write2file(char *path2file, char *data, size_t datalen);

/**
 * Read an "unsigned char" data array from a file
 * 
 * @param  path2file  Path to the file
 * @param  data       Pointer to the input to print
 * @param  datalen    Length of the input
 * @return Nothing
 */
void read4file(char *path2file, char *data, size_t datalen);

/** Write a map of integers to a file 
 * 
 *  @param  data      Map of integers to write
 *  @param  path2file Path to the file
 *  @return Nothing
 */
void mapint2file(std::map<size_t, int> data, char *path2file);

/**
 * Write a map of OSLO signatures to a file
 * 
 * @param  data      Map of OSLO signatures to write
 * @param  path2file Path to the file
 * @return Nothing
 */
void mapsig2file(std::map<size_t, OSLO_SIG> data, char *path2file);

/**
 * Write a map of seeds to a file
 * 
 * @param  data      Map of seeds to write
 * @param  path2file Path to the file
 * @return Nothing
 */
void mapseed2file(std::map<Key, Value> data, char *path2file);

/** Read a map of integers from a file 
 * 
 *  @param  data      Map of integers to read
 *  @param  path2file Path to the file
 *  @return Nothing
 * 
**/
void file2mapint(std::map<size_t, int> *data, char *path2file);

/** Read a map of OSLO signatures from a file 
 * 
 *  @param  data      Map of OSLO signatures to read
 *  @param  path2file Path to the file
 *  @return Nothing
 */
void file2mapsig(std::map<size_t, OSLO_SIG> *data, char *path2file);

/**
 * Read a map of seeds from a file
 * 
 * @param  data      Map of seeds to read
 * @param  path2file Path to the file
 * @return Nothing
 */
void file2mapseed(std::map<Key, Value> *data, char *path2file);

/**
 * Print a map of integers
 * 
 * @param  map   Map of integers to print
 * @param  title Title of the map
 * @return Nothing
 */
template<typename Map>
void printMap(const Map& map, char *title);

/**
 * Set up the parameters for the OSLO signature scheme
 * 
 * @param  path2log Path to the log file
 * @param  sct_l1   Number of epochs in the signature generation
 * @param  sct_l2   Number of iterations within the epoch
 * @param  tau_F    Threshold value for the number of failed signatures
 * @return Nothing
 */
void setup_params(char *path2log, size_t *sct_l1, size_t *sct_l2, double *tau_F);

/**
 * Save the OSLO public key to a file
 * 
 * @param  root_path Path to the file
 * @param  pk        OSLO public key
 * @return Nothing
 */
void save_pk(char *root_path, OSLO_PK pk);

/**
 * Read the OSLO public key from a file
 * 
 * @param  root_path Path to the file
 * @param  pk        OSLO public key
 * @return Nothing
 */
void read_pk(const char *root_path, OSLO_PK *pk);

/**
 * Save timing information to a CSV file
 * 
 * @param  inlen        Length of the input
 * @param  oslot_st     OSLOT state
 * @param  valid        0 if signature is valid and 1 otherwise
 * @param  sign_time    Time taken to sign the input
 * @param  ver_time     Time taken to verify the signature
 * @param  distill_time Time taken to distill the signature
 * @param  batch_ver_time Time taken to batch verify the signature
 * @return Nothing
 */
void save_timing_to_csv(u32 inlen, OSLOT_STATE oslot_st, bool valid, double sign_time, double ver_time, double distill_time, double batch_ver_time);

/**
 * Free the OSLO public key
 * 
 * @param  pk OSLO public key
 * @return Nothing
 */
void free_OSLO_PK(OSLO_PK pk);

/** 
 * Compute the seed value for the given input
 * 
 * @param  in      Pointer to the input to hash
 * @param  inlen   Length of the input
 * @param  out     Pointer to the output seed
 * @param  oslot_st OSLOT state containing the root value, depth, and height
 * @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS compute_seed(u8 *in, u32 inlen, u8 *out, OSLOT_STATE oslot_st, u32 counter);

/** 
 * Compute the hash value for the given input
 * 
 * @param  in      Pointer to the input to hash
 * @param  inlen   Length of the input
 * @param  out     Pointer to the output hash
 * @param  counter Integer to be concatenate with the input message
 * @param  seed    Pointer to the seed value
 * @return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
// ECCRYPTO_STATUS compute_hash(u8 *in, u32 inlen, u8 *seed, u8 *out);
ECCRYPTO_STATUS compute_hash(u8 *in, u32 inlen, u8 *seed, u8 *out, OSLOT_STATE oslot_st);
