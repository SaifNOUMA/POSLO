
#include <openssl/rand.h>
#include "oslo_sgn.hpp"
#include "../misc/helper_timer.h"

ECCRYPTO_STATUS SOCOSLO_Kg(OSLO_SK *sk, OSLO_PK *pk, OSLOT_STATE oslot_st)
{
    ECCRYPTO_STATUS status = ECCRYPTO_SUCCESS;
    u8  ecc_r[ORDER_SIZE], ecc_r_agg[ORDER_SIZE], prior_hash[2*ORDER_SIZE];
    u32 num_msg;

    pk->oslot_st.n1 = oslot_st.n1;
    pk->oslot_st.n2 = oslot_st.n2;
    pk->allocate_ecc_comm_arr(1 << oslot_st.n1);

    // Generate the private/public key
    if (0 == RAND_bytes(sk->ecc_sk, ORDER_SIZE)) {
        return ECCRYPTO_ERROR;
    }
    modulo_order((digit_t*) sk->ecc_sk, (digit_t*) sk->ecc_sk);
    ecc_mul_fixed((digit_t*) sk->ecc_sk, pk->ecc_pk);

#if defined (SeedMethod_AES128)
    // Generate the AES private key and its corresponding (SSL-based) round key
    if (!RAND_bytes(pk->oslot_st.aes_key, SEED_SIZE)) {
        return ECCRYPTO_ERROR;
    }
    if (AES_set_encrypt_key(pk->oslot_st.aes_key, 128, &pk->oslot_st.aes_rd_key) < 0) {
        return ECCRYPTO_ERROR;
    }
#endif

    // Generate the root of the seed tree
    if (0 == RAND_bytes(sk->oslot_root, SEED_SIZE)) {
        return ECCRYPTO_ERROR;
    }
    modulo_order((digit_t*) sk->oslot_root, (digit_t*) sk->oslot_root);
    sk->i = sk->j = 1;
    memset(pk->ecc_comm_agg, 0, ECC_COMM_SIZE);
    memset(pk->ecc_sig_agg, 0, SIG_SIZE);

    // Generate the root of the private nonce "r"
    if (0 == RAND_bytes(sk->ecc_r, ORDER_SIZE)) {
        return ECCRYPTO_ERROR;
    }
    modulo_order((digit_t*) sk->ecc_r, (digit_t*) sk->ecc_r);
    memcpy(prior_hash, sk->ecc_r, ORDER_SIZE);

    for (u32 epoch = 1 ; epoch <= (1 << oslot_st.n1) ; epoch++) {
        memset(ecc_r_agg, 0, ORDER_SIZE);
        for (u32 iter = 1 ; iter <= oslot_st.n2 ; iter++) {
            num_msg = epoch * oslot_st.n2 + iter;
            memcpy(prior_hash + ORDER_SIZE, &num_msg, sizeof(num_msg));
            if (NULL == SHA256(prior_hash, ORDER_SIZE + sizeof(u32), ecc_r)) {
                return ECCRYPTO_ERROR;
            }
            modulo_order((digit_t*) ecc_r, (digit_t*) ecc_r);
            add_mod_order((digit_t*) ecc_r_agg, (digit_t*) ecc_r, (digit_t*) ecc_r_agg);
        }
        ecc_mul_fixed((digit_t*) ecc_r_agg, pk->ecc_comm_arr[epoch-1]);
    }

    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS SOCOSLO_Sign(OSLO_SK *sk, OSLO_PK pk, u8 *in, u32 inlen, OSLO_SIG *sig, OSLOT_DS *oslot_ds)
{
    u8 seed_curr[ORDER_SIZE] = { 0 }, ecc_r[ORDER_SIZE], ecc_e[ORDER_SIZE], ecc_sig[SIG_SIZE], me_j[ORDER_SIZE], my[ORDER_SIZE], pre_hash[inlen + SEED_SIZE];
    u32 num_msg;

    if (sk->i > (1 << pk.oslot_st.n1))                                                                              { return ECCRYPTO_ERROR; }
    if (sk->j == 1) {
        if (ECCRYPTO_ERROR == OSLOT_SC(sk->oslot_root, 0, 1, sk->oslot_node, pk.oslot_st.n1, sk->i, pk.oslot_st))   { return ECCRYPTO_ERROR; }
        memset(sk->ecc_sig_agg, 0, SIG_SIZE);
    }
    
    // Derive the seed of the current iteration from the one of current epoch
    if (compute_seed(sk->oslot_node, SEED_SIZE, seed_curr, pk.oslot_st, sk->j) != ECCRYPTO_SUCCESS)                 { return ECCRYPTO_ERROR; }
    // compute the ephemeral key "e_i^j"
    if (compute_hash(in, inlen, seed_curr, ecc_e, pk.oslot_st) != ECCRYPTO_SUCCESS)                                 { return ECCRYPTO_ERROR; }
    // compute the nonce commitment key "r_i^j" during the current iteration "j" in epoch "i"
    num_msg = sk->i* pk.oslot_st.n2 + sk->j;
    memcpy(pre_hash, sk->ecc_r, ORDER_SIZE);
    memcpy(pre_hash + ORDER_SIZE, &num_msg, sizeof(num_msg));
    if (NULL == SHA256(pre_hash, ORDER_SIZE + sizeof(u32), ecc_r))                                                  { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) ecc_r, (digit_t*) ecc_r);
    // compute the signature "e * y"
    to_Montgomery((digit_t*) ecc_e, (digit_t*) me_j);
    to_Montgomery((digit_t*) sk->ecc_sk, (digit_t*) my);
    Montgomery_multiply_mod_order((digit_t*) me_j, (digit_t*) my, (digit_t*) ecc_sig);
    from_Montgomery((digit_t*) ecc_sig, (digit_t*) ecc_sig);
    // compute the signature "s <- r - e * y"
    subtract_mod_order((digit_t*) ecc_r, (digit_t*) ecc_sig, (digit_t*) ecc_sig);

    // compute the aggregated signature "s_A <- s_A + s_i^j"
    add_mod_order((digit_t*) ecc_sig, (digit_t*) sk->ecc_sig_agg, (digit_t*) sk->ecc_sig_agg);

    if (sk->j == pk.oslot_st.n2) {
        if (ECCRYPTO_ERROR == OSLOT_SSO(sk->oslot_root, sk->i, oslot_ds, pk.oslot_st))                              { return ECCRYPTO_ERROR; }
        // fill the signature components
        sig->epoch = sk->i;
        memcpy(sig->ecc_sig, sk->ecc_sig_agg, SIG_SIZE);
        // update the counters
        sk->i ++;
        sk->j = 1;
    } else {
        sk->j++;
    }

    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS SOCOSLO_Ver(OSLO_PK *pk, u8 *in, u32 inlen, OSLO_SIG sig, OSLOT_DS oslot_ds, bool *valid)
{
    u8 oslot_node[SEED_SIZE], seed_ptr[ORDER_SIZE] = { 0 }, ecc_e[ORDER_SIZE] = { 0 }, ecc_e_agg[ORDER_SIZE], pre_hash[inlen + SEED_SIZE];
    u32 iter, epoch = sig.epoch;
    point_t R_s[64];
    
    // print_hex_m("pk->oslot_st.aes_key ", pk->oslot_st.aes_key, SEED_SIZE);

    memset(ecc_e_agg, 0, ORDER_SIZE);
    memset(ecc_e, 0, ORDER_SIZE);
    // retrieve the seed that corresponds to the given epoch
    if (ECCRYPTO_ERROR == OSLOT_SR(oslot_node, pk->oslot_st.n1, epoch, oslot_ds, pk->oslot_st))                     { return ECCRYPTO_ERROR; }
    for (iter = 0 ; iter < pk->oslot_st.n2 ; iter++) {
        // Derive the seed of the current iteration from the one of current epoch
        if (compute_seed(oslot_node, SEED_SIZE, seed_ptr, pk->oslot_st, iter + 1) != ECCRYPTO_SUCCESS)              { return ECCRYPTO_ERROR; }
        // compute the e component
        if (compute_hash(in + iter * inlen, inlen, seed_ptr, ecc_e, pk->oslot_st) != ECCRYPTO_SUCCESS)              { return ECCRYPTO_ERROR; }

        // aggregate the e components
        add_mod_order((digit_t*) ecc_e_agg, (digit_t*) ecc_e, (digit_t*) ecc_e_agg);
    }
    // compute R' <- s * G + e * Y
    ecc_mul_double((digit_t*) sig.ecc_sig, (point_affine*) pk->ecc_pk, (digit_t*) ecc_e_agg, (point_affine*) R_s);
    // verify the validity of the signature
    if (0 != (*valid = memcmp(pk->ecc_comm_arr[sig.epoch-1], R_s, 64))) {
        pk->failed_sigs[sig.epoch] = sig;
        pk->failed_indices[sig.epoch] ++;
    }

    pk->oslot_ds = oslot_ds;
    
    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS SOCOSLO_Distill(OSLO_PK *pk, OSLO_SIG sig, bool valid)
{
    ECCRYPTO_STATUS status;
    u32 iter;
    point_extproj_t ecc_com_curr, ecc_com_pre;
    point_extproj_precomp_t R_tmp;
    point_t ecc_com_agg;

    if (valid) {
        return ECCRYPTO_SUCCESS;
    }

    memset(ecc_com_agg, 0, sizeof(ecc_com_agg));
    // add up to the aggregated signature
    add_mod_order((digit_t*) pk->ecc_sig_agg, (digit_t*) sig.ecc_sig, (digit_t*) pk->ecc_sig_agg);
    // add up to the public commitment of the aggregated signature
    if (0 == memcmp(pk->ecc_comm_agg, ecc_com_agg, sizeof(ecc_com_agg))) {
        memcpy(pk->ecc_comm_agg, pk->ecc_comm_arr[sig.epoch-1], 64);
    } else {
        point_setup((point_affine*) pk->ecc_comm_agg, ecc_com_pre);
        point_setup(pk->ecc_comm_arr[sig.epoch-1], ecc_com_curr);
        
        R1_to_R2(ecc_com_curr, R_tmp);
        eccadd(R_tmp, ecc_com_pre);

        eccnorm(ecc_com_pre, ecc_com_agg);
        memcpy(pk->ecc_comm_agg, ecc_com_agg, sizeof(ecc_com_agg));
    }
    
    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS SOCOSLO_BatchVer(OSLO_PK pk, u8 *in, u32 inlen, bool *valid)
{
    u8 ecc_e_agg[ORDER_SIZE] = { 0 }, ecc_e_i[ORDER_SIZE], ecc_e_cur[ORDER_SIZE] = {0}, oslot_node[ORDER_SIZE], seed_ptr[ORDER_SIZE] = { 0 }, pre_hash[inlen+SEED_SIZE];
    u32 iter, epoch, num_msg;
    point_t ecc_comm;

    // print_hex_m("pk->oslot_st.aes_key ", pk.oslot_st.aes_key, SEED_SIZE);
    print_hex_m("in: ", in, inlen);
    print_hex_m("pk->ecc_pk: ", (u8*)pk.ecc_pk, sizeof(pk.ecc_pk));
    if (!pk.oslot_ds.empty()) {
        auto first_value = pk.oslot_ds.begin()->second;
        print_hex_m("oslot_root: ", (u8*) first_value.parent_node, SEED_SIZE);
    }

#if defined(SeedMethod_AES128)
    print_hex_m("pk.oslot_st.aes_key: ", pk.oslot_st.aes_key, SEED_SIZE);
#endif

    for (epoch = 1 ; epoch <= (1 << pk.oslot_st.n1) ; epoch++) {
        memset(ecc_e_i, 0, ORDER_SIZE);
        if (ECCRYPTO_ERROR == OSLOT_SR(oslot_node, pk.oslot_st.n1, epoch, pk.oslot_ds, pk.oslot_st))                { return ECCRYPTO_ERROR; }

        if (epoch == 1) {
            print_hex_m("oslot_node: ", oslot_node, SEED_SIZE);
        }

        for (iter = 0 ; iter < pk.oslot_st.n2 ; iter++) {
            num_msg = (epoch - 1) * pk.oslot_st.n2 + iter;

            if (compute_seed(oslot_node, SEED_SIZE, seed_ptr, pk.oslot_st, iter+1) != ECCRYPTO_SUCCESS)             { return ECCRYPTO_ERROR; }
            // compute the e component
            if (compute_hash(in + num_msg * inlen, inlen, seed_ptr, ecc_e_cur, pk.oslot_st) != ECCRYPTO_SUCCESS)    { return ECCRYPTO_ERROR; }

            add_mod_order((digit_t*) ecc_e_i, (digit_t*) ecc_e_cur, (digit_t*) ecc_e_i);
        }
        if (pk.failed_indices[epoch] == 0) {
            add_mod_order((digit_t*) ecc_e_i, (digit_t*) ecc_e_agg, (digit_t*) ecc_e_agg);
        }
    }

    print_hex_m("ecc_e_agg: ", ecc_e_agg, ORDER_SIZE);

    ecc_mul_double((digit_t*) pk.ecc_sig_agg, pk.ecc_pk, (digit_t*) ecc_e_agg, ecc_comm);
    *valid = memcmp(pk.ecc_comm_agg, ecc_comm, sizeof(point_t));
    if (0 != *valid) {
        return ECCRYPTO_ERROR;
    }

    // StopWatchInterface *timer;
	// double avg_time;
	// sdkCreateTimer(&timer);
	// sdkResetTimer(&timer);

    // for (int i = 0 ; i < 1000 ; i++) {
    //     sdkStartTimer(&timer);
    //     ecc_mul_double((digit_t*) pk.ecc_sig_agg, pk.ecc_pk, (digit_t*) ecc_e_agg, ecc_comm);
    //     sdkStopTimer(&timer);
    // }
    // avg_time = sdkGetAverageTimerValue(&timer);
    // printf("[INFO] CPU: avg EC scalar multiplication time =  %.6f ms\n", avg_time);

	// sdkResetTimer(&timer);
    // for (int i = 0 ; i < 1000 ; i++) {
    //     sdkStartTimer(&timer);
    //     add_mod_order((digit_t*) ecc_e_i, (digit_t*) ecc_e_cur, (digit_t*) ecc_e_i);
    //     sdkStopTimer(&timer);
    // }
    // avg_time = sdkGetAverageTimerValue(&timer);
    // printf("[INFO] CPU: avg modular addition time =  %.6f ms\n", avg_time);

    // u8 me_j[ORDER_SIZE], my[ORDER_SIZE], ecc_sig[SIG_SIZE];

	// sdkResetTimer(&timer);
    // for (int i = 0 ; i < 1000 ; i++) {
    //     sdkStartTimer(&timer);
    //     to_Montgomery((digit_t*) ecc_e_cur, (digit_t*) me_j);
    //     to_Montgomery((digit_t*) ecc_e_cur, (digit_t*) my);
    //     Montgomery_multiply_mod_order((digit_t*) me_j, (digit_t*) my, (digit_t*) ecc_sig);
    //     from_Montgomery((digit_t*) ecc_sig, (digit_t*) ecc_sig);
    //     sdkStopTimer(&timer);
    // }
    // avg_time = sdkGetAverageTimerValue(&timer);
    // printf("[INFO] CPU: avg modular multiplication time =  %.6f ms\n", avg_time);

    // sdkResetTimer(&timer);
    // for (int i = 0 ; i < 1000 ; i++) {
    //     sdkStartTimer(&timer);
    //     SHA256(pre_hash, inlen+SEED_SIZE, ecc_e_cur);
    //     sdkStopTimer(&timer);
    // }
    // avg_time = sdkGetAverageTimerValue(&timer);
    // printf("[INFO] CPU: avg SHA256 time =  %.6f ms\n", avg_time);

    return ECCRYPTO_SUCCESS;
}
