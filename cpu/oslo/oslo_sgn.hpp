
#pragma once

#include "oslo_smf.hpp"

/** 
 * Generate private/public key pair of SOCOSLO signature scheme
 * using the supplied number of epochs and iterations within each epoch
 * 
 *  \param  sk      OSLO secret key containing the EC private key
 *  \param  pk      OSLO public key
 *  \param  oslo_l1 number of epochs in the signature generation
 *  \param  oslo_l2 number of iterations within the epoch
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_Kg(OSLO_SK *sk, OSLO_PK *pk, OSLOT_STATE oslot_st);

/** 
 * Computes SOCOSLO signature of a given input value using the supplied private key
 * 
 *  \param  sk      OSLO secret key containing the EC private key
 *  \param  pk      OSLO public key
 *  \param  in      pointer to the input to sign
 *  \param  inlen   length of the input
 *  \param  sig     pointer to the created signature
 *  \param  ds      pointer to the map of disclosed seeds
 *  \param  oslo_l1 number of epochs in the signature generation
 *  \param  oslo_l2 number of iterations within the epoch
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_Sign(OSLO_SK *sk, OSLO_PK pk, u8 *in, u32 inlen, OSLO_SIG *sig, OSLOT_DS *ds);

/** 
 * Verify SOCOSLO signature of a given input value using the supplied public key
 * 
 *  \param  pk      Pointer to the OSLO public key
 *  \param  in      pointer to the input to verify
 *  \param  inlen   length of the input
 *  \param  sig     pointer to the created signature
 *  \param  ds      pointer to the map of disclosed seeds
 *  \param  valid   0 if signature is valid and 1 otherwise
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_Ver(OSLO_PK *pk, u8 *in, u32 inlen, OSLO_SIG sig, OSLOT_DS ds, bool *valid);

/** 
 * Add the SOCOSLO signature to the aggregate signature value in the public 
 * 
 * if it is valid or add it to the list of failed items
 *  \param  pk      Pointer to the OSLO public key
 *  \param  sig     a signature to be distilled
 *  \param  valid   0 if the signature is valid and 1 otherwise
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_Distill(OSLO_PK *pk, OSLO_SIG sig, bool valid);

/** 
 * Batch verify the distilled SOCOSLO signatures of a set of input values the supplied public key
 * 
 *  \param  pk      OSLO public key
 *  \param  in      pointer to the input to sign
 *  \param  inlen   length of the input
 *  \param  valid   0 if signature is valid and 1 otherwise
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_BatchVer(OSLO_PK pk, u8 *in, u32 inlen, bool *valid);
