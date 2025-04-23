
#pragma once

#include "oslo_sgn.hpp"

/** 
 * Add the SOCOSLO signature to the aggregate signature value in the public 
 * 
 * if it is valid or add it to the list of failed items
 *  \param  inlen   length of the input
 *  \param  oslo_l1 number of epochs in the signature generation
 *  \param  oslo_l2 number of iterations within the epoch
 *  \param  path2log   path to the log file
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS SOCOSLO_sgn_test(u8 *data, u32 inlen, OSLOT_STATE oslot_st);
