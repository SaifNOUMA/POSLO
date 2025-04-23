
#pragma once
#include <openssl/aes.h>
#include "util.hpp"

/** Traverse the OSLO Tree-based structure from a source node to a destination node
 *  \param  src_ptr     pointer to the source node
 *  \param  src_height  Height of the source node in the OSLOT structure
 *  \param  src_index   Index of the source node in the OSLOT structure
 *  \param  dst_ptr     Pointer to the source node
 *  \param  dst_height  Height of the source node in the OSLOT structure
 *  \param  dst_index   Index of the source node in the OSLOT structure
 *  \param  dst_index   Index of the source node in the OSLOT structure
 *  \param  oslot_st    OSLOT state containing the root value, depth, and height
 * AES-128 Davies Mayes Construction 
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS OSLOT_SC(u8 *src_value, u32 src_height, u32 src_index,
                         u8 *dst_value, u32 dst_height, u32 dst_index,
                         OSLOT_STATE oslot_st);

/** Return a logarithmic-size set of disclosed seeds for a given leaf index
 *  \param  root_ptr    Pointer to the OSLOT root node
 *  \param  leaf_index  index of the desired leaf node in the OSLOT structure
 *  \param  oslot_ds    Disclosed seeds
 *  \param  oslot_st    OSLOT state containing the root value, depth, and height
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS OSLOT_SSO(u8 *root_ptr, u32 leaf_index, OSLOT_DS *oslot_ds, OSLOT_STATE oslot_st);

/** Retrieve a OSLOT node from the set of disclosed seeds
 *  \param  node_ptr    Pointer to the computed node
 *  \param  node_height Height of the source node in the OSLOT structure
 *  \param  node_index  Index of the desired leaf node in the OSLOT structure
 *  \param  oslot_ds    Disclosed seeds
 *  \param  oslot_st    OSLOT state containing the root value, depth, and height
 *  \return ECCRYPTO_SUCCESS on success and ECCRYPTO_ERROR otherwise
 */
ECCRYPTO_STATUS OSLOT_SR(u8 *node_ptr, u32 node_height, u32 node_index,
                         OSLOT_DS oslot_ds, OSLOT_STATE oslot_st);
