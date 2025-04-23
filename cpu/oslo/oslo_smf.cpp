
#include <bitset>
#include "oslo_smf.hpp"

ECCRYPTO_STATUS OSLOT_SC(u8 *src_ptr, u32 src_height, u32 src_index,
                         u8 *dst_ptr, u32 dst_height, u32 dst_index,
                         OSLOT_STATE oslot_st)
{
    u8 curr_ptr[SEED_SIZE];
    u32 local_height, local_index, local_leaves;

    local_height = dst_height - src_height;
    local_leaves = 1 << local_height;
    local_index  = dst_index - (src_index - 1) * local_leaves;

    // check if the source and destination nodes are in the same height in OSLOT
    if (src_height == dst_height) {
        if (src_index == dst_index) {
            memcpy(dst_ptr, src_ptr, SEED_SIZE);
            return ECCRYPTO_SUCCESS;
        } else {
            return ECCRYPTO_ERROR;
        }
    }

    memcpy(curr_ptr, src_ptr, SEED_SIZE);
    
    for (u32 depth = 1 ; depth <= local_height ; depth++) {
        local_leaves /= 2;

        bool isLeftChild = (local_index < local_leaves) ? 1 : 0;

        if (compute_seed(curr_ptr, SEED_SIZE, curr_ptr, oslot_st, isLeftChild) != ECCRYPTO_SUCCESS) {
            return ECCRYPTO_ERROR;
        }
    }

    memcpy(dst_ptr, curr_ptr, SEED_SIZE);
    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS OSLOT_SSO(u8 *root_ptr, u32 leaf_index, OSLOT_DS *oslot_ds, OSLOT_STATE oslot_st)
{
    Key             k;
    Value           v;
    u8              hashed_seed[SEED_SIZE];
    u32             displacement = 0;
    OSLOT_DS        oslot_ds_tmp;
    std::bitset<30> leaf_bitset(leaf_index);

    for (int index = oslot_st.n1 ; index >= 0 ; index--) {
        if (leaf_bitset[index]) {
            k.start     = displacement + 1;
            k.end       = displacement + (1 << index);
            v.height    = oslot_st.n1 - index;
            v.index     = (displacement / (1 << index)) + 1;
            if (OSLOT_SC(root_ptr, 0, 1, hashed_seed, v.height, v.index, oslot_st) != ECCRYPTO_SUCCESS) {
                return ECCRYPTO_ERROR;
            }
            memcpy(v.parent_node, hashed_seed, SEED_SIZE);
            oslot_ds_tmp.insert( { k , v } );
            displacement += (1 << index);
        }
    }

    *oslot_ds = oslot_ds_tmp;
    return ECCRYPTO_SUCCESS;
}

ECCRYPTO_STATUS OSLOT_SR(u8 *node_ptr, u32 node_height, u32 node_index,
                         OSLOT_DS oslot_ds, OSLOT_STATE oslot_st)
{
    Key k;
    Value v;
    u8 xi[SEED_SIZE];

    for ( const auto& it : oslot_ds) {
        k = it.first;
        v = it.second;
        if (k.start <= node_index && k.end >= node_index) {
            if (ECCRYPTO_ERROR == OSLOT_SC(v.parent_node, v.height, v.index, xi, node_height, node_index, oslot_st)) {
                return ECCRYPTO_ERROR;
            }
            break;
        }
    }
    memcpy(node_ptr, xi, SEED_SIZE);

    return ECCRYPTO_SUCCESS;
}
