// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! What a block is called.
//!
//! A block hash is not a field a node reports; it is keccak256 of the RLP of
//! the header, and two implementations agree on it only if they agree on which
//! fields exist and in what order. A Rust node that hashes a serialised struct
//! — any struct, however faithful its contents — has invented a second name for
//! every block on the chain.
//!
//! The C-chain header ends at `baseFeePerGas`: sixteen fields, London's shape.
//! There is no `withdrawalsRoot`, no blob gas, no requests hash, and — the one
//! that surprises people — no `blockGasCost`, which the RPC reports but the
//! hash preimage does not contain. [`alloy_consensus::Header`] encodes exactly
//! this when the later fields are `None`, so there is nothing here to write but
//! the digest itself and the reason it is the digest.

use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256};

/// The block hash: keccak256 of the header's RLP.
pub fn seal(header: &Header) -> B256 {
    keccak256(alloy_rlp::encode(header))
}

/// Whether `header` has the shape the C-chain seals — London and no further.
///
/// Worth checking before trusting a hash: every field added after London is
/// optional in the encoding, so a header carrying one hashes differently while
/// still looking like a header.
pub fn is_london(header: &Header) -> bool {
    header.base_fee_per_gas.is_some()
        && header.withdrawals_root.is_none()
        && header.blob_gas_used.is_none()
        && header.excess_blob_gas.is_none()
        && header.parent_beacon_block_root.is_none()
        && header.requests_hash.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn london() -> Header {
        Header {
            base_fee_per_gas: Some(25_000_000_000),
            ..Default::default()
        }
    }

    #[test]
    fn the_shape_check_sees_a_post_london_field() {
        let h = london();
        assert!(is_london(&h));

        let mut shanghai = h.clone();
        shanghai.withdrawals_root = Some(B256::ZERO);
        assert!(!is_london(&shanghai));

        let mut cancun = h.clone();
        cancun.blob_gas_used = Some(0);
        assert!(!is_london(&cancun));
    }

    #[test]
    fn a_post_london_field_changes_the_name_of_the_block() {
        // The field set is not decoration: adding one renames every block. This
        // is why the shape check is worth having.
        let h = london();
        let mut shanghai = h.clone();
        shanghai.withdrawals_root = Some(B256::ZERO);
        assert_ne!(seal(&h), seal(&shanghai));
    }

    #[test]
    fn the_seal_is_the_hash_of_the_encoding_and_nothing_else() {
        let h = london();
        assert_eq!(seal(&h), keccak256(alloy_rlp::encode(&h)));
    }
}
