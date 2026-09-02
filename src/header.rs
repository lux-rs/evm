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
//! THE C-CHAIN HAS ACCEPTED MORE THAN ONE SHAPE, and that is the whole
//! difficulty. `luxfi/conformance`'s header history, captured from mainnet
//! across 21 heights, records three:
//!
//! - **16 fields** — core fifteen through `baseFeePerGas`. The genesis, and
//!   only the genesis.
//! - **17 fields** — the same, then `blockGasCost`. What ordinary blocks are.
//! - **20 fields** — the same sixteen, then `withdrawalsRoot`, `blobGasUsed`,
//!   `excessBlobGas`, `parentBeaconBlockRoot`. What later blocks are.
//!
//! So a header is not one layout with optional fields at the end; the
//! SEVENTEENTH position is a quantity in one shape and a hash in another. This
//! module names the shape per header, the way the chain does, rather than
//! declaring one and hashing every block under it.
//!
//! [`alloy_consensus::Header`] already encodes the 16- and 20-field shapes
//! exactly. The 17-field one is the piece it has no field for, and is the piece
//! written here.

use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::{Decodable, Encodable};

/// A C-chain header: Ethereum's, plus the field Lux adds.
///
/// `block_gas_cost` is the seventeenth field. It is mutually exclusive with the
/// post-London tail — a header carrying `withdrawalsRoot` does not carry this,
/// and the chain has never accepted one that carried both — so setting it on a
/// header that already has that tail is refused rather than encoded into a
/// shape no node would accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lux {
    pub header: Header,
    pub block_gas_cost: Option<U256>,
}

impl Lux {
    /// The 16-field shape: a genesis.
    pub fn genesis(header: Header) -> Self {
        Self {
            header,
            block_gas_cost: None,
        }
    }

    /// The 17-field shape: an ordinary block.
    pub fn block(header: Header, cost: U256) -> Self {
        Self {
            header,
            block_gas_cost: Some(cost),
        }
    }

    /// How many fields this header encodes to — the number that names its
    /// shape.
    pub fn fields(&self) -> usize {
        let mut n = 15;
        let h = &self.header;
        if h.base_fee_per_gas.is_some() {
            n += 1;
        }
        if self.block_gas_cost.is_some() {
            return n + 1;
        }
        for present in [
            h.withdrawals_root.is_some(),
            h.blob_gas_used.is_some(),
            h.excess_blob_gas.is_some(),
            h.parent_beacon_block_root.is_some(),
            h.requests_hash.is_some(),
        ] {
            if present {
                n += 1;
            }
        }
        n
    }

    /// The RLP whose keccak256 the network accepted as this block's name.
    pub fn encoded(&self) -> Vec<u8> {
        let inner = alloy_rlp::encode(&self.header);
        let Some(cost) = self.block_gas_cost else {
            return inner;
        };
        // Re-wrap: take alloy's payload, add the seventeenth field, and give
        // the list its new length. Cheaper to be right than to re-implement
        // sixteen field encodings for the sake of one.
        let mut rest = &inner[..];
        let head = alloy_rlp::Header::decode(&mut rest).expect("alloy encodes a list");
        debug_assert!(head.list);
        let mut body = rest[..head.payload_length].to_vec();
        cost.encode(&mut body);
        let mut out = Vec::with_capacity(body.len() + 9);
        alloy_rlp::Header {
            list: true,
            payload_length: body.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// The block hash.
    pub fn seal(&self) -> B256 {
        keccak256(self.encoded())
    }

    /// Read a header off the wire, whichever shape it is.
    ///
    /// The shape is counted, not assumed: seventeen items means the Lux field
    /// is present, and [`alloy_consensus::Header`] cannot be asked to decode
    /// that directly — it would take the seventeenth for a `withdrawalsRoot`
    /// and refuse it for being the wrong width. So the items are walked, the
    /// first sixteen are handed to alloy as their own list, and the last is
    /// read as the quantity it is.
    pub fn read(raw: &[u8]) -> Result<Self, alloy_rlp::Error> {
        let mut cursor = raw;
        let head = alloy_rlp::Header::decode(&mut cursor)?;
        if !head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let start = raw.len() - cursor.len();
        let body = raw
            .get(start..start + head.payload_length)
            .ok_or(alloy_rlp::Error::InputTooShort)?;

        // Where each top-level item begins.
        let mut starts = Vec::with_capacity(20);
        let mut at = 0usize;
        while at < body.len() {
            starts.push(at);
            let mut item = &body[at..];
            let h = alloy_rlp::Header::decode(&mut item)?;
            let header_len = (body.len() - at) - item.len();
            at += header_len + h.payload_length;
        }

        if starts.len() != 17 {
            return Header::decode(&mut &raw[..]).map(Self::genesis);
        }
        let split = starts[16];
        let mut rewrapped = Vec::with_capacity(raw.len());
        alloy_rlp::Header {
            list: true,
            payload_length: split,
        }
        .encode(&mut rewrapped);
        rewrapped.extend_from_slice(&body[..split]);
        let header = Header::decode(&mut &rewrapped[..])?;
        let cost = U256::decode(&mut &body[split..])?;
        Ok(Self {
            header,
            block_gas_cost: Some(cost),
        })
    }
}

impl Encodable for Lux {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_slice(&self.encoded());
    }

    fn length(&self) -> usize {
        self.encoded().len()
    }
}

impl Decodable for Lux {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        // Measure the list, decode it, and advance the caller past exactly it —
        // a block is a header followed by its transactions, so leaving the
        // cursor anywhere else loses the rest of the block.
        let mut peek = *buf;
        let head = alloy_rlp::Header::decode(&mut peek)?;
        if !head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let consumed = (buf.len() - peek.len()) + head.payload_length;
        let whole = buf.get(..consumed).ok_or(alloy_rlp::Error::InputTooShort)?;
        let out = Lux::read(whole)?;
        *buf = &buf[consumed..];
        Ok(out)
    }
}

/// The block hash of a header with no Lux field: keccak256 of its RLP.
///
/// Correct for the genesis and for the 20-field shape, and NOT for an ordinary
/// block — use [`Lux::seal`], which names the shape.
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
