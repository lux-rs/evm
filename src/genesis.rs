// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! Block zero: the state a chain starts from, and the block that names it.
//!
//! A genesis is data, not code. The C-chain's is a JSON document the Go node is
//! started with, and every field of the header it produces is either copied
//! from that document or derived from the allocation — so the only thing this
//! module can get wrong is the derivation, which is exactly what its tests
//! check against the live network's answer.
//!
//! The check is worth stating plainly, because it is the one that says the
//! state layer is real: a Lux node on network 36963 reports the genesis
//! `stateRoot` as `0xe66e9ed3…`. That number is a Merkle-Patricia root over
//! four accounts, one of which has code. If [`World`](crate::state::World)
//! hashed accounts any other way — a digest over a sorted list, a serialised
//! struct, a root that ignored the code hash — it would produce a different
//! number and the node would have forked before it produced a block.

use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use revm::bytecode::Bytecode;
use revm::primitives::{StorageKey, StorageValue};

use crate::header;
use crate::root;
use crate::state::{Account, World};

/// One account the chain begins with.
#[derive(Clone, Debug, Default)]
pub struct Alloc {
    pub balance: U256,
    pub nonce: u64,
    pub code: Bytes,
    pub storage: Vec<(StorageKey, StorageValue)>,
}

impl Alloc {
    /// A balance and nothing else — what most genesis entries are.
    pub fn funded(balance: U256) -> Self {
        Self {
            balance,
            ..Default::default()
        }
    }

    /// An account that starts with code, like the C-chain's `0x02…05`.
    pub fn contract(balance: U256, nonce: u64, code: impl Into<Bytes>) -> Self {
        Self {
            balance,
            nonce,
            code: code.into(),
            storage: Vec::new(),
        }
    }
}

/// The document a chain starts from.
///
/// The field names are the genesis JSON's, so a reader holding the file can
/// check them off one at a time.
#[derive(Clone, Debug)]
pub struct Genesis {
    pub chain_id: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub difficulty: U256,
    pub base_fee: u64,
    pub coinbase: Address,
    pub extra_data: Bytes,
    pub mix_hash: B256,
    pub nonce: u64,
    pub alloc: Vec<(Address, Alloc)>,
}

impl Genesis {
    /// The world the allocation describes.
    pub fn world(&self) -> World {
        let mut w = World::new();
        for (who, entry) in &self.alloc {
            let code = Bytecode::new_raw(entry.code.clone());
            let code_hash = if entry.code.is_empty() {
                Account::default().code_hash
            } else {
                code.hash_slow()
            };
            let account = Account {
                nonce: entry.nonce,
                balance: entry.balance,
                code_hash,
                storage: entry.storage.iter().copied().collect(),
            };
            w.insert(*who, account, (!entry.code.is_empty()).then_some(code));
        }
        w
    }

    /// Block zero's header.
    ///
    /// Every field is the document's except `stateRoot`, which is the
    /// allocation's root — the one thing here that is computed rather than
    /// copied, and therefore the one thing that can disagree with Go.
    pub fn header(&self) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: self.coinbase,
            state_root: self.world().root(),
            transactions_root: root::EMPTY,
            receipts_root: root::EMPTY,
            logs_bloom: Bloom::ZERO,
            difficulty: self.difficulty,
            number: 0,
            gas_limit: self.gas_limit,
            gas_used: 0,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            mix_hash: self.mix_hash,
            nonce: B64::from(self.nonce),
            base_fee_per_gas: Some(self.base_fee),
            // `skipPostMergeFields` in the C-chain genesis: London's sixteen
            // fields and nothing after them, whatever later forks are active.
            ..Default::default()
        }
    }

    /// The hash the network calls block zero.
    pub fn hash(&self) -> B256 {
        header::seal(&self.header())
    }
}

/// The C-chain of Lux network 36963, as a live node is started with it.
///
/// Read out of the genesis document that node runs, so this is a transcription
/// rather than a design. Every value here is checkable against
/// `eth_getBlockByNumber("0x0")` on a running node, and the tests check them.
pub fn lux() -> Genesis {
    // `0x02…05` is the warp precompile's account: one byte of code, so it is
    // not an empty account and does not fall out of the trie under EIP-161.
    const WARP: Address = Address::new([
        0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
    ]);

    Genesis {
        chain_id: 36963,
        timestamp: 0,
        gas_limit: 0xb71b00,
        difficulty: U256::ZERO,
        base_fee: 25_000_000_000,
        coinbase: Address::ZERO,
        extra_data: Bytes::new(),
        mix_hash: B256::ZERO,
        nonce: 0,
        alloc: vec![
            (WARP, Alloc::contract(U256::ZERO, 1, Bytes::from_static(&[0x01]))),
            (
                Address::new(hex_address("703D4227d58d0b6A20BD721c940CED170470f634")),
                Alloc::funded(u256_hex("d3c21bcecceda1000000")),
            ),
            (
                Address::new(hex_address("778237fd03e9b59f1803c87117a7b1cfbd7fc60e")),
                Alloc::funded(u256_hex("3635c9adc5dea00000")),
            ),
            (
                Address::new(hex_address("9011E888251AB053B7bD1cdB598Db4f9DEd94714")),
                Alloc::funded(u256_hex("de24aac7eb3e705b4e0000000")),
            ),
        ],
    }
}

/// A 20-byte address from its hex digits, at compile time in spirit and at
/// startup in fact. Panics on a malformed literal, which is a bug in this file
/// and not a runtime condition.
fn hex_address(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    let raw = alloy_primitives::hex::decode(s).expect("address literal is hex");
    assert_eq!(raw.len(), 20, "address literal is 20 bytes");
    out.copy_from_slice(&raw);
    out
}

fn u256_hex(s: &str) -> U256 {
    U256::from_str_radix(s, 16).expect("balance literal is hex")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    /// What a live Lux node on network 36963 reports for block zero. Captured
    /// from `eth_getBlockByNumber("0x0")`; the same values are in the
    /// `luxfi/conformance` corpus.
    const STATE_ROOT: B256 =
        b256!("e66e9ed33175518345f38838fdc70ba71cd4df8090eb2625ca298eb1b779449e");
    const HASH: B256 = b256!("b4a9545d78d14a5582f390db08112752637243b9e76d594dea51a34d8bc79dc1");

    #[test]
    fn the_allocation_hashes_to_the_root_the_network_reports() {
        // The whole state layer in one number. Four accounts, one with code,
        // hashed as a Merkle-Patricia trie over keccak(address) — and if any
        // part of that is wrong this is a different number.
        assert_eq!(lux().world().root(), STATE_ROOT);
    }

    #[test]
    fn the_genesis_block_has_the_name_the_network_calls_it() {
        assert_eq!(lux().hash(), HASH);
    }

    #[test]
    fn the_genesis_header_is_the_london_shape() {
        assert!(header::is_london(&lux().header()));
    }

    #[test]
    fn the_allocation_is_four_accounts_and_the_warp_account_has_code() {
        let w = lux().world();
        assert_eq!(w.len(), 4);
        let warp = Address::new([
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
        ]);
        assert_eq!(w.nonce(&warp), 1);
        assert_ne!(
            w.get(&warp).expect("warp account").code_hash,
            Account::default().code_hash,
            "an account with code does not hash to the empty code hash"
        );
    }

    #[test]
    fn dropping_the_code_changes_the_root() {
        // Proof the code hash is load-bearing rather than decoration: the same
        // four accounts with the warp account's code removed is a different
        // state, and a node that ignored code would report this instead.
        let mut g = lux();
        g.alloc[0].1.code = Bytes::new();
        assert_ne!(g.world().root(), STATE_ROOT);
    }
}
