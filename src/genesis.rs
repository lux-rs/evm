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
//! state layer is real. `luxfi/genesis` records that the mainnet allocation
//! hashes to `0x2d1cedac…` and seals to `0x3f4fa2a0…`, and a node running on
//! this machine reports `0xe66e9ed3…` for the four-account network it was
//! started with. Both numbers come out of [`World`](crate::state::World)
//! unchanged. A root computed any other way — a digest over a sorted list, a
//! serialised struct, a root that ignored the code hash — is a different
//! number, and a node producing it forked before it produced a block.

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

    /// Block zero, in the sixteen-field shape only the genesis has.
    pub fn sealed(&self) -> header::Lux {
        header::Lux::genesis(self.header())
    }

    /// The hash the network calls block zero.
    pub fn hash(&self) -> B256 {
        self.sealed().seal()
    }
}

/// The warp precompile's account. One byte of code, so it is not an empty
/// account and does not fall out of the trie under EIP-161.
const WARP: Address = Address::new([
    0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
]);

/// The two accounts every Lux network starts with.
fn lux_alloc() -> Vec<(Address, Alloc)> {
    vec![
        (WARP, Alloc::contract(U256::ZERO, 1, Bytes::from_static(&[0x01]))),
        (
            Address::new(hex_address("9011E888251AB053B7bD1cdB598Db4f9DEd94714")),
            Alloc::funded(u256_hex("193e5939a08ce9dbd480000000")),
        ),
    ]
}

/// The Lux C-chain, chain id 96369.
///
/// Transcribed from `luxfi/genesis@v1.16.19 configs/mainnet/cchain.json`, which
/// is the document the Go node is started with. That module also records what
/// the values are supposed to hash to, in `cchain.canonical.json`, and the
/// tests here check against those numbers rather than against ours.
pub fn mainnet() -> Genesis {
    Genesis {
        chain_id: 96369,
        timestamp: 0x672485c2,
        gas_limit: 0xb71b00,
        difficulty: U256::ZERO,
        base_fee: 25_000_000_000,
        coinbase: Address::ZERO,
        extra_data: Bytes::new(),
        mix_hash: B256::ZERO,
        nonce: 0,
        alloc: lux_alloc(),
    }
}

/// The Lux localnet C-chain, chain id 31337 — `0x7a69`.
///
/// `configs/localnet/cchain.json`. The chain id is the one a local development
/// network answers `eth_chainId` with, and it is NOT the mainnet id: a node
/// that compiles either one in is a node that cannot be pointed at the other.
pub fn localnet() -> Genesis {
    Genesis {
        chain_id: 31337,
        timestamp: 0x6a065656,
        gas_limit: 0xb71b00,
        difficulty: U256::ZERO,
        base_fee: 1_000_000_000,
        coinbase: Address::ZERO,
        extra_data: Bytes::new(),
        mix_hash: B256::ZERO,
        nonce: 0,
        alloc: lux_alloc(),
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

    /// What `luxfi/genesis configs/mainnet/cchain.canonical.json` records the
    /// mainnet genesis is. Not our number — the Go module's own.
    const MAINNET_STATE_ROOT: B256 =
        b256!("2d1cedac263020c5c56ef962f6abe0da1f5217bdc6468f8c9258a0ea23699e80");
    const MAINNET_HASH: B256 =
        b256!("3f4fa2a0b0ce089f52bf0ae9199c75ffdd76ecafc987794050cb0d286f1ec61e");

    #[test]
    fn the_mainnet_allocation_hashes_to_the_root_go_records() {
        // The whole state layer in one number: two accounts, one with code,
        // hashed as a Merkle-Patricia trie over keccak(address). Any other way
        // of hashing them — a digest over a sorted list, a serialised struct,
        // a root that ignores the code hash — is a different number and a
        // chain that forked at genesis.
        assert_eq!(mainnet().world().root(), MAINNET_STATE_ROOT);
    }

    #[test]
    fn the_mainnet_genesis_block_has_the_name_go_records() {
        assert_eq!(mainnet().hash(), MAINNET_HASH);
    }

    #[test]
    fn localnet_is_the_same_state_at_a_different_chain_id() {
        // The allocation is shared, so the state root is the same number; the
        // header is not, because the timestamp and base fee differ. This is
        // the check that says chain id lives in the config and not in the
        // state.
        assert_eq!(localnet().world().root(), MAINNET_STATE_ROOT);
        assert_ne!(localnet().hash(), MAINNET_HASH);
        assert_eq!(localnet().chain_id, 31337, "0x7a69");
        assert_eq!(mainnet().chain_id, 96369);
    }

    #[test]
    fn a_running_node_reports_the_root_this_code_computes() {
        // A sovereign L1 on this machine runs network 36963 with a four-account
        // allocation, and reports `stateRoot` 0xe66e9ed3… and block hash
        // 0xb4a9545d… over JSON-RPC. Reproducing a LIVE node's numbers is a
        // stronger claim than reproducing a file's: nothing here was copied
        // from an implementation that could be wrong the same way.
        let g = Genesis {
            chain_id: 36963,
            timestamp: 0,
            base_fee: 25_000_000_000,
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
            ..mainnet()
        };
        assert_eq!(
            g.world().root(),
            b256!("e66e9ed33175518345f38838fdc70ba71cd4df8090eb2625ca298eb1b779449e")
        );
        assert_eq!(
            g.hash(),
            b256!("b4a9545d78d14a5582f390db08112752637243b9e76d594dea51a34d8bc79dc1")
        );
    }

    #[test]
    fn the_genesis_header_is_the_london_shape() {
        assert!(header::is_london(&mainnet().header()));
    }

    #[test]
    fn the_warp_account_has_code_and_the_code_is_load_bearing() {
        let w = mainnet().world();
        assert_eq!(w.len(), 2);
        assert_eq!(w.nonce(&WARP), 1);
        assert_ne!(
            w.get(&WARP).expect("warp account").code_hash,
            Account::default().code_hash,
            "an account with code does not hash to the empty code hash"
        );

        // Proof the code hash is not decoration: drop it and the root moves.
        let mut g = mainnet();
        g.alloc[0].1.code = Bytes::new();
        assert_ne!(g.world().root(), MAINNET_STATE_ROOT);
    }
}
