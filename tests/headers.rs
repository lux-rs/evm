// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! Every header shape the C-chain has accepted, against the headers it accepted.
//!
//! `luxfi/conformance` captured 21 heights from mainnet, each recording the RLP
//! whose keccak256 is the hash the network took. That is the strongest test
//! available for a naming function: not "does this agree with itself" but "does
//! this produce the name a live chain already gave the block".
//!
//! The corpus notes something worth repeating: of luxfi/geth's five header hash
//! functions, none reproduces every block, and block 1 is reproduced by none of
//! them. The accepted hash is keccak of the recorded RLP, and that is what is
//! checked here.

mod corpus;

use alloy_primitives::{hex, B256, U256};
use corpus::{bytes, get as corpus, hash};
use lux_evm::header::{self, Lux};
use serde_json::Value;

/// The header history, as the node served it. Each entry carries the RLP whose
/// keccak256 the network accepted, and nothing else is needed: the header is
/// read back out of those bytes.
fn history() -> Vec<Value> {
    corpus("evm_header_history.json")["blocks"]
        .as_array()
        .expect("the corpus records blocks")
        .clone()
}

fn at(b: &Value, field: &str) -> u64 {
    b[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} is not a number in the corpus"))
}

fn rlp_of(b: &Value) -> Vec<u8> {
    bytes(b, "rlp")
}

#[test]
fn every_accepted_header_encodes_to_the_bytes_the_network_accepted() {
    // Byte-identity is the stronger claim: two encoders can hash the same only
    // by hashing the same bytes, and when they diverge this says where.
    let blocks = history();
    assert_eq!(blocks.len(), 21, "the corpus is 21 heights");
    for b in &blocks {
        let want = rlp_of(b);
        let got = Lux::read(&want)
            .unwrap_or_else(|e| panic!("block {} does not decode: {e:?}", at(b, "number")))
            .encoded();
        assert_eq!(
            hex::encode(&got),
            hex::encode(&want),
            "block {} ({}) does not survive its own encoding",
            at(b, "number"),
            b["shape"].as_str().unwrap_or("?")
        );
    }
}

#[test]
fn every_accepted_header_is_named_what_the_network_named_it() {
    for b in &history() {
        assert_eq!(
            Lux::read(&rlp_of(b)).expect("decodes").seal(),
            hash(b, "hash"),
            "block {} is named something else",
            at(b, "number")
        );
    }
}

#[test]
fn the_shape_is_read_off_the_header_not_declared_once() {
    // Three shapes, and the seventeenth field is a quantity in one and a hash
    // in another. A node that declared one layout would hash two of the three
    // wrongly.
    let mut seen = std::collections::BTreeSet::new();
    for b in &history() {
        let h = Lux::read(&rlp_of(b)).expect("decodes");
        assert_eq!(
            h.fields(),
            at(b, "fields") as usize,
            "block {} field count",
            at(b, "number")
        );
        seen.insert(b["shape"].as_str().unwrap_or("?").to_string());
    }
    assert_eq!(seen.len(), 3, "the corpus carries three shapes: {seen:?}");
}

#[test]
fn the_genesis_is_the_only_sixteen_field_block() {
    for b in &history() {
        let n = at(b, "number");
        let fields = at(b, "fields");
        if n == 0 {
            assert_eq!(fields, 16);
        } else {
            assert!(fields > 16, "block {n} has {fields} fields");
        }
    }
}

#[test]
fn dropping_the_lux_field_renames_an_ordinary_block() {
    // The reason this module exists. A 17-field block hashed under the 16-field
    // shape — which is what hashing the plain header does — is a different
    // name, and a node producing it has forked at block one.
    let blocks = history();
    let one = blocks
        .iter()
        .find(|b| at(b, "number") == 1)
        .expect("block 1");
    let lux = Lux::read(&rlp_of(one)).expect("decodes");
    assert!(lux.block_gas_cost.is_some(), "block 1 carries blockGasCost");
    assert_eq!(lux.seal(), hash(one, "hash"));
    assert_ne!(
        header::seal(&lux.header),
        hash(one, "hash"),
        "the plain header hashes to a name the network never gave this block"
    );
}

#[test]
fn block_one_builds_on_the_genesis_this_crate_computes() {
    // Ties the header history to the genesis: the parent of block 1 is the
    // hash `lux_evm::genesis::mainnet()` produces from the allocation.
    let blocks = history();
    let one = blocks
        .iter()
        .find(|b| at(b, "number") == 1)
        .expect("block 1");
    assert_eq!(
        Lux::read(&rlp_of(one)).expect("decodes").header.parent_hash,
        lux_evm::genesis::mainnet().hash(),
        "the chain the corpus captured is the chain this crate describes"
    );
}

#[test]
fn a_header_that_is_only_a_genesis_shape_still_seals_the_old_way() {
    let g = lux_evm::genesis::mainnet();
    assert_eq!(Lux::genesis(g.header()).seal(), g.hash());
    assert_eq!(Lux::genesis(g.header()).fields(), 16);
    assert_ne!(
        Lux::block(g.header(), U256::ZERO).seal(),
        g.hash(),
        "adding the field renames the block"
    );
}

#[test]
fn the_seventeenth_field_is_a_quantity_and_the_twentieth_shape_has_none() {
    let blocks = history();
    for b in &blocks {
        let h = Lux::read(&rlp_of(b)).expect("decodes");
        let shape = b["shape"].as_str().unwrap_or("");
        if shape.contains("blockGasCost") {
            assert!(h.block_gas_cost.is_some(), "block {}", at(b, "number"));
            assert!(h.header.withdrawals_root.is_none());
        }
        if shape.contains("withdrawalsRoot") {
            assert!(h.block_gas_cost.is_none(), "the two shapes are exclusive");
            assert!(h.header.withdrawals_root.is_some());
        }
    }
    let _ = B256::ZERO;
}
