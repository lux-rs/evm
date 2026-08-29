// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! The Lux EVM in Rust.
//!
//! Go is the network. `luxfi/geth` and `luxfi/evm` decide what a block means,
//! and this crate exists to arrive at the same answer from Rust — same gas,
//! same balances, same roots, same block hashes. Where the two could differ,
//! the Go source is cited in the module that reproduces it.
//!
//! It is built out of four things, and deliberately no more:
//!
//! - [`rules`] — the three rules that make Lux not Ethereum, as a value.
//! - [`handler`] — those rules in the two places revm asks about them.
//! - [`precompile`] — the stock precompiles behind the classical-family gate.
//! - [`header`] and [`root`] — how a block is named and what it commits to.
//!
//! revm is a dependency, not a fork. Three implementations of one protocol are
//! already two more than the protocol needs; a fourth interpreter, maintained
//! here, would be a fifth thing to keep in step. Everything Lux changes is
//! reachable through revm's own seams.
//!
//! ```
//! use lux_evm::{Chain, Precompiles, Profile};
//! use revm::primitives::hardfork::SpecId;
//!
//! // The C-chain: Lux gas accounting from genesis, classical precompiles
//! // admitted, London header shape.
//! let rules = Chain::lux().at(0);
//! assert!(!rules.refunds());
//! let _ = Precompiles::new(SpecId::SHANGHAI, Profile::default());
//! ```

pub mod handler;
pub mod header;
pub mod precompile;
pub mod root;
pub mod rules;

pub use handler::Handler;
pub use precompile::{Op, Precompiles, Profile};
pub use rules::{Chain, Rules};
