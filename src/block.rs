// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! Executing a block.
//!
//! One primitive and two compositions, because building a block and verifying
//! one are the same work read in opposite directions:
//!
//! - [`apply`] runs ONE transaction against the world and commits it. It is the
//!   only thing here that touches the interpreter.
//! - [`execute`] runs a list of them strictly — the first invalid transaction
//!   ends the block, because a block containing one is not a block.
//! - a proposer composes [`apply`] itself, dropping what it cannot include.
//!
//! Writing the strict path as a flag on the permissive one would mean a
//! verifier and a proposer that disagree are still one function; keeping them
//! as two compositions of one primitive means the thing they share is the
//! thing that matters — the execution — and the thing they differ on is stated
//! where it happens.
//!
//! WHAT A BLOCK COMMITS TO. Every root in the header produced here is computed
//! from what actually ran: the state root is the world's trie after the last
//! transaction, the receipts root is over receipts carrying the real cumulative
//! gas, and the transactions root is over the same 2718 bytes the network
//! gossiped. None of them is carried in from the caller.

use alloy_consensus::{
    Eip658Value, Header, Receipt, ReceiptEnvelope, Transaction as _, TxEnvelope, TxType,
    EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bloom, Bytes, Log, B256, B64, U256};
use revm::context::result::{EVMError, ExecutionResult};
use revm::context::{Context, ContextSetters, ContextTr, Evm, TxEnv};
use revm::context_interface::JournalTr;
use revm::handler::instructions::EthInstructions;
use revm::handler::Handler as _;
use revm::primitives::hardfork::SpecId;
use revm::{DatabaseCommit as _, MainContext};

use crate::header;
use crate::root;
use crate::rules::Chain;
use crate::state::World;
use crate::{Handler, Precompiles, Profile};

/// What a block is executed under: the proposer's choices, plus the chain's.
#[derive(Clone, Debug)]
pub struct Env {
    /// When each Lux rule turns on.
    pub chain: Chain,
    /// EIP-155's chain id. Genesis data, not a constant — the C-chain of one
    /// Lux network is not the C-chain of another, and a node that hard-codes
    /// this replays every transaction onto whichever network it was compiled
    /// for.
    pub chain_id: u64,
    pub spec: SpecId,
    /// Which precompiles are admitted.
    pub profile: Profile,
    pub beneficiary: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub mix_hash: B256,
}

impl Env {
    /// The environment a Lux C-chain block is executed under.
    pub fn lux(chain_id: u64, base_fee: u64, gas_limit: u64) -> Self {
        Self {
            chain: Chain::lux(),
            chain_id,
            spec: SpecId::SHANGHAI,
            profile: Profile::default(),
            beneficiary: Address::ZERO,
            timestamp: 0,
            gas_limit,
            base_fee,
            difficulty: U256::ZERO,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
        }
    }
}

/// Why a transaction cannot be in a block.
///
/// A transaction that runs and reverts is NOT here: it consumed gas, it has a
/// receipt, and it belongs in the block. This is only the transactions that
/// cannot be executed at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The signature does not recover to an address.
    Signature,
    /// Signed for a different chain.
    ChainId { want: u64, got: u64 },
    /// The block has no room left.
    GasLimit { used: u64, limit: u64 },
    /// revm refused it: wrong nonce, too poor, fee below base.
    Rejected(String),
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Invalid::Signature => write!(f, "signature does not recover"),
            Invalid::ChainId { want, got } => write!(f, "chain id {got}, expected {want}"),
            Invalid::GasLimit { used, limit } => {
                write!(f, "gas {used} over the block limit {limit}")
            }
            Invalid::Rejected(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Invalid {}

/// What one transaction did.
#[derive(Clone, Debug)]
pub struct Applied {
    pub receipt: ReceiptEnvelope,
    /// Gas this transaction alone used.
    pub gas_used: u64,
    pub success: bool,
    pub output: Bytes,
    /// The address a deployment created.
    pub created: Option<Address>,
}

/// Run one transaction against `world` and commit what it did.
///
/// `cumulative` is the gas the block has already used, because a receipt states
/// the running total rather than its own transaction's share.
///
/// The world is only written if the transaction was executable: a rejected
/// transaction leaves no trace, which is what lets a proposer try one and move
/// on.
pub fn apply(
    world: &mut World,
    env: &Env,
    cumulative: u64,
    tx: &TxEnvelope,
    sender: Address,
) -> Result<Applied, Invalid> {
    if let Some(id) = tx.chain_id() {
        if id != env.chain_id {
            return Err(Invalid::ChainId {
                want: env.chain_id,
                got: id,
            });
        }
    }

    let txenv = to_revm(tx, sender);
    let spec = env.spec;

    // The context borrows the world for exactly this transaction. Access lists
    // and warm slots are per-transaction state and are meant to be dropped
    // here; what carries between transactions is committed state, which lives
    // in the world.
    let (result, state) = {
        let ctx = Context::mainnet()
            .with_db(&mut *world)
            .modify_cfg_chained(|c| {
                c.spec = spec;
                c.chain_id = env.chain_id;
            })
            .modify_block_chained(|b| {
                b.beneficiary = env.beneficiary;
                b.timestamp = U256::from(env.timestamp);
                b.basefee = env.base_fee;
                b.gas_limit = env.gas_limit;
                b.difficulty = env.difficulty;
                b.prevrandao = Some(env.mix_hash);
            });
        let mut evm = Evm::new(
            ctx,
            EthInstructions::new_mainnet_with_spec(spec),
            Precompiles::new(spec, env.profile),
        );
        evm.ctx.set_tx(txenv);

        let mut handler: Handler<_, EVMError<core::convert::Infallible>, _> =
            Handler::new(env.chain);
        let result: ExecutionResult = handler
            .run(&mut evm)
            .map_err(|e| Invalid::Rejected(format!("{e:?}")))?;
        let state = evm.ctx.journal_mut().finalize();
        (result, state)
    };

    let gas_used = result.gas_used();
    if cumulative.saturating_add(gas_used) > env.gas_limit {
        // Refused after running, because whether it fits is only known once the
        // gas is known. Nothing was committed, so the world is untouched.
        return Err(Invalid::GasLimit {
            used: cumulative + gas_used,
            limit: env.gas_limit,
        });
    }

    world.commit(state);

    let created = match &result {
        ExecutionResult::Success { output, .. } => output.address().copied(),
        _ => None,
    };
    let success = result.is_success();
    let logs: Vec<Log> = result.logs().to_vec();
    let output = result.clone().into_output().unwrap_or_default();

    let receipt = Receipt {
        status: Eip658Value::Eip658(success),
        cumulative_gas_used: cumulative + gas_used,
        logs,
    };
    Ok(Applied {
        receipt: envelope(tx.tx_type(), receipt),
        gas_used,
        success,
        output,
        created,
    })
}

/// A block, and everything needed to serve it.
#[derive(Clone, Debug)]
pub struct Built {
    pub header: Header,
    pub transactions: Vec<TxEnvelope>,
    pub receipts: Vec<ReceiptEnvelope>,
}

impl Built {
    /// The block's hash: keccak of its header's RLP, and nothing else.
    pub fn hash(&self) -> B256 {
        header::seal(&self.header)
    }
}

/// Execute a whole block strictly: every transaction must be executable.
///
/// This is the verifier's composition. A proposer wants the permissive one and
/// writes it out of [`apply`] directly, because "skip what does not fit" is a
/// policy about a mempool and not a property of execution.
pub fn execute(
    world: &mut World,
    parent: &Header,
    env: &Env,
    txs: Vec<(TxEnvelope, Address)>,
) -> Result<Built, Invalid> {
    let mut receipts = Vec::with_capacity(txs.len());
    let mut kept = Vec::with_capacity(txs.len());
    let mut cumulative = 0u64;

    for (tx, sender) in txs {
        let done = apply(world, env, cumulative, &tx, sender)?;
        cumulative += done.gas_used;
        receipts.push(done.receipt);
        kept.push(tx);
    }

    Ok(finish(world, parent, env, kept, receipts, cumulative))
}

/// Seal what ran into a header.
///
/// Separate from [`execute`] because a proposer reaches this point by a
/// different route and must arrive at the same header — one place that decides
/// what a block commits to means a proposer and a verifier cannot drift.
pub fn finish(
    world: &World,
    parent: &Header,
    env: &Env,
    transactions: Vec<TxEnvelope>,
    receipts: Vec<ReceiptEnvelope>,
    gas_used: u64,
) -> Built {
    let encoded: Vec<Vec<u8>> = transactions.iter().map(|t| t.encoded_2718()).collect();
    let receipts_encoded: Vec<Vec<u8>> = receipts.iter().map(|r| r.encoded_2718()).collect();
    let logs_bloom = receipts
        .iter()
        .fold(Bloom::ZERO, |acc, r| acc | bloom_of(r));

    let header = Header {
        parent_hash: header::seal(parent),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: env.beneficiary,
        state_root: world.root(),
        transactions_root: root::transactions(&encoded),
        receipts_root: root::receipts(&receipts_encoded),
        logs_bloom,
        difficulty: env.difficulty,
        number: parent.number + 1,
        gas_limit: env.gas_limit,
        gas_used,
        timestamp: env.timestamp,
        extra_data: env.extra_data.clone(),
        mix_hash: env.mix_hash,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(env.base_fee),
        // London's field set, like the genesis: the C-chain seals sixteen
        // fields whatever later forks are active.
        ..Default::default()
    };
    Built {
        header,
        transactions,
        receipts,
    }
}

/// The bloom a receipt carries.
fn bloom_of(r: &ReceiptEnvelope) -> Bloom {
    match r {
        ReceiptEnvelope::Legacy(r)
        | ReceiptEnvelope::Eip2930(r)
        | ReceiptEnvelope::Eip1559(r)
        | ReceiptEnvelope::Eip4844(r)
        | ReceiptEnvelope::Eip7702(r) => r.logs_bloom,
    }
}

/// Wrap a receipt in the envelope its transaction type calls for. The type flag
/// is part of what the receipts trie commits to, so a receipt filed under the
/// wrong one changes the root.
fn envelope(ty: TxType, receipt: Receipt) -> ReceiptEnvelope {
    let with_bloom = receipt.with_bloom();
    match ty {
        TxType::Legacy => ReceiptEnvelope::Legacy(with_bloom),
        TxType::Eip2930 => ReceiptEnvelope::Eip2930(with_bloom),
        TxType::Eip1559 => ReceiptEnvelope::Eip1559(with_bloom),
        TxType::Eip4844 => ReceiptEnvelope::Eip4844(with_bloom),
        TxType::Eip7702 => ReceiptEnvelope::Eip7702(with_bloom),
    }
}

/// A signed transaction as revm wants it stated.
fn to_revm(tx: &TxEnvelope, sender: Address) -> TxEnv {
    let mut builder = TxEnv::builder()
        .tx_type(Some(tx.tx_type() as u8))
        .caller(sender)
        .gas_limit(tx.gas_limit())
        .kind(tx.kind())
        .value(tx.value())
        .data(tx.input().clone())
        .nonce(tx.nonce())
        .chain_id(tx.chain_id())
        .gas_price(tx.max_fee_per_gas())
        .gas_priority_fee(tx.max_priority_fee_per_gas());
    if let Some(list) = tx.access_list() {
        builder = builder.access_list(list.clone());
    }
    builder.build_fill()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
    use alloy_primitives::{address, keccak256, Signature, TxKind};
    use k256::ecdsa::SigningKey;

    const TO: Address = address!("00000000000000000000000000000000000000ff");

    /// The test account's key. Signing here rather than reaching for a signer
    /// crate: secp256k1 is already in the tree under alloy's `k256` feature,
    /// and a second one would be a second curve implementation.
    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).expect("key")
    }

    /// The address a key controls: keccak of the uncompressed public key
    /// without its tag byte, last twenty bytes.
    fn who() -> Address {
        let vk = key().verifying_key().to_encoded_point(false);
        Address::from_slice(&keccak256(&vk.as_bytes()[1..])[12..])
    }

    /// Sign a transaction's signature hash.
    fn sign(hash: B256) -> Signature {
        let (sig, recid) = key()
            .sign_prehash_recoverable(hash.as_slice())
            .expect("sign");
        Signature::new(
            U256::from_be_slice(&sig.r().to_bytes()),
            U256::from_be_slice(&sig.s().to_bytes()),
            recid.is_y_odd(),
        )
    }

    /// A funded world, and the environment its blocks run under.
    fn chain() -> (World, Header, Env, Address) {
        let who = who();
        let g = genesis::Genesis {
            alloc: vec![(who, genesis::Alloc::funded(U256::from(10u64).pow(U256::from(21u64))))],
            ..genesis::lux()
        };
        let env = Env {
            beneficiary: address!("00000000000000000000000000000000000000c0"),
            ..Env::lux(g.chain_id, g.base_fee, g.gas_limit)
        };
        (g.world(), g.header(), env, who)
    }

    fn send(nonce: u64, chain_id: u64, value: U256) -> (TxEnvelope, Address) {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(TO),
            value,
            ..Default::default()
        };
        let sig = sign(tx.signature_hash());
        (TxEnvelope::Eip1559(tx.into_signed(sig)), who())
    }

    #[test]
    fn a_block_moves_value_and_the_state_root_with_it() {
        let (mut world, parent, env, who) = chain();
        let before = world.root();
        let value = U256::from(1_000u64);

        let built = execute(&mut world, &parent, &env, vec![send(0, env.chain_id, value)])
            .expect("the block executes");

        assert_eq!(built.header.number, 1);
        assert_eq!(built.header.parent_hash, header::seal(&parent));
        assert_eq!(world.balance(&TO), value, "the transfer landed");
        assert_eq!(world.nonce(&who), 1, "the sender's nonce advanced");
        assert_ne!(built.header.state_root, before, "the state moved");
        assert_eq!(
            built.header.state_root,
            world.root(),
            "the header commits to the world that actually resulted"
        );
        assert_eq!(built.header.gas_used, 21_000);
    }

    #[test]
    fn the_roots_are_over_what_ran_not_over_nothing() {
        let (mut world, parent, env, _) = chain();
        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::from(1u64))],
        )
        .expect("executes");
        assert_ne!(built.header.transactions_root, root::EMPTY);
        assert_ne!(built.header.receipts_root, root::EMPTY);
        assert_eq!(built.receipts.len(), 1);
    }

    #[test]
    fn an_empty_block_still_advances_and_keeps_the_empty_roots() {
        let (mut world, parent, env, _) = chain();
        let built = execute(&mut world, &parent, &env, vec![]).expect("executes");
        assert_eq!(built.header.number, 1);
        assert_eq!(built.header.gas_used, 0);
        assert_eq!(built.header.transactions_root, root::EMPTY);
        assert_eq!(built.header.receipts_root, root::EMPTY);
        assert_eq!(
            built.header.state_root, parent.state_root,
            "nothing ran, so nothing changed"
        );
    }

    #[test]
    fn a_transaction_for_another_chain_is_not_in_this_one() {
        let (mut world, parent, env, _) = chain();
        let wrong = env.chain_id + 1;
        let refused = execute(&mut world, &parent, &env, vec![send(0, wrong, U256::ZERO)]);
        assert_eq!(
            refused.err(),
            Some(Invalid::ChainId {
                want: env.chain_id,
                got: wrong
            })
        );
    }

    #[test]
    fn a_repeated_nonce_is_refused_and_leaves_no_trace() {
        let (mut world, parent, env, _) = chain();
        let one = send(0, env.chain_id, U256::from(1u64));
        let done = apply(&mut world, &env, 0, &one.0, one.1).expect("first");
        assert!(done.success);
        let after = world.root();

        let replay = apply(&mut world, &env, done.gas_used, &one.0, one.1);
        assert!(matches!(replay, Err(Invalid::Rejected(_))), "{replay:?}");
        assert_eq!(world.root(), after, "a refused transaction changed nothing");
    }

    #[test]
    fn two_blocks_chain_onto_each_other() {
        let (mut world, genesis, env, _) = chain();
        let first = execute(
            &mut world,
            &genesis,
            &env,
            vec![send(0, env.chain_id, U256::from(1u64))],
        )
        .expect("first");
        let second = execute(
            &mut world,
            &first.header,
            &env,
            vec![send(1, env.chain_id, U256::from(1u64))],
        )
        .expect("second");

        assert_eq!(second.header.number, 2);
        assert_eq!(second.header.parent_hash, first.hash());
        assert_ne!(second.header.state_root, first.header.state_root);
        assert_eq!(world.balance(&TO), U256::from(2u64));
    }

    #[test]
    fn the_beneficiary_is_paid_the_whole_fee_under_lux_rules() {
        let (mut world, parent, env, _) = chain();
        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::ZERO)],
        )
        .expect("executes");
        // Lux credits gasUsed * effectiveGasPrice with nothing burned. The
        // effective price under a 25 gwei base fee and a 1 gwei tip is 26 gwei.
        let paid = world.balance(&env.beneficiary);
        assert_eq!(
            paid,
            U256::from(built.header.gas_used as u128 * 26_000_000_000u128)
        );
    }

    #[test]
    fn a_legacy_transaction_is_a_legacy_receipt() {
        let (mut world, _parent, env, _) = chain();
        let tx = TxLegacy {
            chain_id: Some(env.chain_id),
            nonce: 0,
            gas_price: 30_000_000_000,
            gas_limit: 100_000,
            to: TxKind::Call(TO),
            value: U256::from(5u64),
            ..Default::default()
        };
        let sig = sign(tx.signature_hash());
        let env_tx = TxEnvelope::Legacy(tx.into_signed(sig));
        let done = apply(&mut world, &env, 0, &env_tx, who()).expect("applies");
        assert!(matches!(done.receipt, ReceiptEnvelope::Legacy(_)));
        assert_eq!(world.balance(&TO), U256::from(5u64));
    }
}
