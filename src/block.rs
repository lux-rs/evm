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

use crate::fee;
use crate::header;
use crate::root;
use crate::rules::{Chain, WARP};
use crate::state::World;
use crate::{Handler, Precompiles, Profile};

/// What a block is executed under: the chain's configuration, and the values
/// its header carries — every one of which Go derives from the parent.
///
/// A chain's own is [`Genesis::env`](crate::Genesis::env); [`Env::next`] is the
/// one way to the environment of a block after it, and [`rule`] holds a block
/// someone else built to it.
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
    /// The fee schedule every header field below is derived under.
    pub fee: fee::Config,
    /// `allowFeeRecipients`: a builder may name its own coinbase.
    pub allow_fee_recipients: bool,
    /// The coinbase. A builder's is its fee recipient where the chain allows
    /// one and [`fee::BLACKHOLE`] otherwise — also Go's when none is set.
    pub beneficiary: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    /// 1 after the genesis: Go's `Prepare`, and the only value its VM accepts.
    pub difficulty: U256,
    /// The fee window, then — from Durango — the predicate results.
    pub extra_data: Bytes,
    pub mix_hash: B256,
    /// The block gas cost the block is under, derived from its parent's
    /// ([`fee::cost`]). The header carries it when it is not zero.
    pub block_gas_cost: u64,
}

impl Env {
    /// The environment of a block at `time` on top of `parent`.
    ///
    /// Every field Go derives, derived: the gas limit (`header.GasLimit`), the
    /// base fee, the block gas cost and the extra (see [`fee`]). And the ones
    /// its builder fixes: difficulty 1, a zero mix digest, and the blackhole
    /// for a coinbase unless the chain lets a builder name its fee recipient
    /// (miner/worker.go:135-205 `commitNewWork`). Refused before the EVM
    /// upgrade, whose rules this crate does not run.
    pub fn next(&self, parent: &header::Lux, time: u64) -> Result<Self, fee::Error> {
        if !self.chain.at(time).evm {
            return Err(fee::Error::PreEvm);
        }
        let head = &parent.header;
        let window = fee::window(&self.chain, head, time)?;
        Ok(Self {
            timestamp: time,
            gas_limit: self.fee.gas_limit,
            base_fee: fee::base_fee(&self.chain, &self.fee, head, time)?,
            block_gas_cost: fee::cost(&self.fee, cost_of(parent), head.timestamp, time),
            extra_data: fee::extra(&window, self.chain.at(time).durango),
            difficulty: U256::from(1u64),
            mix_hash: B256::ZERO,
            beneficiary: if self.allow_fee_recipients {
                self.beneficiary
            } else {
                fee::BLACKHOLE
            },
            ..self.clone()
        })
    }
}

/// The block gas cost a child of `parent` derives from: none for the genesis,
/// and otherwise what the parent's header carries, zero when it carries none.
fn cost_of(parent: &header::Lux) -> Option<u64> {
    (parent.header.number > 0).then(|| {
        parent
            .block_gas_cost
            .unwrap_or_default()
            .saturating_to::<u64>()
    })
}

/// How far past a node's clock a block may be dated: `allowedFutureBlockTime`
/// (consensus/dummy/consensus.go:28) and the VM's `maxFutureBlockTime`
/// (plugin/evm/vm.go:114).
pub const FUTURE: u64 = 10;

/// Go's rule for a header: whether `claimed` may follow `parent` by the clock
/// `now`. Returns the environment the block runs under.
///
/// Every clause is one Go applies, cited where it is: the dummy engine's
/// `verifyHeader` and `verifyHeaderGasFields` (consensus/dummy/consensus.go:
/// 129-226), the VM's `SyntacticVerify` (plugin/evm/block_verification.go:
/// 32-170) and `verifyPredicates` (plugin/evm/block.go:429-460), and the body
/// check's uncle root (core/block_validator.go:65-76). What is left — the
/// block fee, and the roots and gas that only running the block gives — is
/// [`finish`]'s, on both the proposer's side and the verifier's.
///
/// `now` is `None` for history: a block a node already accepted is not held to
/// that node's clock a second time, as Go does not re-verify what it wrote.
pub fn rule(
    env: &Env,
    parent: &header::Lux,
    claimed: &header::Lux,
    now: Option<u64>,
) -> Result<Env, Invalid> {
    let h = &claimed.header;
    let (head, parent) = (parent, &parent.header);
    let no = |why: String| Err(Invalid::Header(why));
    // consensus.go:213-216: the parent's number plus one.
    if h.number != parent.number + 1 {
        return no(format!(
            "number {} on a parent at {}",
            h.number, parent.number
        ));
    }
    // consensus.go:204-212: not before the parent — equal is several blocks a
    // second — and not more than `FUTURE` past the clock.
    if h.timestamp < parent.timestamp {
        return no(format!(
            "timestamp {} before its parent's {}",
            h.timestamp, parent.timestamp
        ));
    }
    if now.is_some_and(|now| h.timestamp > now.saturating_add(FUTURE)) {
        return no(format!("timestamp {} in the future", h.timestamp));
    }
    // block_verification.go:49-62.
    if h.difficulty != U256::from(1u64) {
        return no(format!("difficulty {}", h.difficulty));
    }
    if h.nonce != B64::ZERO {
        return no(format!("nonce {}", h.nonce));
    }
    if h.mix_hash != B256::ZERO {
        return no(format!("mix digest {}", h.mix_hash));
    }
    // consensus.go:182-186, 250-255 and block_validator.go:72-75: no uncles,
    // so the uncle root is the empty list's. The list itself is the reader's.
    if h.ommers_hash != EMPTY_OMMER_ROOT_HASH {
        return no(format!("uncle hash {}", h.ommers_hash));
    }
    // consensus.go:217-224: Lux runs no blobs.
    if h.blob_gas_used.is_some_and(|g| g != 0) {
        return no("blob gas used".into());
    }

    let mut next = env
        .next(head, h.timestamp)
        .map_err(|e| Invalid::Header(e.to_string()))?;
    let durango = env.chain.at(h.timestamp).durango;

    // header/gas_limit.go:68-83 and 46-65: the schedule's limit, exactly, and
    // no more gas than it.
    if h.gas_limit != next.gas_limit {
        return no(format!("gas limit {}, not {}", h.gas_limit, next.gas_limit));
    }
    if h.gas_used > next.gas_limit {
        return no(format!(
            "gas used {} over the limit {}",
            h.gas_used, next.gas_limit
        ));
    }
    // header/extra.go:74-106: at least a window from Durango, exactly one
    // before it.
    let extra = &h.extra_data;
    if extra.len() < fee::WINDOW_SIZE || (!durango && extra.len() != fee::WINDOW_SIZE) {
        return no(format!("{} bytes of extra", extra.len()));
    }
    // header/extra.go:47-68: the window derived from the parent.
    if extra[..fee::WINDOW_SIZE] != next.extra_data[..fee::WINDOW_SIZE] {
        return no("an extra that does not begin with the fee window".into());
    }
    // block.go:429-460: the predicate results the block's transactions give.
    // For a block this crate can run that is none — a transaction carrying a
    // predicate is refused in [`apply`] — so the bytes are `NO_PREDICATES`.
    if extra[fee::WINDOW_SIZE..] != next.extra_data[fee::WINDOW_SIZE..] {
        return no("predicate results this block's transactions do not give".into());
    }
    // consensus.go:149-159: the base fee as derived.
    if h.base_fee_per_gas != Some(next.base_fee) {
        return no(format!(
            "base fee {:?}, not {}",
            h.base_fee_per_gas, next.base_fee
        ));
    }
    // consensus.go:161-177 and 336-350: the block gas cost as derived, and a
    // header that carries none owes zero (see [`fee`] on where a cost lives).
    let cost = claimed.block_gas_cost.unwrap_or_default();
    if cost != U256::from(next.block_gas_cost) {
        return no(format!(
            "block gas cost {cost}, not {}",
            next.block_gas_cost
        ));
    }
    // consensus.go:106-127 and core/blockchain_reader.go:418-431: any coinbase
    // where fee recipients are allowed, the blackhole where they are not.
    if env.allow_fee_recipients {
        next.beneficiary = h.beneficiary;
    } else if h.beneficiary != fee::BLACKHOLE {
        return no(format!(
            "coinbase {}, not {}",
            h.beneficiary,
            fee::BLACKHOLE
        ));
    }
    Ok(next)
}

/// Why a transaction cannot be in a block, or a block cannot be one.
///
/// A transaction that runs and reverts is NOT here: it consumed gas, it has a
/// receipt, and it belongs in the block. This is only the transactions that
/// cannot be executed at all, and the blocks Go's rule refuses.
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
    /// Its access list names the warp precompile while warp is on, which makes
    /// it a predicate Go verifies and prices, and this crate does not.
    Predicate,
    /// The header is not the one Go derives from its parent ([`rule`]).
    Header(String),
    /// The block's tips do not cover its block gas cost ([`fee::covered`]).
    Fee(String),
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
            Invalid::Predicate => write!(f, "a warp predicate, which this node does not verify"),
            Invalid::Header(why) => write!(f, "header: {why}"),
            Invalid::Fee(why) => write!(f, "{why}"),
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
    if env.chain.at(env.timestamp).warp
        && tx
            .access_list()
            .is_some_and(|l| l.iter().any(|item| item.address == WARP))
    {
        return Err(Invalid::Predicate);
    }

    let (result, state) = run(world, env, to_revm(tx, sender), Checks::All)?;
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

/// Which rules a run is subject to.
///
/// Not a flag: the two are different questions. Consensus asks "may this
/// transaction be in a block", where paying for gas is the point. A simulation
/// asks "what would this do", where the caller is not paying and a balance is
/// not part of the question — `eth_call` from an address holding nothing is the
/// normal case, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checks {
    /// Every rule. What a block is verified under.
    All,
    /// The rules about being able to pay are set aside, and nothing else is.
    /// Only ever reachable through [`call`], which cannot commit.
    Simulated,
}

/// Drive the interpreter once. The ONE place execution happens.
///
/// Returns what the transaction did and the state it would leave behind —
/// separately, because whether that state is kept is the caller's decision and
/// not the interpreter's. [`apply`] keeps it; [`call`] throws it away.
pub fn run(
    world: &mut World,
    env: &Env,
    tx: TxEnv,
    checks: Checks,
) -> Result<(ExecutionResult, revm::state::EvmState), Invalid> {
    let spec = env.spec;
    let relaxed = checks == Checks::Simulated;
    // The context borrows the world for exactly this transaction. Access lists
    // and warm slots are per-transaction state and are meant to be dropped
    // here; what carries between transactions is committed state, which lives
    // in the world.
    let ctx = Context::mainnet()
        .with_db(&mut *world)
        .modify_cfg_chained(|c| {
            c.spec = spec;
            c.chain_id = env.chain_id;
            // A simulation is not paying, so the fee gates are not its
            // question. Every other rule — gas metering, the interpreter, the
            // precompile set — is untouched.
            c.disable_balance_check = relaxed;
            c.disable_base_fee = relaxed;
            c.disable_nonce_check = relaxed;
            c.disable_eip3607 = relaxed;
        })
        .modify_block_chained(|b| {
            b.beneficiary = env.beneficiary;
            b.timestamp = U256::from(env.timestamp);
            b.basefee = env.base_fee;
            b.gas_limit = env.gas_limit;
            b.difficulty = env.difficulty;
            // Go's block context sets Random to the header's difficulty from
            // Shanghai on (core/evm.go:82-89), so PREVRANDAO answers 1 on
            // every Lux block, not the mix digest.
            b.prevrandao = Some(B256::from(env.difficulty));
        });
    let mut evm = Evm::new(
        ctx,
        EthInstructions::new_mainnet_with_spec(spec),
        Precompiles::new(spec, env.profile),
    );
    evm.ctx.set_tx(tx);

    let mut handler: Handler<_, EVMError<core::convert::Infallible>, _> = Handler::new(env.chain);
    let result: ExecutionResult = handler
        .run(&mut evm)
        .map_err(|e| Invalid::Rejected(format!("{e:?}")))?;
    let state = evm.ctx.journal_mut().finalize();
    Ok((result, state))
}

/// Run a transaction and keep nothing — `eth_call`.
///
/// The world is taken by value so the discarding is structural: there is no
/// path from here that could commit, because the caller handed over a copy.
pub fn call(mut world: World, env: &Env, tx: TxEnv) -> Result<ExecutionResult, Invalid> {
    run(&mut world, env, tx, Checks::Simulated).map(|(result, _)| result)
}

/// A block, and everything needed to serve it.
#[derive(Clone, Debug)]
pub struct Built {
    /// The header in the shape the chain accepts: sixteen fields at genesis,
    /// seventeen after. See [`crate::header`] for why a shape is a layout and
    /// not one list with optional fields.
    pub header: header::Lux,
    pub transactions: Vec<TxEnvelope>,
    pub receipts: Vec<ReceiptEnvelope>,
}

impl Built {
    /// The block's hash: keccak of its header's RLP, and nothing else.
    pub fn hash(&self) -> B256 {
        self.header.seal()
    }

    /// The Ethereum fields, for everything that does not care about the shape.
    pub fn fields(&self) -> &Header {
        &self.header.header
    }
}

/// Execute a whole block strictly: every transaction must be executable.
///
/// This is the verifier's composition. A proposer wants the permissive one and
/// writes it out of [`apply`] directly, because "skip what does not fit" is a
/// policy about a mempool and not a property of execution.
pub fn execute(
    world: &mut World,
    parent: &header::Lux,
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

    finish(world, parent, env, kept, receipts, cumulative)
}

/// Seal what ran into a header, once its tips are known to cover the block gas
/// cost (consensus.go:322-364 `Finalize`, 366-434 `FinalizeAndAssemble`).
///
/// Separate from [`execute`] because a proposer reaches this point by a
/// different route and must arrive at the same header — one place that decides
/// what a block commits to means a proposer and a verifier cannot drift.
pub fn finish(
    world: &World,
    parent: &header::Lux,
    env: &Env,
    transactions: Vec<TxEnvelope>,
    receipts: Vec<ReceiptEnvelope>,
    gas_used: u64,
) -> Result<Built, Invalid> {
    if env.chain.at(env.timestamp).evm {
        fee::covered(env.base_fee, env.block_gas_cost, &transactions, &receipts)
            .map_err(Invalid::Fee)?;
    }
    let encoded: Vec<Vec<u8>> = transactions.iter().map(|t| t.encoded_2718()).collect();
    let receipts_encoded: Vec<Vec<u8>> = receipts.iter().map(|r| r.encoded_2718()).collect();
    let logs_bloom = receipts
        .iter()
        .fold(Bloom::ZERO, |acc, r| acc | bloom_of(r));

    let fields = Header {
        parent_hash: parent.seal(),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: env.beneficiary,
        state_root: world.root(),
        transactions_root: root::transactions(&encoded),
        receipts_root: root::receipts(&receipts_encoded),
        logs_bloom,
        difficulty: env.difficulty,
        number: parent.header.number + 1,
        gas_limit: env.gas_limit,
        gas_used,
        timestamp: env.timestamp,
        extra_data: env.extra_data.clone(),
        mix_hash: env.mix_hash,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(env.base_fee),
        // No post-London tail: a block here is "17" or "19 lux", and neither
        // has a position for one.
        ..Default::default()
    };
    Ok(Built {
        // Every block but the genesis is in a Lux shape. The genesis is built
        // by `genesis::Genesis`, never here.
        header: header::Lux::block(fields, U256::from(env.block_gas_cost)),
        transactions,
        receipts,
    })
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

    /// Mainnet's configuration, with the test key funded.
    fn funded() -> genesis::Genesis {
        genesis::Genesis {
            alloc: vec![(
                who(),
                genesis::Alloc::funded(U256::from(10u64).pow(U256::from(21u64))),
            )],
            ..genesis::mainnet()
        }
    }

    /// A funded world, its genesis, and the environment of block one a minute
    /// after it — derived, as Go derives it.
    fn chain() -> (World, header::Lux, Env, Address) {
        let g = funded();
        let parent = g.sealed();
        let env = g
            .env()
            .next(&parent, parent.header.timestamp + 60)
            .expect("derives");
        (g.world(), parent, env, who())
    }

    fn send(nonce: u64, chain_id: u64, value: U256) -> (TxEnvelope, Address) {
        paying(nonce, chain_id, value, 1_000_000_000)
    }

    /// A transfer whose tip over the base fee is `tip`.
    fn paying(nonce: u64, chain_id: u64, value: U256, tip: u128) -> (TxEnvelope, Address) {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 25_000_000_000 + tip,
            max_priority_fee_per_gas: tip,
            to: TxKind::Call(TO),
            value,
            ..Default::default()
        };
        let sig = sign(tx.signature_hash());
        (TxEnvelope::Eip1559(tx.into_signed(sig)), who())
    }

    /// The clock the tests verify by: well after every block they build.
    const NOW: Option<u64> = Some(u64::MAX / 2);

    #[test]
    fn a_block_moves_value_and_the_state_root_with_it() {
        let (mut world, parent, env, who) = chain();
        let before = world.root();
        let value = U256::from(1_000u64);

        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, value)],
        )
        .expect("the block executes");

        assert_eq!(built.fields().number, 1);
        assert_eq!(built.fields().parent_hash, parent.seal());
        assert_eq!(world.balance(&TO), value, "the transfer landed");
        assert_eq!(world.nonce(&who), 1, "the sender's nonce advanced");
        assert_ne!(built.fields().state_root, before, "the state moved");
        assert_eq!(
            built.fields().state_root,
            world.root(),
            "the header commits to the world that actually resulted"
        );
        assert_eq!(built.fields().gas_used, 21_000);
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
        assert_ne!(built.fields().transactions_root, root::EMPTY);
        assert_ne!(built.fields().receipts_root, root::EMPTY);
        assert_eq!(built.receipts.len(), 1);
    }

    #[test]
    fn an_empty_block_still_advances_and_keeps_the_empty_roots() {
        let (mut world, parent, env, _) = chain();
        let built = execute(&mut world, &parent, &env, vec![]).expect("executes");
        assert_eq!(built.fields().number, 1);
        assert_eq!(built.fields().gas_used, 0);
        assert_eq!(built.fields().transactions_root, root::EMPTY);
        assert_eq!(built.fields().receipts_root, root::EMPTY);
        assert_eq!(
            built.fields().state_root,
            parent.header.state_root,
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
        let (mut world, _parent, env, _) = chain();
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
        let next = env.next(&first.header, env.timestamp + 2).expect("derives");
        let second = execute(
            &mut world,
            &first.header,
            &next,
            vec![send(1, env.chain_id, U256::from(1u64))],
        )
        .expect("second");

        assert_eq!(second.fields().number, 2);
        assert_eq!(second.fields().parent_hash, first.hash());
        assert_ne!(second.fields().state_root, first.fields().state_root);
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
            env.beneficiary,
            fee::BLACKHOLE,
            "mainnet names no fee recipient"
        );
        assert_eq!(
            paid,
            U256::from(built.fields().gas_used as u128 * 26_000_000_000u128)
        );
    }

    #[test]
    fn a_built_block_is_one_the_rule_derives() {
        let g = funded();
        let (mut world, parent, env, _) = chain();
        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::from(1u64))],
        )
        .expect("builds");
        let h = built.fields();
        assert_eq!(h.extra_data.len(), 86, "the window and no predicates");
        assert_eq!(
            &h.extra_data[..80],
            &[0u8; 80][..],
            "the first block's window is empty"
        );
        assert_eq!(h.beneficiary, fee::BLACKHOLE);
        assert_eq!(h.difficulty, U256::from(1u64));
        assert_eq!(h.gas_limit, 12_000_000, "the schedule's limit");
        assert_eq!(
            h.base_fee_per_gas,
            Some(25_000_000_000),
            "the minimum, after the genesis"
        );
        let ruled = rule(&g.env(), &parent, &built.header, NOW).expect("passes");
        assert_eq!(ruled.base_fee, env.base_fee);
        assert_eq!(ruled.extra_data, env.extra_data);
        assert_eq!(ruled.block_gas_cost, 0);

        // The second, in the same second: its window holds the first's gas,
        // and it owes a block gas cost of two steps.
        let next = env.next(&built.header, env.timestamp).expect("derives");
        assert_eq!(next.block_gas_cost, 400_000);
        let w = fee::Window::parse(&next.extra_data).expect("a window");
        assert_eq!(w.0[9], 21_000, "the parent's gas, in its second");
        let second = execute(
            &mut world,
            &built.header,
            &next,
            vec![paying(1, env.chain_id, U256::from(1u64), 500_000_000_000)],
        )
        .expect("the tip covers the cost");
        assert_eq!(second.header.layout.name, "19 lux", "a cost is carried");
        assert_eq!(second.header.block_gas_cost, Some(U256::from(400_000u64)));
        rule(&g.env(), &built.header, &second.header, NOW).expect("passes");
    }

    #[test]
    fn a_fast_block_pays_its_block_gas_cost_or_is_not_a_block() {
        let (mut world, parent, env, _) = chain();
        let first = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::ZERO)],
        )
        .expect("first");
        let next = env.next(&first.header, env.timestamp).expect("derives");
        // 400,000 gas at 25 gwei is 1e16 wei of tips; 21,000 gas at 1 gwei is
        // far short of it.
        let refused = execute(
            &mut world.clone(),
            &first.header,
            &next,
            vec![send(1, env.chain_id, U256::ZERO)],
        );
        assert!(matches!(refused, Err(Invalid::Fee(_))), "{refused:?}");
        // 476,190,476,191 wei a gas is the least tip that covers it.
        let short = paying(1, env.chain_id, U256::ZERO, 476_190_476_190);
        let enough = paying(1, env.chain_id, U256::ZERO, 476_190_476_191);
        assert!(matches!(
            execute(&mut world.clone(), &first.header, &next, vec![short]),
            Err(Invalid::Fee(_))
        ));
        execute(&mut world, &first.header, &next, vec![enough]).expect("exactly covered");

        // Two seconds on, the target rate, and nothing is owed.
        let slow = env.next(&first.header, env.timestamp + 2).expect("derives");
        assert_eq!(slow.block_gas_cost, 0);
    }

    #[test]
    fn every_derived_field_is_held_to_what_the_parent_gives() {
        let g = funded();
        let (mut world, parent, env, _) = chain();
        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::ZERO)],
        )
        .expect("builds");
        let ok = |h: &header::Lux| rule(&g.env(), &parent, h, NOW);
        ok(&built.header).expect("the block as built");
        type Edit = fn(&mut header::Lux);
        let edits: [(&str, Edit); 15] = [
            ("number", |h| h.header.number += 1),
            ("before its parent", |h| h.header.timestamp = 0),
            ("gas limit", |h| h.header.gas_limit += 1),
            ("base fee", |h| {
                h.header.base_fee_per_gas = Some(25_000_000_001)
            }),
            ("window", |h| {
                let mut e = h.header.extra_data.to_vec();
                e[79] = 1;
                h.header.extra_data = e.into();
            }),
            ("predicate results", |h| {
                let mut e = h.header.extra_data.to_vec();
                e[85] = 1;
                h.header.extra_data = e.into();
            }),
            ("no predicate results", |h| {
                h.header.extra_data = h.header.extra_data.slice(..80)
            }),
            ("short extra", |h| {
                h.header.extra_data = h.header.extra_data.slice(..79)
            }),
            ("coinbase", |h| h.header.beneficiary = Address::ZERO),
            ("difficulty", |h| h.header.difficulty = U256::ZERO),
            ("nonce", |h| h.header.nonce = B64::from(1u64)),
            ("mix digest", |h| h.header.mix_hash = B256::repeat_byte(1)),
            ("uncle hash", |h| h.header.ommers_hash = B256::ZERO),
            ("block gas cost", |h| {
                h.layout = header::named("19 lux");
                h.block_gas_cost = Some(U256::from(1u64));
                h.ext_data_hash = Some(B256::ZERO);
                h.ext_data_gas_used = Some(Bytes::new());
            }),
            ("blob gas", |h| {
                h.layout = header::named("20 lux");
                h.block_gas_cost = Some(U256::ZERO);
                h.ext_data_gas_used = Some(Bytes::new());
                h.header.blob_gas_used = Some(1);
            }),
        ];
        for (what, edit) in edits {
            let mut h = built.header.clone();
            edit(&mut h);
            assert!(
                matches!(ok(&h), Err(Invalid::Header(_))),
                "{what}: {:?}",
                ok(&h)
            );
        }
        let future = rule(
            &g.env(),
            &parent,
            &built.header,
            Some(env.timestamp - FUTURE - 1),
        );
        assert!(
            matches!(future, Err(Invalid::Header(_))),
            "a block past the clock"
        );
        rule(
            &g.env(),
            &parent,
            &built.header,
            Some(env.timestamp - FUTURE),
        )
        .expect("ten seconds ahead is allowed");
        rule(&g.env(), &parent, &built.header, None).expect("history is not clocked");
    }

    #[test]
    fn a_header_that_omits_a_cost_it_owes_is_refused() {
        // Go's builder never writes the cost into a header, and its VM fills an
        // absent one from the parent; its import path, cevm and this crate read
        // an absent cost as zero, so a block that owes one must carry it.
        let g = funded();
        let (mut world, parent, env, _) = chain();
        let first = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::ZERO)],
        )
        .expect("first");
        assert_eq!(cost_of(&first.header), Some(0), "carries none, owes zero");
        assert_eq!(cost_of(&parent), None, "the genesis holds none");
        let next = env.next(&first.header, env.timestamp).expect("derives");
        let second = execute(
            &mut world,
            &first.header,
            &next,
            vec![paying(1, env.chain_id, U256::ZERO, 500_000_000_000)],
        )
        .expect("second");
        assert_eq!(cost_of(&second.header), Some(400_000));
        let bare = header::Lux::block(second.fields().clone(), U256::ZERO);
        assert_eq!(bare.layout.name, "17");
        let refused = rule(&g.env(), &first.header, &bare, NOW);
        assert!(matches!(refused, Err(Invalid::Header(_))), "{refused:?}");
    }

    #[test]
    fn a_coinbase_is_the_builders_only_where_the_chain_allows_it() {
        let g = genesis::Genesis {
            allow_fee_recipients: true,
            ..funded()
        };
        let parent = g.sealed();
        let mine = address!("00000000000000000000000000000000000000c0");
        let env = Env {
            beneficiary: mine,
            ..g.env()
        }
        .next(&parent, parent.header.timestamp + 60)
        .expect("derives");
        assert_eq!(env.beneficiary, mine);
        let mut world = g.world();
        let built = execute(
            &mut world,
            &parent,
            &env,
            vec![send(0, env.chain_id, U256::ZERO)],
        )
        .expect("builds");
        let ruled = rule(&g.env(), &parent, &built.header, NOW).expect("any coinbase");
        assert_eq!(
            ruled.beneficiary, mine,
            "the block runs under the one it names"
        );
    }

    #[test]
    fn a_warp_predicate_is_refused_once_warp_is_on() {
        let (mut world, _parent, env, _) = chain();
        let tx = TxEip1559 {
            chain_id: env.chain_id,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(TO),
            access_list: alloy_eips::eip2930::AccessList(vec![
                alloy_eips::eip2930::AccessListItem {
                    address: WARP,
                    storage_keys: vec![B256::ZERO],
                },
            ]),
            ..Default::default()
        };
        let sig = sign(tx.signature_hash());
        let tx = TxEnvelope::Eip1559(tx.into_signed(sig));
        let on = Env {
            chain: Chain {
                warp: Some(env.timestamp),
                ..env.chain
            },
            ..env.clone()
        };
        assert_eq!(
            apply(&mut world.clone(), &on, 0, &tx, who()).err(),
            Some(Invalid::Predicate)
        );
        let before = Env {
            chain: Chain {
                warp: Some(env.timestamp + 1),
                ..env.chain
            },
            ..env.clone()
        };
        apply(&mut world, &before, 0, &tx, who()).expect("an access list, not yet a predicate");
    }

    #[test]
    fn the_sha256_precompile_returns_the_digest_anyone_else_computes() {
        // Real bytecode execution, checked against a value that has nothing to
        // do with this codebase: SHA-256("abc") is a published constant.
        let (world, env, _) = {
            let (w, _p, e, who) = chain();
            (w, e, who)
        };
        let out = call(
            world,
            &env,
            TxEnv::builder()
                .caller(who())
                .kind(TxKind::Call(Address::from_slice(&{
                    let mut a = [0u8; 20];
                    a[19] = 2;
                    a
                })))
                .gas_limit(100_000)
                .gas_price(env.base_fee as u128)
                .data(Bytes::from_static(b"abc"))
                .nonce(0)
                // A call is not signed, so it carries no EIP-155 binding.
                .chain_id(None)
                .build_fill(),
        )
        .expect("the call runs");
        assert!(out.is_success(), "{out:?}");
        assert_eq!(
            alloy_primitives::hex::encode(out.into_output().unwrap_or_default()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256(\"abc\")"
        );
    }

    #[test]
    fn prevrandao_is_the_headers_difficulty_as_go_reads_it() {
        // PREVRANDAO; PUSH0 MSTORE; RETURN(0, 32): the word the opcode answers.
        let code = Bytes::from_static(&[0x44, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        let (mut world, _parent, env, _) = chain();
        let at = address!("00000000000000000000000000000000000000aa");
        world.insert(
            at,
            crate::state::Account {
                code_hash: revm::bytecode::Bytecode::new_raw(code.clone()).hash_slow(),
                ..Default::default()
            },
            Some(revm::bytecode::Bytecode::new_raw(code)),
        );
        assert_eq!(env.difficulty, U256::from(1u64));
        let out = call(
            world,
            &env,
            TxEnv::builder()
                .caller(who())
                .kind(TxKind::Call(at))
                .gas_limit(100_000)
                .nonce(0)
                .chain_id(None)
                .build_fill(),
        )
        .expect("runs");
        assert_eq!(
            out.into_output().unwrap_or_default(),
            Bytes::from(B256::from(U256::from(1u64)).to_vec()),
            "the difficulty, not the zero mix digest"
        );
    }

    #[test]
    fn consensus_still_refuses_a_sender_that_cannot_pay() {
        // The guard on the simulation relaxation: `Checks::All` is what a block
        // is verified under, and enabling revm's optional_* features must not
        // have loosened it. An account with nothing cannot send a transaction.
        let (mut world, _parent, env, _) = chain();
        let broke = address!("00000000000000000000000000000000000000bb");
        let refused = run(
            &mut world,
            &env,
            TxEnv::builder()
                .caller(broke)
                .kind(TxKind::Call(TO))
                .gas_limit(100_000)
                .gas_price(30_000_000_000u128)
                .nonce(0)
                .chain_id(Some(env.chain_id))
                .build_fill(),
            Checks::All,
        );
        assert!(
            matches!(&refused, Err(Invalid::Rejected(why)) if why.contains("LackOfFundForMaxFee")),
            "{refused:?}"
        );
        // And the same transaction simulates fine, which is the whole point of
        // there being two answers.
        assert!(call(
            world,
            &env,
            TxEnv::builder()
                .caller(broke)
                .kind(TxKind::Call(TO))
                .gas_limit(100_000)
                .nonce(0)
                .chain_id(None)
                .build_fill()
        )
        .is_ok());
    }

    #[test]
    fn a_call_keeps_nothing() {
        let (world, _parent, env, _) = chain();
        let before = world.root();
        let _ = call(
            world.clone(),
            &env,
            TxEnv::builder()
                .caller(who())
                .kind(TxKind::Call(TO))
                .gas_limit(100_000)
                .gas_price(env.base_fee as u128)
                .value(U256::from(1u64))
                .nonce(0)
                .chain_id(None)
                .build_fill(),
        )
        .expect("runs");
        assert_eq!(world.root(), before, "a call is not a transaction");
        assert_eq!(world.balance(&TO), U256::ZERO);
    }

    /// One receipt, so each field can be moved on its own.
    fn one_receipt(ty: TxType, success: bool, cumulative: u64, logs: Vec<Log>) -> ReceiptEnvelope {
        envelope(
            ty,
            Receipt {
                status: Eip658Value::Eip658(success),
                cumulative_gas_used: cumulative,
                logs,
            },
        )
    }

    fn receipts_root(rs: &[ReceiptEnvelope]) -> B256 {
        let encoded: Vec<Vec<u8>> = rs.iter().map(|r| r.encoded_2718()).collect();
        root::receipts(&encoded)
    }

    #[test]
    fn every_field_a_receipt_commits_to_moves_the_receipts_root() {
        // The root is a commitment, and a commitment that ignores a field is a
        // field two chains can disagree about while agreeing on the block. Each
        // of these was a mutation the tests here used to sleep through.
        let log = Log::new_unchecked(
            TO,
            vec![B256::repeat_byte(0x11)],
            Bytes::from_static(b"data"),
        );
        let base = one_receipt(TxType::Eip1559, true, 21_000, vec![log.clone()]);
        let root_of = |r: &ReceiptEnvelope| receipts_root(std::slice::from_ref(r));
        let want = root_of(&base);

        assert_ne!(
            want,
            root_of(&one_receipt(
                TxType::Legacy,
                true,
                21_000,
                vec![log.clone()]
            )),
            "the type flag is part of the 2718 envelope the trie commits to"
        );
        assert_ne!(
            want,
            root_of(&one_receipt(
                TxType::Eip1559,
                false,
                21_000,
                vec![log.clone()]
            )),
            "success and failure are different receipts"
        );
        assert_ne!(
            want,
            root_of(&one_receipt(
                TxType::Eip1559,
                true,
                21_001,
                vec![log.clone()]
            )),
            "cumulative gas is committed to"
        );
        assert_ne!(
            want,
            root_of(&one_receipt(TxType::Eip1559, true, 21_000, vec![])),
            "dropping the logs is a different receipt"
        );

        // And the bloom is not decoration: it is inside the encoding, so a
        // receipt whose bloom was zeroed does not hash to the same value.
        let mut blanked = match base.clone() {
            ReceiptEnvelope::Eip1559(mut r) => {
                r.logs_bloom = Bloom::ZERO;
                ReceiptEnvelope::Eip1559(r)
            }
            other => other,
        };
        assert_ne!(want, root_of(&blanked), "the logs bloom is committed to");
        blanked = base.clone();
        assert_eq!(
            want,
            root_of(&blanked),
            "and the unchanged receipt still matches"
        );
    }

    #[test]
    fn a_receipt_in_another_position_is_another_root() {
        let a = one_receipt(TxType::Eip1559, true, 21_000, vec![]);
        let b = one_receipt(TxType::Eip1559, true, 42_000, vec![]);
        assert_ne!(
            receipts_root(&[a.clone(), b.clone()]),
            receipts_root(&[b, a]),
            "position is part of the commitment"
        );
    }

    #[test]
    fn the_block_bloom_is_the_or_of_its_receipts() {
        // The header's bloom has to be derivable from the receipts, or a node
        // could serve a block whose bloom answers filters the receipts do not.
        let log = Log::new_unchecked(TO, vec![B256::repeat_byte(0x22)], Bytes::new());
        let r = one_receipt(TxType::Eip1559, true, 21_000, vec![log]);
        let folded = [r.clone()]
            .iter()
            .fold(Bloom::ZERO, |acc, x| acc | bloom_of(x));
        assert_eq!(folded, bloom_of(&r));
        assert_ne!(folded, Bloom::ZERO, "a receipt with a log has a bloom");
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
