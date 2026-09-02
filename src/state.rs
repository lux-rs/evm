// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! The world state: what every account holds, and what that hashes to.
//!
//! revm arrives at a state *diff* — the accounts one transaction touched — and
//! stops there, deliberately: where that diff is kept is a node's business, not
//! an interpreter's. This module is that business. It holds every account the
//! chain has, applies revm's diff to it, and computes the root a header commits
//! to.
//!
//! The root is the reason this type cannot be a `HashMap` the caller keeps. A
//! `stateRoot` is a Merkle-Patricia hash over `keccak(address)`, and each
//! account's third field is itself a trie over `keccak(slot)` — so a store that
//! does not keep storage per account cannot produce one. [`root`](crate::root)
//! owns the trie; what is here is the world it is taken over.
//!
//! Two rules from Ethereum's state that a naive store gets wrong, and that
//! change the root when missed:
//!
//! - **a zero slot is an absent slot.** Writing `0` to storage deletes the key.
//!   A store that keeps it holds a trie entry nobody else has.
//! - **an empty account is an absent account** (EIP-161): nonce 0, balance 0,
//!   no code. Touching one and leaving it behind forks the state root.
//!
//! Both are applied in [`World::commit`], which is the only way state changes.

use std::collections::BTreeMap;
use std::convert::Infallible;

use alloy_primitives::{Address, B256, U256};
use revm::bytecode::Bytecode;
use revm::primitives::{StorageKey, StorageValue, KECCAK_EMPTY};
use revm::state::{AccountInfo, EvmState};
use revm::{Database, DatabaseCommit};

use crate::root;

/// One account as the world holds it.
///
/// The same four fields the trie commits to, except that storage is kept whole
/// rather than pre-hashed: the root is derived from it on demand, because a
/// cached root is a second place for the state to be, and the two disagree the
/// first time someone forgets to invalidate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    /// `keccak(code)`, or [`KECCAK_EMPTY`] for an account with no code — never
    /// zero, which is a different account to every other implementation.
    pub code_hash: B256,
    pub storage: BTreeMap<StorageKey, StorageValue>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            storage: BTreeMap::new(),
        }
    }
}

impl Account {
    /// An account with a balance and nothing else — what a genesis allocation
    /// is.
    pub fn funded(balance: U256) -> Self {
        Self {
            balance,
            ..Default::default()
        }
    }

    /// Whether this account is one the state trie does not carry: EIP-161's
    /// nonce 0, balance 0, no code.
    ///
    /// Storage is not part of the test, and cannot be: an account with storage
    /// and no code is only reachable by having had code, which means it had a
    /// nonce.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.code_hash == KECCAK_EMPTY
    }

    /// This account's `storageRoot`.
    pub fn storage_root(&self) -> B256 {
        root::storage(self.storage.iter().map(|(k, v)| ((*k).into(), *v)))
    }
}

/// Every account on the chain, and the code they run.
///
/// Ordered rather than hashed: two nodes that walk this map take the same walk,
/// which is what makes a dump of it comparable between implementations. The
/// trie sorts on its own, so ordering is not load-bearing for the root — it is
/// load-bearing for being able to read one.
#[derive(Clone, Debug, Default)]
pub struct World {
    accounts: BTreeMap<Address, Account>,
    code: BTreeMap<B256, Bytecode>,
    /// The last 256 block hashes, for `BLOCKHASH`. Keyed by number, and the
    /// EVM asks for numbers that may not be here — an unknown number is zero,
    /// which is what the opcode is defined to return.
    hashes: BTreeMap<u64, B256>,
}

impl World {
    pub fn new() -> Self {
        Self::default()
    }

    /// A world holding a genesis allocation.
    pub fn allocated(alloc: impl IntoIterator<Item = (Address, U256)>) -> Self {
        let mut w = Self::new();
        for (who, balance) in alloc {
            w.accounts.insert(who, Account::funded(balance));
        }
        w
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    pub fn get(&self, who: &Address) -> Option<&Account> {
        self.accounts.get(who)
    }

    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.accounts.iter()
    }

    /// What an account holds. An account nobody has ever touched holds zero,
    /// which is the same answer as an account that spent everything.
    pub fn balance(&self, who: &Address) -> U256 {
        self.accounts.get(who).map(|a| a.balance).unwrap_or_default()
    }

    pub fn nonce(&self, who: &Address) -> u64 {
        self.accounts.get(who).map(|a| a.nonce).unwrap_or_default()
    }

    /// The code at an address, empty if there is none.
    pub fn code(&self, who: &Address) -> Bytecode {
        self.accounts
            .get(who)
            .and_then(|a| self.code.get(&a.code_hash))
            .cloned()
            .unwrap_or_default()
    }

    /// One storage slot. An unset slot is zero — it is not absent, it is zero.
    pub fn storage(&self, who: &Address, slot: StorageKey) -> StorageValue {
        self.accounts
            .get(who)
            .and_then(|a| a.storage.get(&slot).copied())
            .unwrap_or_default()
    }

    /// Put an account in place directly. For building a genesis, not for
    /// executing — execution goes through [`World::commit`], which applies the
    /// rules that keep the root right.
    pub fn insert(&mut self, who: Address, account: Account, code: Option<Bytecode>) {
        if let Some(code) = code {
            if !code.is_empty() {
                self.code.insert(code.hash_slow(), code);
            }
        }
        self.accounts.insert(who, account);
    }

    /// Record a block hash for `BLOCKHASH`, keeping the last 256 — the window
    /// the opcode can reach, so anything older is memory nothing can read.
    pub fn remember(&mut self, number: u64, hash: B256) {
        self.hashes.insert(number, hash);
        while self.hashes.len() > 256 {
            let oldest = *self.hashes.keys().next().expect("non-empty");
            self.hashes.remove(&oldest);
        }
    }

    /// The `stateRoot`: a Merkle-Patricia trie over every account, each carrying
    /// the root of its own storage trie.
    pub fn root(&self) -> B256 {
        root::state(self.accounts.iter().map(|(who, a)| {
            (
                *who,
                root::account(a.nonce, a.balance, a.storage_root(), a.code_hash),
            )
        }))
    }

    /// Apply what a transaction did.
    ///
    /// This is [`DatabaseCommit`], and the three cases revm distinguishes are
    /// all here: an untouched account is not a change, a self-destructed one is
    /// gone, and a newly created one starts from empty storage rather than
    /// inheriting whatever an earlier incarnation left at that address.
    fn apply(&mut self, changes: EvmState) {
        for (who, account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() {
                self.accounts.remove(&who);
                continue;
            }

            if let Some(code) = &account.info.code {
                if !code.is_empty() {
                    self.code.insert(account.info.code_hash, code.clone());
                }
            }

            let entry = self.accounts.entry(who).or_default();
            entry.nonce = account.info.nonce;
            entry.balance = account.info.balance;
            entry.code_hash = account.info.code_hash;
            // A created account is created empty. Anything at this address
            // before belonged to a contract that no longer exists.
            if account.is_created() {
                entry.storage.clear();
            }
            for (slot, value) in account.storage {
                // A zero slot is an absent slot; keeping it would put a key in
                // the trie that no other implementation has.
                if value.present_value.is_zero() {
                    entry.storage.remove(&slot);
                } else {
                    entry.storage.insert(slot, value.present_value);
                }
            }

            // EIP-161: an account touched into emptiness is deleted.
            if entry.is_empty() && entry.storage.is_empty() {
                self.accounts.remove(&who);
            }
        }
    }
}

impl DatabaseCommit for World {
    fn commit(&mut self, changes: EvmState) {
        self.apply(changes);
    }
}

impl Database for World {
    /// A world always answers: it is memory, and there is no read that can
    /// fail. Making that `Infallible` rather than a stub error type means the
    /// caller's error handling has nothing to pretend about.
    type Error = Infallible;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).map(|a| AccountInfo {
            balance: a.balance,
            nonce: a.nonce,
            code_hash: a.code_hash,
            code: self.code.get(&a.code_hash).cloned(),
            account_id: None,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.code.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        Ok(World::storage(self, &address, index))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.hashes.get(&number).copied().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use revm::state::{Account as RevmAccount, AccountStatus, EvmStorageSlot};

    const A: Address = address!("00000000000000000000000000000000000000a1");

    /// A touched account carrying `info`, as revm hands one back.
    fn touched(info: AccountInfo, status: AccountStatus) -> RevmAccount {
        RevmAccount {
            original_info: Box::new(info.clone()),
            info,
            transaction_id: 0,
            storage: Default::default(),
            status: status | AccountStatus::Touched,
        }
    }

    #[test]
    fn an_empty_world_is_the_empty_root() {
        assert_eq!(World::new().root(), root::EMPTY);
    }

    #[test]
    fn a_funded_account_moves_the_root() {
        let w = World::allocated([(A, U256::from(1u64))]);
        assert_ne!(w.root(), root::EMPTY);
        assert_eq!(w.balance(&A), U256::from(1u64));
        // And it is the trie's number, not some digest of our own: the same
        // account built through `root` directly must agree.
        assert_eq!(
            w.root(),
            root::state([(A, root::account(0, U256::from(1u64), root::EMPTY, KECCAK_EMPTY))])
        );
    }

    #[test]
    fn an_untouched_account_is_not_a_change() {
        let mut w = World::new();
        let mut untouched = touched(
            AccountInfo {
                balance: U256::from(5u64),
                ..Default::default()
            },
            AccountStatus::empty(),
        );
        untouched.status = AccountStatus::empty();
        w.commit(EvmState::from_iter([(A, untouched)]));
        assert_eq!(w.root(), root::EMPTY, "nothing was touched, nothing changed");
    }

    #[test]
    fn a_zero_slot_is_deleted_not_stored() {
        let mut w = World::new();
        let mut acct = touched(
            AccountInfo {
                balance: U256::from(1u64),
                nonce: 1,
                ..Default::default()
            },
            AccountStatus::empty(),
        );
        acct.storage.insert(
            StorageKey::from(1u64),
            EvmStorageSlot::new_changed(StorageValue::ZERO, StorageValue::from(7u64), 0),
        );
        w.commit(EvmState::from_iter([(A, acct.clone())]));
        assert_eq!(w.storage(&A, StorageKey::from(1u64)), StorageValue::from(7u64));
        let with_slot = w.root();

        // Now write zero to it. The slot must leave the trie entirely, so the
        // root returns to what it was before the slot existed.
        let mut cleared = acct;
        cleared.storage.insert(
            StorageKey::from(1u64),
            EvmStorageSlot::new_changed(StorageValue::from(7u64), StorageValue::ZERO, 0),
        );
        w.commit(EvmState::from_iter([(A, cleared)]));
        assert_eq!(w.storage(&A, StorageKey::from(1u64)), StorageValue::ZERO);
        assert_ne!(w.root(), with_slot);
        assert_eq!(
            w.get(&A).expect("account").storage_root(),
            root::EMPTY,
            "a storage trie whose only key was zeroed is the empty trie"
        );
    }

    #[test]
    fn an_account_touched_into_emptiness_leaves_the_trie() {
        let mut w = World::allocated([(A, U256::from(10u64))]);
        assert_ne!(w.root(), root::EMPTY);
        w.commit(EvmState::from_iter([(
            A,
            touched(AccountInfo::default(), AccountStatus::empty()),
        )]));
        assert_eq!(w.root(), root::EMPTY, "EIP-161 deletes it");
        assert!(w.get(&A).is_none());
    }

    #[test]
    fn a_self_destructed_account_is_gone() {
        let mut w = World::allocated([(A, U256::from(10u64))]);
        w.commit(EvmState::from_iter([(
            A,
            touched(AccountInfo::default(), AccountStatus::SelfDestructed),
        )]));
        assert!(w.get(&A).is_none());
        assert_eq!(w.root(), root::EMPTY);
    }

    #[test]
    fn a_created_account_does_not_inherit_old_storage() {
        let mut w = World::new();
        let mut first = touched(
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
            AccountStatus::empty(),
        );
        first.storage.insert(
            StorageKey::from(1u64),
            EvmStorageSlot::new_changed(StorageValue::ZERO, StorageValue::from(9u64), 0),
        );
        w.commit(EvmState::from_iter([(A, first)]));
        assert_eq!(w.storage(&A, StorageKey::from(1u64)), StorageValue::from(9u64));

        let created = touched(
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
            AccountStatus::Created,
        );
        w.commit(EvmState::from_iter([(A, created)]));
        assert_eq!(
            w.storage(&A, StorageKey::from(1u64)),
            StorageValue::ZERO,
            "creation clears whatever the address held before"
        );
    }

    #[test]
    fn the_blockhash_window_holds_the_last_256() {
        let mut w = World::new();
        for n in 0..300u64 {
            w.remember(n, B256::with_last_byte(n as u8));
        }
        let mut db = w.clone();
        assert_eq!(db.block_hash(299).expect("infallible"), B256::with_last_byte(43));
        assert_eq!(
            db.block_hash(0).expect("infallible"),
            B256::ZERO,
            "outside the window is zero, which is what BLOCKHASH returns"
        );
    }
}
