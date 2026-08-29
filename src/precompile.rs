// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//! The classical-precompile gate.
//!
//! A post-quantum chain refuses the precompiles whose security rests on a
//! problem a quantum computer solves. Which families it refuses is a per-chain
//! value, not a global: one process hosts several chains and each carries its
//! own [`Profile`] on its config, exactly as Go carries `ChainConfig.PQ`.
//!
//! Two things about the Go gate matter, and both are easy to get wrong:
//!
//! 1. **Gas is charged before the refusal, not instead of it.** `(*EVM).
//!    runPrecompile` in `luxfi/geth@v1.20.2 core/vm/evm.go` deducts
//!    `RequiredGas(input)`, and only then calls `RefuseUnder`. A refusal that
//!    charged nothing would be visible in gas, and a chain that reads its own
//!    posture out of gas timing is a chain that leaks it.
//! 2. **The classification is on identity, not address.** Go type-switches on
//!    the precompile implementation so that remapping a precompile to another
//!    address does not change which family it belongs to. revm carries the same
//!    identity as [`PrecompileId`], so this maps that, not the address.
//!
//! `identity` (0x04) and `modexp` (0x05) are deliberately ungated: Go's
//! `opForPrecompile` has no case for them, so they fall to [`Op::Unknown`],
//! which every profile admits.

use revm::context::{Cfg, ContextTr};
use revm::handler::{EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, InstructionResult, InterpreterResult};
use revm::precompile::PrecompileId;
use revm::primitives::{hardfork::SpecId, Address, Bytes};

/// The precompile families a profile can refuse, mirroring `luxfi/pq`'s `Op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Ecrecover,
    P256Verify,
    Sha256,
    Ripemd160,
    Blake2f,
    Bn256,
    Bls12381,
    Kzg,
    /// Not gated by any profile — admitted unconditionally.
    Unknown,
}

impl Op {
    /// The family a precompile belongs to.
    ///
    /// One arm per case in Go's `opForPrecompile`. Go separates bn256 into add,
    /// mul and pairing, but `Profile` carries a single `ForbidBn256` flag for
    /// all three, so the distinction has no observable effect and is not
    /// reproduced here.
    pub fn of(id: &PrecompileId) -> Self {
        match id {
            PrecompileId::EcRec => Op::Ecrecover,
            PrecompileId::P256Verify => Op::P256Verify,
            PrecompileId::Sha256 => Op::Sha256,
            PrecompileId::Ripemd160 => Op::Ripemd160,
            PrecompileId::Blake2F => Op::Blake2f,
            PrecompileId::Bn254Add | PrecompileId::Bn254Mul | PrecompileId::Bn254Pairing => {
                Op::Bn256
            }
            PrecompileId::Bls12G1Add
            | PrecompileId::Bls12G1Msm
            | PrecompileId::Bls12G2Add
            | PrecompileId::Bls12G2Msm
            | PrecompileId::Bls12Pairing
            | PrecompileId::Bls12MapFpToGp1
            | PrecompileId::Bls12MapFp2ToGp2 => Op::Bls12381,
            PrecompileId::KzgPointEvaluation => Op::Kzg,
            PrecompileId::Identity | PrecompileId::ModExp | PrecompileId::Custom(_) => Op::Unknown,
        }
    }
}

/// Which classical families a chain refuses.
///
/// The default admits everything, which is Go's nil `*pq.Profile` and is what
/// every Lux chain serving traffic today installs — the post-quantum block is
/// not active on the C-chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub ecrecover: bool,
    pub p256: bool,
    pub sha256: bool,
    pub ripemd160: bool,
    pub blake2f: bool,
    pub bn256: bool,
    pub bls12381: bool,
    pub kzg: bool,
}

impl Profile {
    /// Refuses every classical family. `pq.Strict()`.
    pub const fn strict() -> Self {
        Self {
            ecrecover: true,
            p256: true,
            sha256: true,
            ripemd160: true,
            blake2f: true,
            bn256: true,
            bls12381: true,
            kzg: true,
        }
    }

    /// What a Lux chain installs: strict, less bn256.
    ///
    /// The alt_bn128 precompiles at 0x06–0x08 stay available so Ethereum
    /// contracts keep working; Lux's own pairing use lives in its own
    /// precompiles and is gated separately. See
    /// `luxfi/geth core/vm/pq_lux_profile_test.go`.
    pub const fn lux() -> Self {
        Self {
            bn256: false,
            ..Self::strict()
        }
    }

    /// Whether this profile refuses `op`.
    pub const fn forbids(&self, op: Op) -> bool {
        match op {
            Op::Ecrecover => self.ecrecover,
            Op::P256Verify => self.p256,
            Op::Sha256 => self.sha256,
            Op::Ripemd160 => self.ripemd160,
            Op::Blake2f => self.blake2f,
            Op::Bn256 => self.bn256,
            Op::Bls12381 => self.bls12381,
            Op::Kzg => self.kzg,
            Op::Unknown => false,
        }
    }
}

/// The stock Ethereum precompiles behind a [`Profile`].
///
/// A refused call keeps the gas the charge already took and loses its output,
/// which is what Go produces: `runPrecompile` returns `(nil, suppliedGas, err)`
/// after the deduction. Running the precompile and then discarding its answer
/// gives the same observable result as never running it, because a precompile
/// touches nothing but its own input — and it keeps the gas schedule in one
/// place, revm's, rather than in a second table here that could drift.
#[derive(Clone, Debug)]
pub struct Precompiles {
    inner: EthPrecompiles,
    profile: Profile,
}

impl Precompiles {
    /// The precompiles for `spec` under `profile`.
    pub fn new(spec: SpecId, profile: Profile) -> Self {
        Self {
            inner: EthPrecompiles::new(spec),
            profile,
        }
    }

    /// The family the precompile at `address` belongs to, if one lives there.
    pub fn op(&self, address: &Address) -> Option<Op> {
        self.inner.precompiles.get(address).map(|p| Op::of(p.id()))
    }

    /// The profile this set is gated by.
    pub const fn profile(&self) -> Profile {
        self.profile
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for Precompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.inner, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        // Read the family before running: the borrow on the set ends with the
        // call, and an address alone does not say which implementation answered.
        let op = self.op(&inputs.bytecode_address);
        let mut run = self.inner.run(context, inputs)?;

        if let (Some(op), Some(out)) = (op, run.as_mut()) {
            // A call that could not pay never reached the gate in Go either:
            // the gas check comes first and returns out-of-gas.
            if out.result != InstructionResult::PrecompileOOG && self.profile.forbids(op) {
                out.result = InstructionResult::PrecompileError;
                out.output = Bytes::new();
            }
        }
        Ok(run)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.inner.warm_addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: SpecId = SpecId::SHANGHAI;

    fn at(byte: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = byte;
        Address::from(a)
    }

    #[test]
    fn every_stock_address_classifies_the_way_go_does() {
        let p = Precompiles::new(SpecId::PRAGUE, Profile::default());
        for (byte, want) in [
            (1u8, Op::Ecrecover),
            (2, Op::Sha256),
            (3, Op::Ripemd160),
            (4, Op::Unknown),
            (5, Op::Unknown),
            (6, Op::Bn256),
            (7, Op::Bn256),
            (8, Op::Bn256),
            (9, Op::Blake2f),
            (0x0a, Op::Kzg),
            (0x0b, Op::Bls12381),
            (0x0c, Op::Bls12381),
            (0x0d, Op::Bls12381),
            (0x0e, Op::Bls12381),
            (0x0f, Op::Bls12381),
            (0x10, Op::Bls12381),
            (0x11, Op::Bls12381),
        ] {
            assert_eq!(
                p.op(&at(byte)),
                Some(want),
                "the precompile at 0x{byte:02x} is classified wrongly"
            );
        }
    }

    #[test]
    fn identity_and_modexp_are_ungated() {
        let p = Precompiles::new(SPEC, Profile::strict());
        for byte in [4u8, 5] {
            let op = p.op(&at(byte)).unwrap();
            assert_eq!(op, Op::Unknown);
            assert!(
                !Profile::strict().forbids(op),
                "Go's opForPrecompile has no case for 0x{byte:02x}, so no profile refuses it"
            );
        }
    }

    #[test]
    fn the_lux_profile_is_strict_less_bn256() {
        let lux = Profile::lux();
        assert!(!lux.forbids(Op::Bn256), "the Ethereum-compat carve-out");
        for op in [
            Op::Ecrecover,
            Op::P256Verify,
            Op::Sha256,
            Op::Ripemd160,
            Op::Blake2f,
            Op::Bls12381,
            Op::Kzg,
        ] {
            assert!(lux.forbids(op), "{op:?} must still be refused");
        }
    }

    #[test]
    fn no_profile_refuses_anything_by_default() {
        let d = Profile::default();
        for op in [
            Op::Ecrecover,
            Op::P256Verify,
            Op::Sha256,
            Op::Ripemd160,
            Op::Blake2f,
            Op::Bn256,
            Op::Bls12381,
            Op::Kzg,
            Op::Unknown,
        ] {
            assert!(!d.forbids(op), "a nil profile is classical semantics");
        }
    }

    #[test]
    fn an_address_with_no_precompile_has_no_family() {
        let p = Precompiles::new(SPEC, Profile::default());
        assert_eq!(p.op(&at(0xff)), None);
    }
}
