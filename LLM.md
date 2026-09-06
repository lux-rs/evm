# lux-rs/evm

## What is here

`lux-evm`: the Lux EVM in Rust. revm is the machine; the Lux rules are values on
top of it. It executes real blocks, computes the roots a header commits to, and
names a block the way the network names it.

- `src/rules.rs` — the four rules that make Lux not Ethereum, as one value.
- `src/handler.rs` — those rules in the two places revm asks about them.
- `src/gas.rs` — what a transaction owes before it runs.
- `src/precompile.rs` — which precompile answers where, and at what price.
- `src/state.rs` — the world the roots are taken over.
- `src/block.rs` — `run` (the ONE interpreter call), `apply`, `execute`, `call`.
- `src/header.rs` — the three shapes a C-chain header has, and their RLP.
- `src/genesis.rs` — block zero, as a document.
- `tests/headers.rs` — 21 real mainnet headers, decoded and re-named.

## Decisions worth not relitigating

- **A root is a Merkle-Patricia trie, never a digest over a sorted list.**
  `state::World` holds every account and hashes them through `alloy-trie`. Two
  rules a naive store gets wrong and that both move the root: a zero slot is an
  ABSENT slot, and an empty account (EIP-161) is an ABSENT account.

- **The genesis is checked against Go, not against ourselves.** `luxfi/genesis`
  records mainnet's state root `0x2d1cedac…` and hash `0x3f4fa2a0…`; both come
  out of `World` unchanged. A live node's own numbers are checked too — see the
  node repo's `genesis::luxd_conformance`.

- **A block is named by the SHAPE it is.** The C-chain has accepted three:
  16 fields at genesis (through `baseFeePerGas`), 17 for ordinary blocks
  (`blockGasCost`), and 20 later (`withdrawalsRoot`, `blobGasUsed`,
  `excessBlobGas`, `parentBeaconBlockRoot`). The seventeenth position is a
  QUANTITY in one shape and a HASH in another, so the shape is read per header
  rather than declared once. `header::Lux` encodes and DECODES all three —
  decoding matters, because alloy alone takes a seventeenth field for a
  withdrawals root and refuses it for being the wrong width.

- **The RPC lies in both directions about the header.**
  `eth_getBlockByNumber` REPORTS `blockGasCost` for a block whose preimage does
  not contain it, and does NOT report `withdrawalsRoot`, which is in the
  preimage. Believing it on either count names every block wrongly.
  `difficulty` is 0 at genesis and 1 after it.

- **`seal_bytes` hashes what arrived.** Re-encoding a decoded header to name it
  is a chance to name it differently — a field this crate does not model would
  round-trip to a different preimage.

- **`Checks` is a value, not a flag.** Consensus asks "may this be in a block",
  where paying is the point; a simulation asks "what would this do", where the
  caller is not paying. `Checks::Simulated` sets aside the three rules about
  paying and NOTHING else, and is only reachable through `block::call`, which
  takes the world by value so discarding the result is structural.

- **`block_gas_cost` is supplied, not derived.** Go computes it from a fee
  schedule this crate does not model. Every network here sets that schedule to
  zero and the mainnet history agrees, so zero is right for them; a network with
  a real schedule needs the formula first.

- **chainId is genesis data.** Mainnet 96369, localnet 31337. A node that
  compiles one in replays onto whichever network it was built for.

- **The C-chain's BLS12-381 is the PRE-FINAL EIP-2537 assignment.** G1Add,
  G1Mul, G1MSM, G2Add, G2Mul, G2MSM, Pairing at 0x0b–0x11
  (`luxfi/precompile@v0.19.21 bls12381/contract.go`). revm's set is the final
  one, so from 0x0c onward the same address names a different operation in
  each: 0x0d is a G1 multi-scalar multiplication to the chain and a G2 addition
  to revm. The chain has no map-to-curve precompile at all. Mainnet has had all
  seven since 2025-12-26 and changing them is a hard fork, so the port follows
  the chain rather than the EIP.

- **A module SHADOWS the Ethereum precompile at its address.** Go asks
  `LuxPrecompileOverrider` before the standard table, so at an address both
  claim the standard table never answers.

- **Registered is not enabled.** The Go registry holds ~56 modules; a chain
  serves only the ones its `upgrade.json` lists under `precompileUpgrades`.
  Every Lux network lists the seven BLS keys; none lists `secp256r1Config`, so
  0x0100 answers nothing on any Lux chain and is deliberately absent from
  `MODULES`. The precompile differential's Go evaluator asks the registry
  rather than an enabled set and therefore serves 0x0100 at 3450 — a price no
  Lux chain charges. That is a fact about the harness, not about a chain.

- **A module is outside the classical gate.** `opForPrecompile` type-switches
  on the implementation and has no case for the `precompileAdapter` an
  overrider installs, so every module falls to `Op::Unknown`, which no profile
  refuses. The consequence is real and is Go's: a strict-PQ chain still serves
  BLS12-381 at 0x0b–0x11.

- **Price and work are stated apart, because Go deducts before it reads.**
  `contract.DeductGas` runs at the top of every module's `Run`, so a call that
  reads its input and then refuses it has still paid. revm computes a
  precompile's price inside the function that does the work and its error
  carries no charge, so `Module` keeps `gas` and `run` as two fields.

- **Go checks the BLS subgroup on the additions and the final EIP-2537 does
  not.** One `decodeG1`/`decodeG2` serves all seven Go operations and both
  check `IsInSubGroup`; revm's `g1_add`/`g2_add` follow the final text and skip
  it. An on-curve point outside the r-order subgroup is therefore accepted by
  revm and refused by the chain. `subgroup_g1`/`subgroup_g2` close that by
  handing the point to revm's MSM with a zero scalar, which validates it and
  then computes nothing.
