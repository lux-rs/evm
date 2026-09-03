# lux-rs/evm

## What is here

`lux-evm`: the Lux EVM in Rust. revm is the machine; the Lux rules are values on
top of it. It executes real blocks, computes the roots a header commits to, and
names a block the way the network names it.

- `src/rules.rs` — the four rules that make Lux not Ethereum, as one value.
- `src/handler.rs` — those rules in the two places revm asks about them.
- `src/gas.rs` — what a transaction owes before it runs.
- `src/precompile.rs` — the stock precompiles behind the classical-family gate.
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
