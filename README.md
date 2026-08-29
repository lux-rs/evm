# lux-evm

The Lux EVM in Rust.

Go is the network. `luxfi/geth` and `luxfi/evm` decide what a block means; this
crate exists to arrive at the same answer from Rust — same gas, same balances,
same roots, same block hashes.

## What it is

revm is a dependency, not a fork. Three implementations of one protocol are
already two more than the protocol needs, and a fourth interpreter maintained
here would be a fifth thing to keep in step. Everything Lux changes is reachable
through revm's own seams, so the crate is four small things:

| module       | what it holds                                                     |
| ------------ | ----------------------------------------------------------------- |
| `rules`      | the three rules that make Lux not Ethereum, as one value           |
| `handler`    | those rules in the two `Handler` methods that ask about them       |
| `precompile` | the stock precompiles behind the classical-family gate             |
| `header`     | how a block is named: `keccak256(rlp(header))`                     |
| `root`       | what a block commits to: the transaction, receipt and state tries  |

The three rules, with the Go they come from:

- **No refunds.** `luxfi/evm core/state_transition.go refundGas` applies the
  refund counter only `if !isEVM`, so `gasUsed == gasSpent` on every Lux block.
- **The whole fee, not the tip.** The beneficiary is credited
  `gasUsed * gasPrice`; Ethereum credits `gasUsed * (gasPrice - baseFee)` and
  burns the difference.
- **The split.** Once `IsFeeSplit(blockTime)`, `core/fee_split.go creditTxFee`
  credits `floor(fee/2)` and the other half is burned by never being credited.

## What is checked

`cargo test` runs three kinds of check.

Against the Go corpus at `luxfi/conformance` — set `LUX_VECTORS` to point at a
vectors directory, or leave it and the harness looks beside this crate:

- the genesis header built in Rust encodes to **byte-identical RLP** and seals
  to the block hash the live node reports;
- the transactions root over five signed transactions of four types is the root
  Go derives, including the EIP-2718 envelopes that are easy to wrap wrongly.

Against real execution, through revm with this handler installed:

- Lux pays the beneficiary the whole fee and Ethereum burns the base fee;
- Lux discards the storage-clear refund and Ethereum keeps it;
- a refused precompile still costs the caller the gas it forwarded, and the
  bn256 carve-out at 0x06–0x08 still answers under the Lux profile.

And as unit tests, the rules and the family classification on their own.

## What is not here yet

- **A `Database` over real state.** The trie functions compute roots from
  accounts; nothing yet holds those accounts across blocks.
- **The post-quantum precompiles** at `0x012201`–`0x012208` and `0x012220`.
  They are not active on any chain serving traffic today. When they are, the
  right move is to dispatch them to `libluxprecompile.so` rather than write
  the cryptography a second time — a second implementation of a signature
  scheme is a second thing that can disagree.
- **`luxfi/evm`'s stateful precompiles** — warp, the allow lists, the fee and
  reward managers.
