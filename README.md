# securetheoption

Presigned option-mint offers for the [Chia](https://www.chia.net) blockchain.

A maker commits a backing coin by **presigning** the spends that would mint an option contract and lock
its underlying, then publishes those spends as an ordinary Chia offer. Nothing happens on chain until a
taker accepts — at which point the option, the underlying lock and the premium payment all settle
atomically. Because the terms live only in the unbroadcast bundle, re-pricing a quote is just a
re-sign.

The tool is **offline end to end**: quote creation, offer sealing and verification never open a socket,
and signing is delegated to an external signer. Nothing in this repository persists a mnemonic or a
secret key.

## Layout

| Crate | Path | What it is |
| --- | --- | --- |
| `securetheoption` | `crates/securetheoption` | The library: terms resolution, quote preparation, offer/CAT construction, spend-bundle verification, and a local quote book. |
| `securetheoption-cli` | `crates/securetheoption-cli` | The `securetheoption` binary: one subcommand per step of a quote's life. |

## Requirements

A Rust toolchain that supports the 2024 edition (Rust 1.85 or newer). `chia-wallet-sdk` resolves from
crates.io, so a clone builds with no external checkouts.

```sh
cargo build --release
# binary: target/release/securetheoption
```

## Quick start

Every command is a subcommand of `quote`. The lifecycle is:

```
prepare  ──▶  create  ──▶  (external signer)  ──▶  seal  ──▶  verify
```

**1. Write a draft.** Human units only — decimal XCH, `30d`-style deadlines, bech32m addresses.

```json
{
  "maker_public_key": "0x…",
  "underlying": {
    "kind": "xch",
    "coin": {
      "parent_coin_info": "0x…",
      "puzzle_hash": "0x…",
      "amount": 189899999999
    },
    "amount": "0.05"
  },
  "strike": {
    "kind": "cat",
    "asset_id": "0x…",
    "amount": 1000
  },
  "expiry": "7d",
  "take_by": "1h",
  "premium": {
    "kind": "cat",
    "asset_id": "0x…",
    "amount": 500,
    "recipient": "xch1…"
  }
}
```

**2. Resolve and preview.** `prepare` turns the draft into terms and prints what they commit to. It
never writes the quote book — a preview is not a commitment.

```sh
securetheoption quote prepare --draft draft.json --output terms.json
```

**3. Precompute the bundle** for your signer. This is where the backing coin is booked.

```sh
securetheoption quote create --terms terms.json --output unsigned.json
```

**4. Sign out of process.** `unsigned.json` carries the required-signature material — for BLS, the
public key and the full message including its domain-separation suffix. Use whatever signer you
already trust.

**5. Seal** the signed bundle into a landable offer plus the plaintext sidecar a taker verifies against.

```sh
securetheoption quote seal --terms terms.json --signed signed.json --output quote
# writes quote.offer (bech32 offer1…) and quote-sidecar.json
```

**6. Verify** any offer against the terms it claims to encode.

```sh
securetheoption quote verify quote.offer quote-sidecar.json
```

## Commands

| Command | Purpose |
| --- | --- |
| `quote prepare` | Resolve a friendly draft into terms and preview the commitment. |
| `quote create` | Precompute a quote and emit the unsigned maker bundle for a signer. |
| `quote seal` | Bind a signature into a landable offer plus its sidecar. |
| `quote verify` | Check a published offer against the terms it claims to encode. |
| `quote list` | Show every booked quote. |
| `quote requote` | Replace a booked quote with new terms over the same backing coin. |
| `quote retire` | Stop advertising a quote locally. |

Common flags: `--network mainnet|testnet11` (address prefix and `AGG_SIG_ME` domain separation
constants — a signature is only valid on the network it was made for), `--format offer|json`, and
`--json` on the commands that have a human-readable default.

## How verification works

`verify` re-derives the terms from scratch and compares them against what the offer actually commits
to, so a taker never has to trust a puzzle reveal or a number the maker printed. The check is **strict
where the terms are precise** — the premium and the take-by deadline must be present exactly once and
must be the ones the terms name — and **reported** where the tool has no model for a condition, since
an unusual condition is not necessarily a wrong offer.

It deliberately does **not** check signatures. A wrong signature is not the verifier's to find:
validity is the network's concern, and a bad signature fails at take time, after which nothing has
moved.

The commitment tiers are made explicit in the `prepare` preview:

- **hash-committed** — what the option's hashes bind (amounts, strike, underlying, puzzle hashes).
- **signature-committed** — what only the maker's signature binds (`take_by_seconds`, `premium`).
- **not bound** — values the maker reads that no hash and no signature covers.

## The quote book

`quotes.json` (configurable via `--book`) records which backing coins are already committed, and to
what. It exists for one reason: a maker must not presign two different quotes over the same backing
coin, because both would be landable, only one can ever land, and the coin would be committed twice
from the maker's own point of view. A second live quote over a booked coin is a hard error.

It is deliberately small — one JSON file, rewritten through a staging file on every mutation — and
assumes a **single writer**. Cross-process locking is out of scope. Retiring is local bookkeeping only:
nothing here can stop an already-published offer from landing.

## Security model

- No secret key, mnemonic or API token is persisted, logged or defaulted. Signing is always external.
- Every `SecretKey` in the tree is a deterministic test fixture behind `#[cfg(test)]`.
- The library has no network capability; the CLI links no async runtime and no coinset client, because
  every command is offline.
- `seal` re-derives the bundle from the terms before accepting a signature, so a signer that returned a
  different bundle is rejected rather than sealed silently.

Found a security issue? Please open an issue rather than a pull request disclosing details publicly.

## Testing

```sh
cargo test --workspace
```

The suite includes a simulator integration test (`crates/securetheoption/tests/simulator.rs`) that
exercises the full seal → verify → take path for both XCH-backed and CAT-backed quotes, and checks that
the maker bundle alone is not landable and that an offer stops landing after its take-by deadline.

## License

Apache-2.0. See [LICENSE](LICENSE).
