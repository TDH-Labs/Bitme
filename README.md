# Bitme Cosigner

A self-hosted, policy-gated Bitcoin co-signing service. It holds one key in a 3-key miniscript
wallet and countersigns PSBTs only when policy allows - it can never spend alone, never
initiates a transaction, and never finalizes or broadcasts anything itself.

## The wallet model

Three keys, two spending paths:

- **SATOCHIP** (smartcard) - required for every spend.
- **MOBILE** (Bitcoin Keeper app) - paired with SATOCHIP for the **RECOVERY** path, after a
  relative timelock (default ~90 days). Works even if this service is gone permanently.
- **SERVER** (this service) - paired with SATOCHIP for the **HOT** path, immediately, but only
  after passing policy.

No single key, and no pair excluding SATOCHIP, can ever spend - see `src/invariants.rs` for the
formal proof.

## What it does

1. **Inspects** an untrusted PSBT: what's being spent, where it's going, the fee, which path it
   uses - trusting nothing the PSBT claims that can be independently verified against the chain.
2. **Evaluates policy**: per-transaction and rolling day/week/month spend caps, max fee, an
   optional destination whitelist. Above-threshold spends are refused outright - there is no
   override.
3. **Notifies, holds, and only then signs**: an approved spend is queued, a notification goes
   out (ntfy and/or email), and it's only actually signed once the hold elapses with no veto
   (`POST /veto/{id}`).
4. **Never changes its own rules unsupervised**: the policy itself can only be changed at
   runtime via a signature from the SATOCHIP key (standard Bitcoin "Sign Message" format),
   durably versioned and replay-proof.

## HTTP API

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Service status, network, current policy version |
| `/inspect` | POST | Parse a PSBT into inputs/outputs/fee/spending path |
| `/sign_psbt` | POST | Inspect, evaluate policy, queue for signing (or replay an already-signed one) |
| `/sign_psbt/{id}` | GET | Poll a queued spend's status |
| `/veto/{id}` | POST | Cancel a still-pending spend before it's signed |
| `/policy` | GET | Current policy and its version |
| `/policy` | POST | Propose a SATOCHIP-authorized policy change |

No web UI - this is an API-only service, by design.

## Running it

- **[docs/DOCKER.md](docs/DOCKER.md)** - Docker Compose, for local testing on a Mac or a real
  VPS deployment.
- **[docs/UMBREL.md](docs/UMBREL.md)** - installing on Umbrel via a community app store.

Either way: **start on signet.** This service refuses mainnet unless
`i_understand_this_is_mainnet = true` is explicitly set in its config - don't set that until
you've verified your whole setup end-to-end.

## Hard rules

- Signet or regtest by default; mainnet requires explicit opt-in.
- This service never generates keys - SATOCHIP, MOBILE, and SERVER keys are all provided, not
  created here.
- The server's private key is never logged; it's loaded from a file or environment variable and
  best-effort zeroized on drop.
- Every spend is policy-checked with no override path.

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt
```

`cargo run -- descriptor build --config examples/signet-demo.toml` builds and validates a
descriptor from a config without needing a running server or a node.

`cargo test` alone only runs the ~117 mocked-chain unit tests. Two integration test files run
against a *real* regtest `bitcoind` and skip gracefully (not a failure) without one -
`tests/regtest_inspect.rs`'s doc comment has the exact command. `tests/regtest_full_flow.rs` is
the important one: it proves the whole notify-hold-sign flow, a live veto, and a live
SATOCHIP-authorized policy change against a real node, ending in an actual signature-satisfies-
the-descriptor check - not just an HTTP 200.
