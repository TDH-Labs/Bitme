# Bitme Cosigner

Bitme Cosigner holds one key in a 3-key Bitcoin wallet, running on hardware you control. It only
signs a transaction when your policy allows it. Root the box, and there still isn't a usable key
sitting on it: two signatures move funds here, and the server only ever holds one of them.

It's basically the third signer you'd have in an ordinary 2-of-3 wallet. Here, you're the one
running it. You picked its rules, and the code behind it is sitting in this repo for you to read.

> **Status: signet only.** The service refuses to run on mainnet unless you explicitly opt in,
> and you shouldn't opt in until you've run the whole thing end to end. See
> [Current status](#current-status) for exactly what is and isn't finished.

---

## Contents

- [The idea](#the-idea)
- [The wallet](#the-wallet)
- [Which devices work](#which-devices-work)
- [How a spend actually works](#how-a-spend-actually-works)
- [Recovery: losing a device](#recovery-losing-a-device)
- [Recovery contacts](#recovery-contacts)
- [Where Nostr fits](#where-nostr-fits)
- [How it compares to Bitkey](#how-it-compares-to-bitkey)
- [HTTP API](#http-api)
- [Running it](#running-it)
- [Threat model](#threat-model)
- [Current status](#current-status)

---

## The idea

A single-key wallet has one big flaw. Lose the device, or just fat-finger something at 2am, and
the coins go with it. Multisig gets rid of that single point of failure. Now you're juggling
several keys, and none of them are watching what gets signed before it ships.

Bitme's third signer is a policy engine loaded with your spending limits. It pages you before it
signs anything you didn't pre-approve. You also get a window to kill the signature before it
goes out, if something looks wrong. That signer is baked into the wallet itself, as a real key,
so its checks aren't something a compromised app could route around.

A few things hold regardless of what happens to the server:

1. **It can't spend on its own, full stop.** Even fully rooted, it's still just one of the two
   keys a spend needs.
2. **Lose the server for good and your coins are untouched.** Two other paths reach them, and
   neither needs it.
3. **Starting a transaction isn't something it can do.** Someone else builds one first. This
   thing only ever signs what's already sitting there.

Bitcoin's consensus rules enforce all three. Each one also has a
[machine-checked proof](bitme-cosigner/src/invariants.rs) in the code, run on every build.

---

## The wallet

Three keys:

| Key | Lives on | You use it via |
|---|---|---|
| **HARDWARE** | An offline signing device you keep | Tap / plug / scan, via your wallet app |
| **MOBILE** | A wallet app on your phone | The app |
| **SERVER** | This service, on your own box | Automatically, under policy |

These are **roles, not products.** Which specific device and which phone app can fill them is a
narrower question than it looks — see [Which devices work](#which-devices-work) before you buy
anything or fund anything.

The rule is: **any two of the three can spend, but anything involving the phone key waits 30
days.**

```mermaid
flowchart LR
    subgraph FAST["Immediately"]
        A1[HARDWARE] --- S1[SERVER]
    end
    subgraph SLOW["After 4320 blocks (~30 days)"]
        A2[HARDWARE] --- M2[MOBILE]
        M3[MOBILE] --- S3[SERVER]
    end
    FAST --> SPEND([Spend])
    SLOW --> SPEND
    ONE[Any single key alone] -.->|never, no matter how long| X([Cannot spend])
```

Which gives exactly three ways to move money:

| Combination | When | What it's for |
|---|---|---|
| HARDWARE + SERVER | Immediately | **Everyday spending.** The only path the server co-signs on demand, and the only one that's policy-gated. |
| HARDWARE + MOBILE | After ~30 days | **The server died.** Your VPS burned down, or you shut it off. You don't need it. |
| MOBILE + SERVER | After ~30 days | **The hardware died.** Lost, snapped, demagnetised. |

The descriptor:

```
wsh(thresh(2,pk(HARDWARE),s:pk(SERVER),snj:and_v(v:pk(MOBILE),older(4320))))
```

**Why the timelock is on the phone key.** It keeps the policy engine meaningful: the only way
to spend without satisfying a 30-day-deep timelock is HARDWARE + SERVER, so there's no routing
around your own rules for day-to-day spending.

Note that **daily spending never involves the phone key at all** — the timelock bars it at the
consensus layer. The app holding your mobile key and the app driving your hardware don't have
to be the same app, or even know about each other.

⚠️ **Read this carefully — it is the most misunderstood part of the design.** `older(N)` is a
*relative* timelock (BIP68). It requires **that coin to be 4320 blocks deep**, not that 30 days
pass from now. Coins you received last week are locked out of the recovery paths; coins that
have been sitting for six months satisfy it **already, right now**.

So for a mature wallet, the recovery paths are open immediately, and the timelock is *not* a
30-day alarm window. What actually protects mature coins on the no-hardware path is the
server-side hold, the notification, and your veto — which is why `[recovery] hold_seconds`
defaults to 48 hours rather than minutes, and why an offline destination whitelist is worth
setting.

**Why 30 days.** It's baked into your addresses, so it's a hard floor on how long a *fresh
deposit* stays unrecoverable, and changing it later means moving your coins. Long enough to
matter; short enough that recovery isn't a season of your life.

> **An earlier version of this design was wrong** and it's worth saying so. It required the
> HARDWARE key for *both* paths, which meant losing that one device — with no seed backup — lost
> the funds permanently. That's a single point of catastrophic failure. The shape above fixes it:
> every single-device loss is survivable. There's a test named
> [`every_pair_can_eventually_spend`](bitme-cosigner/src/invariants.rs) that fails the build if that ever
> stops being true.

---

## Which devices work

**Read this before you buy hardware or fund an address.** It is the most likely way to end up
with a wallet you cannot spend from.

The descriptor above is miniscript. It's a perfectly standard P2WSH output — it relays and
confirms like anything else — but it is **not** `sortedmulti()`, which is what most wallet
software means by "multisig". So two separate things have to be true:

1. Some app has to **import and track** a `thresh`/`older` descriptor.
2. Something has to **drive your hardware device** to sign for it.

Those are different capabilities held by different software, and the intersection is small.
Both vendors can advertise "miniscript support" and still leave you unable to spend.

A concrete example, and the one this project was originally built around:

| | Tracks a miniscript descriptor | Drives a Satochip |
|---|---|---|
| Bitcoin Keeper | ✅ | ❌ |
| Sparrow | ❌ ([open issue](https://github.com/sparrowwallet/sparrow/issues/1700)) | ✅ |

Neither does both. That combination produces a wallet you can *recover* from but very likely
cannot *spend* from — and it isn't visible from either product's feature list.

Currently understood to work as the HARDWARE key, with Bitcoin Keeper as the coordinator:
**Coldcard, Blockstream Jade, Ledger, BitBox02, Tapsigner.** Known not to work: **SeedSigner**
(`sortedmulti` only) and **Satochip** (no miniscript-capable coordinator drives it).

Two more things that catch people:

- **Message signing is a separate requirement.** `POST /policy` and `POST /unfreeze` need a
  Bitcoin signed message from the hardware key. A device can be perfectly fine for spending and
  still leave you changing spending limits from a shell on the box.
- **Check the first address.** Whatever you use, confirm your wallet app's first receive address
  matches the one the setup wizard shows. A mismatch means a mistyped xpub or a descriptor the
  app silently reinterpreted. It costs nothing and it catches nearly everything.

Full capability model, the data schema behind it, and the verification procedure a device has to
pass before it's called supported: **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)**.

> **The setup wizard checks this for you.** Its second step asks which wallet app and which
> hardware signer you're using, resolves every spending path against them, and blocks a
> known-broken pairing until you tick a box saying you understand exactly what won't work. Every
> device stays on the list with its verdict shown — nothing is hidden. Still verify on signet
> before funding anything: the matrix says what software *claims*, not what your firmware does.

---

## How a spend actually works

**The hardware key never talks to the server.** An offline signing device has no networking — no
WiFi, no Bluetooth, nothing that reaches the internet. It only ever talks to whatever taps or
plugs into it: your phone over NFC, a card reader, a USB cable, a QR scan. Every
"HARDWARE + SERVER" spend is really two separate, disconnected steps stitched together by a PSBT
file that your wallet app carries between them — never a live connection between the device and
this service.

The server never signs the moment you ask, either way. It queues, it tells you, it waits, and
only then does it sign - so a signature is never the first you hear about a transaction.

```mermaid
sequenceDiagram
    participant SC as Your hardware key
    participant You as Your wallet app
    participant CS as Cosigner
    participant Node as Your bitcoind
    participant N as Notification

    Note over SC,You: Tap / plug / scan - purely local, no network
    SC->>You: Partial signature (HARDWARE's share)
    You->>CS: POST /sign_psbt (HARDWARE's signature already attached)
    CS->>Node: Are these coins real? Whose are they?
    Node-->>CS: UTXO details
    Note over CS: Re-derives every address itself.<br/>Never trusts what the PSBT claims.
    CS->>CS: Check against policy
    alt Over your limits
        CS-->>You: 422 denied — nothing queued, nothing signed
    else Allowed
        CS->>N: "Pending spend: 50,000 sat to bc1q… — signs in 15 min"
        CS-->>You: 202 Accepted + id
        Note over CS: Holding. You can POST /veto/{id}
        alt You veto
            CS->>CS: Cancelled permanently
        else Hold elapses
            CS->>CS: Re-check policy against live state
            CS->>CS: Add the SERVER signature
            CS-->>You: PSBT with both signatures — 2 of 3, spendable
        end
    end
    Note over You: You broadcast. The server never does.<br/>Notice the hardware key only ever appears in the top line.
```

The cosigner never talks to the hardware key either — as far as this service is concerned,
"HARDWARE signed" just means *a PSBT arrived with a valid signature under that key already in
it*. It has no way to reach the device, ask it to sign, or know it exists except through that
signature. Your wallet app is the only thing that talks to both sides — locally to the device,
over the network to the cosigner — and a PSBT file is the only thing that ever crosses between
them.

This is also why the hardware side of [device compatibility](#which-devices-work) is entirely
your wallet app's problem, never this service's: it only ever sees signatures, not devices.

Some specifics that matter:

- **It re-derives everything.** A PSBT is untrusted input. Amounts, addresses, and which outputs
  are really your change all get checked against your own node — a transaction that *claims* an
  output is change gets rejected if the address doesn't actually derive from your wallet.
- **Policy is checked twice**, once when you submit and again the instant before signing. Two
  transactions submitted together can't both slip under one shared limit; the second gets denied
  at signing time when the first has already consumed the budget.
- **Killing the server doesn't cancel a pending spend.** The queue is on disk. Restart it and
  anything whose hold has elapsed gets signed. To stop something, veto it.
- **Signing is atomic with recording.** The spend is written to the ledger in the same database
  transaction as the signature, so a crash can't produce a signature nobody counted.

Policy knobs: per-transaction cap, rolling daily/weekly/monthly caps, max fee, max fee rate,
optional destination whitelist. Over the line is a hard refusal — there is no override.

Changing those rules requires a signature from your **hardware key** (standard Bitcoin signed
message), is versioned, and rejects replays of old authorisations. A compromised server can't
quietly raise its own limits. Not every signing device can produce one — see
[Which devices work](#which-devices-work).

---

## Recovery: losing a device

**The unavoidable part first.** You cannot revoke a key from coins that already exist — the key
is baked into the address. Replacing a device means *building a new wallet and moving your coins
to it*. Bitkey works exactly this way too; every one of their recoveries mints a new key set and
sweeps on-chain. Anyone claiming otherwise is selling something.

So there are two different questions, and it's worth keeping them apart:

**"Can I still get my money?"** — yes, from any two keys:

```mermaid
flowchart TD
    START{What did you lose?} 
    START -->|Phone| P[HARDWARE + SERVER<br/>spend immediately]
    START -->|Hardware key| H[MOBILE + SERVER<br/>after ~30 days]
    START -->|Server| S[HARDWARE + MOBILE<br/>after ~30 days]
    START -->|Two of them| D[Gone.<br/>2-of-3 needs two.]
    P --> SWEEP[Sweep to a fresh wallet<br/>with a replacement key]
    H --> SWEEP
    S --> SWEEP
```

**"Can I stop the lost device from working?"** — only by sweeping. Until the coins move, the old
key still signs. What the server can do is refuse to co-sign anything except your escape
transaction while you get organised.

### Back these up

Losing a *seed* is much worse than losing a *device* — a device is replaceable from its seed.
You need:

1. **Hardware seed** — however your device backs up: written down, a steel plate, a SeedKeeper
   card.
2. **Mobile seed** — your phone wallet's own backup.
3. **Server xprv** — generated on the box by the setup wizard from kernel entropy, and written
   to `server.xprv` next to your config. It exists in exactly one place until you back it up.
   See [docs/KEY-GENERATION.md](docs/KEY-GENERATION.md).
4. **The descriptor itself.** ⚠️ Easy to forget and fatal to lose. In a multisig, all three keys
   plus no descriptor equals no money — you can't reconstruct the script. It lives in your
   `wallet.toml`; if that's only on the VPS, one dead server and you're locked out despite
   holding everything.

Bitkey solves #4 with an encrypted descriptor backup on their servers, and #3-equivalent with an
"Emergency Exit Kit" PDF in your cloud storage. Ours is a **recovery kit** — `wallet.toml` plus the
SERVER xprv, `age`-encrypted with a passphrase:

```sh
cosigner recovery-kit export --config wallet.toml --passphrase-file pass.txt --out kit.age
cosigner recovery-kit import --in kit.age --passphrase-file pass.txt \
  --out-config restored.toml --out-server-key restored.xprv
```

Store `kit.age` somewhere other than the box it came from — a second machine, a paper/QR backup,
or Nostr relays (below). It backs up the *box*, not the other two keys: your hardware device and
your phone wallet already have their own seed backups, so this has nothing to add there.

⚠️ **This blob contains the SERVER xprv.** If you publish it to public relays, treat the
passphrase as load-bearing: someone who breaks it holds one of your three keys. That alone can't
move coins, but combined with a compromised phone it's the MOBILE + SERVER path. Use a long
passphrase.

---

## Recovery contacts

**Optional, off by default.** People you name can vouch for you, by quorum, to release a queued
spend's remaining hold.

```toml
[recovery_contacts]
npubs = ["npub1alice…", "npub1bob…", "npub1carol…"]
threshold = 2
```

**What a quorum can do:** bring forward the hold on a spend this service had already queued and
already approved.

**What a quorum cannot do — and this is the whole design:** create a spend, raise a cap, change
your policy, redirect a destination, or revive something you vetoed. Policy is re-evaluated from
scratch when the spend actually fires, whatever made it due. Every consensus rule is untouched.
Your contacts hold no key material; losing one loses nothing, and a hostile one costs you a
single vote.

That boundary is deliberate. This service's central claim is that its delay is a *consensus*
rule, not a server promise. A social-recovery feature that could authorise spending would hand
that straight back — so the quorum is wired to the one thing that genuinely is just a server-side
timer.

**Threshold must be at least 2.** A threshold of 1 means any single contact acting alone, which
isn't meaningfully different from having none.

**How a contact vouches:** they sign an ordinary Nostr event whose content is the approval
message for that transaction id — the thing every Nostr client and browser extension already
does. No account with you, no software to install beyond a Nostr client, no key of yours in their
hands. An approval is bound to one transaction id, so it can't be replayed against a later spend.

The realistic friction: your contacts need to be able to sign with a Nostr key. If they're your
non-technical relatives, test that with one person before relying on it.

---

## Where Nostr fits

Nostr is **not** a key here, and it never will be. Nostr keys live in browser extensions and get
pasted between apps; making one a spending key would hand your money to whoever compromises your
social identity. Its job is **addressing and transport**. Two uses, both real:

### 1. Talking to the cosigner without exposing it

**Built.** Reaching the service over HTTP means an open port — on a home box that's
port-forwarding, a domain, a certificate.

Instead, `[nostr_transport]` gives the cosigner its own Nostr identity, connecting **outward**
to relays and receiving requests as NIP-17 gift-wrapped private messages (`{"method", "path",
"body"}`, mirroring the HTTP API one-to-one). Each message is dispatched straight into the same
`axum::Router` the HTTP server itself runs — the same policy, signing, and freeze logic, just a
different door — so the two transports can never drift apart. It's the same pattern NIP-46
already uses for remote Nostr signing, applied to Bitcoin PSBTs.

```mermaid
flowchart LR
    subgraph HOME["Your home / VPS — no open ports"]
        CS["Cosigner<br/>npub1cosigner…"]
    end
    PHONE["Your phone<br/>npub1you…"]
    LOST["Stolen phone<br/>npub1old…"]
    R(("Nostr relays"))

    PHONE -->|"encrypted DM"| R
    LOST -->|"encrypted DM"| R
    R -->|"outbound only"| CS
    CS -->|"on allowlist ✓"| OK([signs])
    CS -->|"not on allowlist ✗"| NO([ignored])
```

What that buys:

- **No inbound ports.** Nothing exposed, no forwarding, no certificate, no dynamic DNS.
- **Authentication for free.** Every message is signed by its sender. Only npubs on your
  allowlist get processed — the signature *is* the auth.
- **Revocation that actually works.** Each device is an npub. Remove it from the allowlist and
  it's mute immediately. This is the clean answer to *"how do I stop a stolen phone talking to
  my server?"* — far better than a bearer token you'd have to rotate everywhere.
- **Reachable from anywhere** without a VPN or publishing your home IP.

### 2. Storing the recovery kit

**Built.** An encrypted recovery kit needs to survive losing your house. The usual answer is
iCloud or Google Drive — which is an account that can be SIM-swapped, locked, or closed, and a
company that can be compelled.

```sh
cosigner recovery-kit publish --in kit.age --passphrase-file pass.txt \
  --relay wss://relay.damus.io --relay wss://nos.lol --relay wss://relay.snort.social
cosigner recovery-kit fetch --passphrase-file pass.txt \
  --relay wss://relay.damus.io --relay wss://nos.lol --out kit.age
```

Publishing the (already `age`-encrypted) blob to a handful of independent relays instead: no
account to hijack, nothing to ask permission from, replicated across operators who don't know
each other. It's still just ciphertext — useless without the passphrase.

The identity used to publish/locate it is derived deterministically *from that same passphrase*
(NIP-78 application data, kind 30078) — one secret to remember, not a passphrase plus a separate
Nostr key to also back up. Relay URLs are always yours to choose; nothing is hardcoded.

**Tradeoffs, honestly:** you depend on relays being reachable (use several — pick at least 3),
and relays can see *that* this identity published something and roughly how large it is, even
though the content itself stays opaque.

---

## How it compares to Bitkey

Block's [Bitkey](https://bitkey.world) is the most mature product in this shape, and it's open
source, so it's worth being precise rather than hand-wavy. The findings below are read from
[their repository](https://github.com/proto-at-block/bitkey), not their marketing.

| | Bitkey | Bitme |
|---|---|---|
| Structure | `wsh(sortedmulti(2, app, hardware, server))` | `wsh(thresh(2, hardware, server, mobile+timelock))` |
| Third key held by | Block, in an AWS Nitro enclave | You, on your own box |
| Everyday spend | app + hardware (server not involved) | hardware + server (**always** policy-gated) |
| Spend from phone alone | Yes, under a daily limit ("Mobile Pay") | **No.** The timelock bars it at the consensus layer. |
| Device choice | One device, theirs, attested to a factory root | Any device your wallet app supports — [a shorter list than it sounds](#which-devices-work) |
| Spending limits | Server policy — Block chooses to refuse | Server policy — you choose to refuse |
| Recovery delay | **7 days, enforced by their server** | **~30 days, enforced by Bitcoin** |
| Recovery without the company | Emergency Exit Kit + hardware | Any two of your three keys |
| Lose two keys | Unrecoverable | Unrecoverable |
| Social recovery | Yes — up to 3 contacts, threshold 1 | Yes — k-of-n npubs, threshold ≥ 2, and it can only release a hold |

**The difference that matters most** is that line about the delay. Bitkey's waiting period, its
spending limits, and its whole recovery flow are server-side policy: bypassable if their server
is compromised, and simply *gone* if it disappears. The only thing Bitcoin enforces for them is
the 2-of-3 itself.

Ours puts the delay in the script. `older(4320)` is a consensus rule — it holds if this service
is rooted, seized, or deleted. That's not a claim about our code being better; it's a structural
difference in where the guarantee lives.

**Where they're clearly ahead:** setup is dramatically easier, they have social recovery and
inheritance, their hardware is attested against a factory root, and they notify you repeatedly
during a delay window rather than once. Adopting that last one is on the list below — one missed
notification shouldn't silently burn your veto window.

There's also an honest cost to being open that's worth naming: Bitkey ships one device it
controls end to end, so "which hardware works" is never a question their users have to answer.
Supporting whatever you already own means inheriting the compatibility problem instead — which
is why [Which devices work](#which-devices-work) exists and why the wizard needs to check it.

**On their Mobile Pay, and why we don't have it.** Letting the phone spend alone under a daily
limit is genuinely better UX. It requires an untimelocked mobile+server branch, which would make
a stolen phone plus a compromised server sufficient to spend — the delay would go back to being
a server promise rather than a consensus rule. That's the one property this design is built
around, so the trade isn't available to us without giving up the argument above.

**On social recovery, and why ours is deliberately smaller.** Bitkey's threshold is 1, and a
recovery contact colluding with Block could reconstruct enough to spend. Ours cannot do that at
any threshold, because contacts hold no key material and the only thing a quorum can do is bring
forward a hold on a spend this service had *already approved* — see
[Recovery contacts](#recovery-contacts). That is a narrower feature than theirs. It is narrow on
purpose: a social-recovery flow that could authorise spending would hand back the very property
this design is built on.

---

## HTTP API

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Status, network, current policy version |
| `/inspect` | POST | Parse a transaction — amounts, destinations, fee, which path. **Needs the API token.** |
| `/sign_psbt` | POST | Submit for signing; returns an id to poll or veto. **Needs the API token.** |
| `/sign_psbt/{id}` | GET | Status of a queued spend |
| `/veto/{id}` | POST | Cancel before it signs |
| `/policy` | GET | Current rules and version |
| `/policy` | POST | Change the rules (needs a hardware-key signed message) |
| `/freeze` | GET/POST | Stop all co-signing. **POST is unauthenticated on purpose** — it's the "my phone was just stolen" button and must work in a hurry. Freezing can only cause denial of service; that's strictly better than theft. |
| `/unfreeze` | POST | Resume. Needs a hardware-key signed message, or the `cosigner unfreeze` CLI if the hardware key is what you lost. |
| `/recovery/approve/{id}` | POST | Release a queued spend's remaining hold, on the say-so of a quorum of your recovery contacts. See [Recovery contacts](#recovery-contacts). |

**Two of these need a bearer token, and the split is deliberate.** The setup wizard generates one
and shows it on the last screen; send it as `Authorization: Bearer <token>`. `/inspect` and
`/sign_psbt` *consume* something — rolling budget, notifications, per-input work against your node
— so they're gated. `/freeze` and `/veto` only ever *stop* a signature happening, so they stay
open: the worst an unauthenticated caller does with them is deny service, and they have to work in
a hurry from whatever device you have to hand. The token lives at `config/api.token`; delete it to
turn authentication off.

One screen of web UI, and only one: the first time it starts with no config, it serves a setup
wizard on this same port instead of the API — collect the two external xpubs, generate the
SERVER key on the box, write the config, hand back the descriptor to register in your wallet app.
Finishing it restarts the service into the API and the wizard is gone for good. It's a wizard
*or* the API, never both, so an unconfigured process never holds a signing key.

Everything after that is API.

[What the wizard looks like](docs/screenshots/) &middot; [how the SERVER key is generated](docs/KEY-GENERATION.md)

---

## Running it

- **[docs/DOCKER.md](docs/DOCKER.md)** — Docker Compose, for a Mac or a VPS.
- **[docs/UMBREL.md](docs/UMBREL.md)** — installing on Umbrel via a community app store.

Quick look without installing anything (the crate lives in `bitme-cosigner/`, not the repo root —
see [Development](#development) below for why):

```sh
cd bitme-cosigner
cargo run -- descriptor build --config ../examples/signet-demo.toml
```

That prints the descriptor, some addresses, and the full invariant report — no node, no server,
no keys of your own required.

Setting up for real, without hand-editing TOML: `cosigner init` walks through the three
xpubs/fingerprints, the timelock, and everything `cosigner serve` needs, with sensible defaults
and immediate validation of anything a typo could break, and writes a `wallet.toml` that's
already confirmed to parse and validate before it's written.

```sh
cargo run -- init --out wallet.toml
```

---

## Threat model

What each attacker can and can't do:

| They have | Can they spend? |
|---|---|
| The server, fully rooted | **No.** One key of two. They can annoy you and read your balance. |
| Your phone, alone | **No.** Needs a second key — and under stock defaults (`recovery.enabled = true`), that second key doesn't have to be the hardware one. See *Phone + server*, below. |
| Your hardware key | **No.** Needs a second key. |
| Phone + server | **Coins under 30 days old:** locked until they mature. **Coins older than that:** the script timelock is already satisfied, so only the 48h hold, the notification and your veto stand in the way — and none of those survive a *fully rooted* server that has the raw key. This is the sharpest edge in the design. |
| Hardware + phone | Yes, after ~30 days. |
| Hardware + server | Yes, immediately, within your policy limits. |
| Network access to the HTTP API | **Without the API token:** can cancel your pending spends (`/veto`) and halt co-signing (`/freeze`) — both unauthenticated on purpose, both denial of service only. **With it:** can also submit transactions and burn your spending limits. Either way it can't move funds by itself — a MOBILE or HARDWARE signature must already be in the submitted PSBT. But under stock defaults (`recovery.enabled = true`), that second signer doesn't have to be the hardware one: see *Phone + server*, above. Still worth keeping on a private network; `[nostr_transport]` (above) authenticates per-device rather than with one shared token. |

The honest weak point: **an attacker holding both your phone and your raw server key can take
mature coins, and the timelock will not stop them.** It only delays coins younger than 30 days.
Mitigations that do apply: set `[recovery] destination_whitelist` so recovery spends can only go
somewhere you chose in advance, keep `hold_seconds` long, and actually read your notifications.
This is the same exposure Bitkey has with app + server, and the reason both designs lean on
notification rather than pretending the delay is a wall.

---

## Current status

Working and tested — 216 unit tests, plus integration tests against a real regtest node:

- Descriptor construction with machine-checked invariant proofs
- Transaction inspection with independent on-chain verification
- The policy engine, exhaustively tested at every boundary
- Signing, with atomic ledger recording proven race-free under concurrency
- Notify → hold → veto
- Hardware-key-authorised, versioned, replay-proof policy changes
- Docker and Umbrel packaging
- **Lost-hardware recovery co-signing** (`[recovery]`), with its own policy: ordinary caps
  don't apply (a sweep is the point), a longer default hold, and an optional destination
  whitelist
- **Freeze / unfreeze**, durable across restarts
- **Device compatibility checking** in the wizard, with a blocking gate and generated warnings —
  see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)
- **Recovery contacts** (`[recovery_contacts]`) — a k-of-n quorum of people you name can release a
  queued spend's remaining hold, and can do nothing else
- **Repeat notifications** during a hold, so one missed message doesn't cost you the veto window
- **API token** on `/inspect` and `/sign_psbt`, generated at setup. The stop-things-happening
  endpoints stay open on purpose — see [HTTP API](#http-api)
- **Optional entropy mixing** — add your own dice rolls at setup and they're combined with the
  OS CSPRNG, so a compromised RNG on the box alone can't make the SERVER key guessable
- **Delivery-gated signing** — a spend is only ever signed if a notification for it was actually
  confirmed delivered. If the notification channel is down, the spend is held (and retried, and
  logged) rather than signed on schedule with nobody informed. A hold nobody heard about isn't a
  hold.
- **The recovery kit** — `wallet.toml` + encrypted server key (`recovery-kit export/import`),
  publishable to Nostr relays (`recovery-kit publish/fetch`) as decentralized off-machine
  storage. Live-relay round-tripping is verified structurally here and pending confirmation
  against real relays from a machine with network access to them.
- **Migration tooling** (`migrate-build-sweep`) — builds the unsigned sweep PSBT for moving funds
  off an old descriptor to a new one when replacing a lost device. Signing still goes through the
  normal channels (hardware apps + the old wallet's own `/sign_psbt`); this only builds the PSBT.

- **The setup wizard** (`cosigner init`) — an interactive prompt flow for every field
  `cosigner serve` needs (keys, timelock, bitcoind, policy, notify, recovery, and optionally
  Nostr transport), with inline validation and a config that's confirmed to parse and validate
  before it's ever written.

- **Nostr transport** (`[nostr_transport]`) — NIP-17 gift-wrapped private messages dispatched
  into the same HTTP router, so it can never drift out of sync with the HTTP API. The relay
  round-trip itself is env-gated and pending confirmation against real relays from a machine
  with network access to them, same as the recovery kit's relay publishing above.

Not done yet:

- **Nothing has touched real hardware.** No signing device, no phone wallet, no mainnet. Signet
  first, and not yet.

---

## Development

The crate lives in `bitme-cosigner/`, not the repo root - Umbrel's installer only ever copies
that one folder onto the device, so it needs to be a self-contained build context.

```sh
cd bitme-cosigner
cargo build && cargo test && cargo clippy --all-targets && cargo fmt
```

`cargo test` runs the mocked-chain unit tests. The regtest integration tests need a real node
and skip cleanly without one — see [`tests/regtest_inspect.rs`](bitme-cosigner/tests/regtest_inspect.rs) for the
command. CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs both on every push:
unit tests/clippy/fmt always, and the regtest suite for real against a bitcoind service
container.
