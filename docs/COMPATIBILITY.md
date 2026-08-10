# Device and coordinator compatibility

**Status: implemented.** The model below is what `bitme-cosigner/src/compat.rs` actually does,
with the data in `bitme-cosigner/src/compatibility.toml` and the gate wired into the setup
wizard's second step. Drop your own `compatibility.toml` in the config directory to override the
bundled one without waiting for a release.

---

## The problem this solves

Bitme's descriptor is miniscript with a relative timelock:

```
wsh(thresh(2,pk(HARDWARE),s:pk(SERVER),snj:and_v(v:pk(MOBILE),older(4320))))
```

That is a plain, standard P2WSH output — it relays and confirms like anything else. But it is
**not** `sortedmulti()`, which is what most wallet software means when it says "multisig". Two
independent things have to be true before a given pair of devices can use this wallet:

1. Some app has to **import and track** a `thresh`/`older` descriptor.
2. Something has to **drive your hardware device** to sign for that script.

Those are different capabilities, held by different software, and the intersection is small.
A user who picks a hardware device and a phone app that each look well-supported can still end
up with a wallet they cannot spend from. That has already happened once during this project's
own design work — see [Worked example](#worked-example-satochip--bitcoin-keeper) below.

The wizard's job is to catch that **before** the user funds an address, not after.

---

## The model: three roles, not two

The instinct is to build a matrix of `(hardware × coordinator)` pairs. Don't. It is O(n×m),
it will never be complete, and it produces false negatives — it would reject working setups
where two apps split the work between them.

Model the three *roles* in a spend instead, and let the resolver compose them:

| Role | What it does | Who typically plays it |
|---|---|---|
| **Coordinator** | Holds the descriptor watch-only, builds the PSBT, finalizes, broadcasts | Bitcoin Keeper, Nunchuk, Sparrow, Bitcoin Core |
| **Signer driver** | Physically talks to a hardware device to get a signature | The coordinator, usually — but not always |
| **Mobile key holder** | Holds the MOBILE key and signs with it | Bitcoin Keeper, Nunchuk |

One app commonly plays all three. It does not have to. Splitting them is what makes some
otherwise-dead combinations viable, and the resolver has to be able to see that.

### Which roles each spending path actually needs

This is the part that makes the model tractable. Bitme's descriptor has three spending paths,
and **they need different things**:

| Path | Keys | Needs a coordinator that… | Needs the hardware to… | Needs the mobile key? |
|---|---|---|---|---|
| **Daily spend** | HARDWARE + SERVER | registers miniscript, drives the hardware, reaches the cosigner | sign miniscript | No |
| **Policy change** | HARDWARE signed message | — (can be done by CLI on the box) | sign messages | No |
| **Unfreeze** | HARDWARE signed message | — (CLI fallback exists) | sign messages | No |
| **Recovery: server gone** | HARDWARE + MOBILE | registers miniscript, drives the hardware | sign miniscript | Yes |
| **Recovery: hardware gone** | MOBILE + SERVER | registers miniscript, reaches the cosigner | — | Yes |

Two consequences worth internalising:

- **Daily spending never involves the mobile key.** `snj:and_v(v:pk(MOBILE),older(N))` bars it
  at the consensus layer. So the app holding your mobile key does not need to be able to drive
  your hardware, and vice versa. They can be entirely different apps that never meet.
- **"Hardware can sign messages" is a separate axis from "hardware can sign miniscript."** A
  device can pass every spending check and still leave you unable to run `POST /policy` or
  `POST /unfreeze`. That is a real, silent failure mode and it needs its own column.

---

## Data schema

The matrix ships as **data**, not Rust. Devices and firmware move faster than release cycles,
and a stale hardcoded matrix that blocks a now-working combination is worse than no matrix.

`config/compatibility.toml`, loaded at startup, overridable by the operator.

```toml
schema_version = 1
# Bump when any entry changes. Surfaced in the wizard so a user can tell how stale their data is.
revision = "2026-08-10"

[[hardware]]
id           = "coldcard"
label        = "Coldcard (Mk4 / Q)"
form_factor  = "usb-sd-nfc"
signs_miniscript = true      # can produce a signature for a non-sortedmulti witness script
signs_older      = true      # handles a relative-timelock branch
signs_message    = true      # Bitcoin signed message — required for /policy and /unfreeze
verified         = "vendor-docs"
notes            = "older() range: 1-65535 blocks, or 4194305-4259839 for time-based."

[[hardware]]
id           = "satochip"
label        = "Satochip"
form_factor  = "smartcard-nfc"
signs_miniscript = true      # the applet signs hashes; the script is the coordinator's problem
signs_older      = true
signs_message    = true
verified         = "unverified"
notes            = "Signing is not the constraint. No known coordinator both registers miniscript and drives this card — see the worked example."

[[coordinator]]
id                  = "bitcoin-keeper"
label               = "Bitcoin Keeper"
platform            = "mobile"
registers_miniscript = true
holds_mobile_key     = true
finalizes            = true
reaches_cosigner     = "manual"          # "native" once a coordinator speaks to /sign_psbt directly
drives               = ["coldcard", "jade", "ledger", "bitbox02", "tapsigner"]
verified             = "release-notes"
verified_version     = "2.0.1"

[[coordinator]]
id                  = "sparrow"
label               = "Sparrow"
platform            = "desktop"
registers_miniscript = false             # open feature request, not implemented
holds_mobile_key     = false
finalizes            = true
reaches_cosigner     = "manual"
drives               = ["coldcard", "jade", "ledger", "bitbox02", "satochip", "seedsigner"]
verified             = "issue-tracker"
notes                = "Drives the widest device range, but cannot register a thresh/older descriptor."
```

### Field meanings

**Hardware**

| Field | Meaning |
|---|---|
| `signs_miniscript` | Will produce a signature for a witness script that is not `multi`/`sortedmulti`. For devices that sign whatever hash they are handed, this is `true` — the constraint lives in the coordinator. |
| `signs_older` | Accepts a branch guarded by a relative timelock. Some devices support miniscript but restrict the fragment set. |
| `signs_message` | Bitcoin signed-message (`signed_msg_hash`), as consumed by `policy_auth::HardwareAuthKeys::verify`. **Without it, runtime policy changes and unfreeze require CLI access to the box.** |

**Coordinator**

| Field | Meaning |
|---|---|
| `registers_miniscript` | Will import and track a `thresh`/`older` descriptor as a watch-only wallet. **This is the field that eliminates most software.** |
| `drives` | Hardware ids this app can talk to. Not transitive — being able to import a descriptor says nothing about which devices it can drive. |
| `holds_mobile_key` | Can itself be the MOBILE key. |
| `reaches_cosigner` | `native` = talks to `/sign_psbt` directly. `manual` = the user shuttles a PSBT by file or QR. Nothing is `native` today. |

**`verified`** — provenance, and it is not decoration:

| Value | Meaning |
|---|---|
| `signet-tested` | Someone ran the full flow on signet with this exact combination. The only value that should be treated as authoritative. |
| `vendor-docs` | Claimed by vendor documentation. |
| `release-notes` | Claimed in a release announcement. |
| `issue-tracker` | Inferred from an open/closed issue. |
| `unverified` | Assumed. **Must render as a warning in the wizard.** |

---

## Resolver

The resolver takes the user's three selections and returns a verdict **per spending path**, not
per device pair. Warning text is generated from which check failed — never hand-written per
combination, which is what makes this scale to devices nobody has thought of yet.

```
resolve(hardware, coordinator, mobile_holder) -> [PathVerdict]

for each path in [DailySpend, PolicyChange, Unfreeze, RecoveryServerGone, RecoveryHardwareGone]:
    missing = []

    if path.needs_miniscript_registration:
        if not coordinator.registers_miniscript:
            # can any other known coordinator cover it?
            alt = coordinators.filter(registers_miniscript
                                      and hardware.id in drives)
            missing.push(NeedsMiniscriptRegistration { alt })

    if path.needs_hardware_driving:
        if hardware.id not in coordinator.drives:
            alt = coordinators.filter(hardware.id in drives
                                      and registers_miniscript)
            missing.push(CannotDriveHardware { alt })

    if path.needs_hardware_signing and not hardware.signs_miniscript:
        missing.push(HardwareCannotSignMiniscript)

    if path.needs_message_signing and not hardware.signs_message:
        missing.push(HardwareCannotSignMessages)   # CLI fallback exists

    verdict = GREEN  if missing.empty
              AMBER  if every entry in missing has a non-empty `alt`
              RED    otherwise
```

### Verdict levels

| Verdict | Meaning | Wizard behaviour |
|---|---|---|
| **GREEN** | One app covers this path end to end. | Proceed. |
| **AMBER** | Works, but needs a second app. A concrete alternative exists. | Proceed **only** after an explicit acknowledgement naming the extra app and the paths affected. |
| **RED** | No known combination of listed software covers this path. | Block. Overridable only by the informed-consent checkbox below. |

### Generated acknowledgement text

Templated from the failure, so new devices inherit correct copy for free:

> **AMBER — daily spending needs a second app**
> `{coordinator}` can track this wallet but cannot sign with your `{hardware}`.
> **Every spend** will require `{alt_coordinator}` — not just spends over your daily limit.
> Affected: daily spending, recovery if the server is lost.
> `[ ] I understand every transaction will require {alt_coordinator}.`

> **RED — no known way to spend from this wallet**
> No listed app both tracks a miniscript descriptor and signs with `{hardware}`.
> `{coordinator}` tracks the descriptor but cannot drive `{hardware}`.
> `{other}` drives `{hardware}` but cannot track the descriptor.
> **If you fund this wallet you may be unable to spend from it** until software support
> changes. Recovery paths are affected identically.
> `[ ] I understand I may not be able to spend from this wallet.`

> **AMBER — policy changes will need server access**
> `{hardware}` cannot sign messages, which `POST /policy` and `POST /unfreeze` require.
> You will need shell access to the box and the `cosigner` CLI to change spending limits or
> lift a freeze. Spending is unaffected.
> `[ ] I understand policy changes will require CLI access.`

### Wording rule

The copy must state the **whole** consequence, not the mildest true one.

Say *"every spend will require Sparrow"* — never *"spends beyond your daily limit will require
Sparrow."* The daily cap is enforced by Bitme against a PSBT that already carries a hardware
signature; it does not change which keys are required. Understating this gets someone to check
a box thinking they have accepted an edge case, and discover later that they cannot spend at
all.

---

## Wizard flow

Selection order matters — pick the constraining thing first:

```
1. Which app will you use day to day?          → coordinator
2. Which hardware device?                       → filtered + annotated by step 1
3. Where does the mobile recovery key live?     → filtered by registers_miniscript
4. → resolve() → verdict panel
5. → block / acknowledge / proceed
```

Step 2 renders every device, never a filtered-down list with no explanation. GREEN devices are
selectable; AMBER and RED are selectable **with their reason shown inline**. A greyed-out option
with no explanation produces support questions; an annotated one teaches the constraint.

Devices whose entry is `verified = "unverified"` show a distinct marker regardless of verdict.

---

## Worked example: Satochip + Bitcoin Keeper

This is the combination this project was originally built around, and it is the reason this
document exists.

| | Registers miniscript | Drives Satochip |
|---|---|---|
| Bitcoin Keeper | ✅ | ❌ |
| Sparrow | ❌ | ✅ |

Resolver output for `(hardware=satochip, coordinator=bitcoin-keeper, mobile=keeper)`:

- `DailySpend` → **RED**. Keeper cannot drive the Satochip. No alternative coordinator both
  registers miniscript and drives it.
- `RecoveryServerGone` → **RED**, same reason.
- `RecoveryHardwareGone` → **GREEN**. Needs only MOBILE + SERVER; Keeper covers it.
- `PolicyChange` / `Unfreeze` → **AMBER**. The Satochip signs messages, but nothing convenient
  drives it for that; CLI fallback applies.

So: a wallet you can recover from but very likely cannot spend from. Exactly the failure this
gate exists to prevent, and it is not visible from either vendor's feature list.

**Two ways out**, both supported by the model:

1. **Keep Keeper, change hardware.** Tapsigner is the closest swap — same smartcard/NFC form
   factor, and it is on Keeper's miniscript signer list. Coldcard, Jade, Ledger and BitBox02
   also resolve GREEN.
2. **Keep the Satochip, change the descriptor.** A `wsh(sortedmulti(2,…))` wallet works with
   nearly everything, including Sparrow + Satochip. **This is a security downgrade, not a
   preference:** without `older(N)` on the mobile branch, MOBILE + SERVER spends immediately,
   the policy engine becomes bypassable by a stolen phone, and Bitme's central claim — that the
   delay is a consensus rule rather than a server promise — no longer holds. If it is ever
   offered it must be a clearly-labelled mode, defaulted off, with its own acknowledgement.

---

## Seed data

**Treat every row as unverified until it says `signet-tested`.** The author of this document
confidently recommended a Sparrow-coordinated setup two days before discovering Sparrow does not
implement miniscript. That is the failure mode this column exists to prevent.

### Coordinators

| App | Platform | Registers miniscript | Holds mobile key | Source |
|---|---|---|---|---|
| Bitcoin Keeper | mobile | ✅ | ✅ | v2.0.1 release notes |
| Nunchuk | mobile + desktop | ✅ | ✅ | vendor announcement — **device list unverified** |
| Sparrow | desktop | ❌ | ❌ | [sparrowwallet/sparrow#1700](https://github.com/sparrowwallet/sparrow/issues/1700) open |
| Liana | desktop | ✅ | ❌ | built on miniscript — **arbitrary descriptor import unverified** |
| Bitcoin Core | desktop/CLI | ✅ | ❌ | `importdescriptors`; no hardware driving without HWI |

### Hardware

| Device | Signs miniscript | Signs messages | Keeper miniscript list | Source |
|---|---|---|---|---|
| Coldcard Mk4 / Q | ✅ | ✅ | ✅ | vendor docs |
| Blockstream Jade | ✅ | ✅ | ✅ | vendor announcement |
| Ledger | ✅ | ✅ | ✅ | vendor announcement |
| BitBox02 | ✅ | ✅ | ✅ | Keeper release notes |
| Tapsigner | ✅ | ❓ | ✅ | Keeper release notes |
| Satochip | ✅ (applet) | ✅ | ❌ | **no miniscript-capable coordinator drives it** |
| SeedSigner | ❌ | ✅ | ❌ | `sortedmulti` only |

### Verification procedure

A row earns `signet-tested` only by completing all of this on signet:

1. Run the wizard; register the descriptor in the coordinator.
2. Confirm the coordinator's first receive address **matches the wizard's `first_address`.**
   A mismatch means a mistyped xpub or a descriptor the coordinator silently reinterpreted —
   this check is the cheapest catch in the whole system and it is not optional.
3. Fund it. Build a spend. Sign with the hardware.
4. `POST /sign_psbt`, wait out the hold, retrieve the signed PSBT.
5. Finalize and broadcast. Confirm.
6. Sign a `POST /policy` change with the hardware key.

Steps 1–2 alone catch most incompatibilities and cost nothing.

---

## Implementation notes

### The `satochip` → `hardware` rename

**Done.** The role is spelled `hardware` throughout — config, descriptor construction, policy
authorization, both wizards, and every error string.

`keys.satochip` is still accepted as a serde alias, and that alias is **permanent, not a
migration window**. An existing `wallet.toml` saying `satochip` is not wrong, just old, and
asking someone to rewrite a working wallet's config to chase a rename would be a poor trade for
zero benefit. The same alias applies to the setup API's `satochip` field.

**This rename never affected coordinator compatibility**, because the role name appears nowhere
in the descriptor a coordinator imports — only fingerprints, derivation paths and xpubs do.

### Not in scope

The matrix describes what software *can* do. It cannot verify what a user's specific firmware
version actually does. It reduces the failure rate; it does not replace the signet dry run in
[Verification procedure](#verification-procedure).
