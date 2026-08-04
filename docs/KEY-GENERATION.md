# How the SERVER key is generated

The setup wizard generates this service's own key on the box it will run on. That key is one of
the three that can move your coins, so this document states exactly where its entropy comes from
and which code is involved — verified against the vendored sources in this build, not from
memory.

If you would rather generate the SERVER key yourself with a tool you already trust, you can:
write it to `config/server.xprv` and use `cosigner init` (or hand-write `wallet.toml`) instead of
the browser wizard. The wizard is the only path that generates a key; nothing else in this
codebase ever does.

## The chain, end to end

```
bitcoin 0.32.8
  └── secp256k1 0.29.1
        └── rand 0.8.7
              └── rand_core 0.6.4        ← OsRng lives here
                    └── getrandom 0.2.17
                          └── libc::syscall(libc::SYS_getrandom, …)
```

`rand_core`'s `OsRng` is a thin shim over `getrandom` (`use getrandom::getrandom;` — its whole
implementation), and `getrandom`'s Linux backend is
`util_libc::sys_fill_exact(dest, util_libc::getrandom_syscall)`, which issues the raw
`getrandom(2)` syscall. So:

- **No userspace PRNG is interposed.** `rand`'s `StdRng`/`ThreadRng` — the ChaCha-based
  generators that get seeded once and then stretched — are *not* used. `rand_chacha` appears in
  the dependency tree because other crates pull it; it is not in this path.
- **Nothing is seeded from a timestamp, PID, hostname, MAC address, install path, or any other
  low-entropy value.** The seed is 256 bits read straight from the kernel CSPRNG.
- **The kernel pool must be initialised.** `getrandom(2)` blocks until it is, rather than
  returning predictable bytes early — which is the failure mode that has historically produced
  duplicate keys on freshly-booted embedded devices.
- **`/dev/urandom` is not opened.** The syscall is used directly, so a missing, replaced, or
  wrongly-permissioned device node inside the container cannot silently degrade it. (getrandom
  keeps a `/dev/urandom` fallback for kernels older than 3.17; umbrelOS is far past that.)
- **No new dependency was added to reach any of this.** `secp256k1` already pulled `rand` in this
  build.

## What the code does with those bytes

From `src/setup.rs`:

```rust
let mut seed = Zeroizing::new([0u8; 32]);
bitcoin::secp256k1::rand::rngs::OsRng.fill_bytes(seed.as_mut());

let master = Xpriv::new_master(network.xpub_network_kind(), seed.as_ref())?;
let master_fingerprint = master.fingerprint(&secp);

let account = master.derive_priv(&secp, &path)?;   // 48h/{0h|1h}/0h/2h
let xpub = Xpub::from_priv(&secp, &account);
```

1. 256 bits into a `Zeroizing` buffer, wiped when it drops.
2. `Xpriv::new_master` runs BIP32's HMAC-SHA512 over the seed to produce the master key.
3. The account key is derived at the BIP48 script-type-2 (P2WSH multisig) path, with the
   registered SLIP44 coin type: `0h` on mainnet, `1h` on every test chain.
4. **Only the account xprv is persisted.** The master is dropped and never written anywhere.
   Every key the descriptor actually uses is an unhardened `<0;1>/*` child of the account key, so
   keeping the master would add no capability while being strictly more dangerous to hold.
5. `config/server.xprv` and `config/wallet.toml` are created with mode `0600` via `create_new` —
   opened with those permissions rather than chmod'd afterwards, so neither is ever briefly
   world-readable, and an existing config is never silently overwritten.

At startup, `ServerSigningKey::load` re-derives the xpub from the stored xprv and refuses to run
unless it matches `[keys.server].xpub` exactly — so a truncated, swapped, or wrong-depth key
fails loudly at boot instead of producing invalid signatures later.

## Every install gets a different wallet

The seed is drawn fresh on every generation, including each time you click **Generate a different
key** in the wizard. Three consecutive generations while this was being verified produced
fingerprints `2df97e30`, `3d23b7ca`, and `6e3c46cf`. `setup.rs`'s
`two_generated_keys_are_never_the_same` test asserts it, and
`generated_server_key_matches_its_own_xpub_and_path` asserts the persisted xprv is really the
account key the config names.

Your wallet's identity is the descriptor over all three xpubs plus your timelock, and two of
those come off your own devices — so even an identical SERVER key could not reconstruct someone
else's wallet.

## Libraries, and why these

| crate | version | role |
|---|---|---|
| [`bitcoin`](https://crates.io/crates/bitcoin) | 0.32.8 | BIP32 derivation (`Xpriv`/`Xpub`), the rust-bitcoin project |
| [`secp256k1`](https://crates.io/crates/secp256k1) | 0.29.1 | Rust bindings to `libsecp256k1` — the same C library Bitcoin Core signs with |
| [`rand`](https://crates.io/crates/rand) / `rand_core` | 0.8.7 / 0.6.4 | `OsRng` only |
| [`getrandom`](https://crates.io/crates/getrandom) | 0.2.17 | the `getrandom(2)` syscall |
| [`zeroize`](https://crates.io/crates/zeroize) | 1.9.0 | wiping seed and key material on drop |

No custom cryptography is implemented anywhere in this project — no hand-rolled RNG, no
hand-rolled key derivation, no hand-rolled signing.

## The honest limits

- `zeroize` is best-effort, not a guarantee. `secp256k1`/`bitcoin` don't implement `Zeroize` for
  `SecretKey`/`Xpriv`, and `Xpriv` is `Copy`, so the compiler may have left copies elsewhere in
  memory. What is guaranteed: the raw seed and the xprv *string* are wiped promptly, and the
  parsed key's bytes are overwritten on drop via `non_secure_erase`. See the comment on
  `ServerSigningKey` in `src/signing.rs`.
- Entropy quality is the kernel's. This documents that the kernel CSPRNG is what's being asked,
  through the shortest path available, and that nothing weakens it in between — it cannot make
  claims about the kernel itself or the hardware under it.
- A VM restored from a snapshot taken *before* key generation, then generating a key, is outside
  what `getrandom(2)` alone protects against. Generate on real hardware, or after first boot.
