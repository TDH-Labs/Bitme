# Running cosigner with Docker

This covers running `cosigner` via Docker Compose - on a Mac (via Docker Desktop) for local
testing, or on a VPS for a real deployment. For Umbrel specifically, see
[`docs/UMBREL.md`](UMBREL.md) instead - it uses the same image but a different compose file that
plugs into Umbrel's own Bitcoin Core app.

**Start on signet. Always.** This service refuses to run on mainnet unless
`i_understand_this_is_mainnet = true` is set in `wallet.toml` - don't set that until you've
verified the whole setup end-to-end here.

## What you need first

- Docker and the Compose plugin (`docker compose version` should work - Docker Desktop on Mac
  includes this already).
- Your SATOCHIP's master fingerprint, derivation path, and xpub (readable from Sparrow, Electrum,
  or similar wallet software connected to the card - never its private key).
- The same for your Bitcoin Keeper (MOBILE) wallet.
- A SERVER key: an xprv/xpub pair *you* generate and hold. This service never generates keys -
  see the hard rule in the project's spec. Generate it with hardware or software you already
  trust (e.g. a second hardware wallet, or `bitcoin-cli` on a machine with no network access),
  at whatever `derivation_path` you choose (the examples throughout this project use
  `48h/1h/0h/2h`, but any path is fine as long as `[keys.server]` in `wallet.toml` matches it).

## 1. Clone and configure

```sh
git clone https://github.com/TDH-Labs/Bitme.git
cd Bitme
cp .env.example .env
```

Edit `.env`:
- `COSIGNER_SERVER_XPRV` - your SERVER xprv from above. This file is gitignored; never commit it.
- Leave `BITCOIND_RPC_URL`/`USER`/`PASSWORD` as-is if you're using the bundled signet node below;
  otherwise point them at your own node.
- `COSIGNER_BIND_ADDR` - optional, defaults to `0.0.0.0:8080`. All interfaces is right when the
  container has its own network namespace and is reached through a proxy, which is the normal
  Docker and Umbrel case. Set it explicitly if this container shares a namespace with anything
  else, or if you want the service on one specific interface and nowhere else - a WireGuard or
  Yggdrasil address, say. Binding narrowly is a perimeter, not authentication: see the API token
  in the README either way.

## 2. Start (with a bundled local signet node, for testing)

If you don't already have a signet `bitcoind` reachable, this override adds one:

```sh
docker compose -f docker-compose.yml -f docker-compose.signet.yml up -d bitcoind
```

Give it a few minutes to sync signet (much faster than mainnet - typically well under an hour).
Check progress with:

```sh
docker compose -f docker-compose.yml -f docker-compose.signet.yml logs -f bitcoind
```

If you already have a node (your own VPS, home server, etc.), skip this and just make sure
`BITCOIND_RPC_URL` in `.env` points at it.

## 3. Write your wallet config

Three ways to do this, in rough order of least to most manual. All three produce the same file.

**The browser wizard.** Start the container with `config/` empty and it serves a setup wizard on
its own port instead of the API. Point a browser at it and it collects the two external xpubs,
generates the SERVER key itself from the OS CSPRNG, writes both `wallet.toml` and `server.xprv`
mode `0600`, and shows you the descriptor to register in your coordinator. This is the only one
of the three that also *generates* the SERVER key, so it's the path to prefer unless you have a
reason to make that key yourself. Finishing it shuts the wizard down; with `restart:
unless-stopped` the container comes straight back up serving the real API.

**`cosigner init`.** The same flow as guided terminal prompts - see below.

**By hand.** `config/` is bind-mounted straight into the container, so you can just edit a normal
file on your host:

```sh
cp config/wallet.toml.example config/wallet.toml
$EDITOR config/wallet.toml
```

Fill in real values for `[keys.hardware]`, `[keys.mobile]`, `[keys.server]` (see "What you need
first" above), and adjust `[policy]`/`[notify]` to taste. Leave `network = "signet"` and don't
touch `[bitcoind]`/`[server]` - they don't belong in this file (see the comments in the file
itself for why). `config/wallet.toml` is gitignored - it will hold your real xpubs, never commit
it.

**The terminal wizard:** `cosigner init` covers this same file with guided prompts, sensible
defaults and inline validation, instead of copying the example and filling in ~30 fields by hand.
It shares its validators and its renderer with the browser wizard above, so the two cannot drift
into producing different configs. Unlike the browser wizard it does *not* generate a SERVER key -
you supply one. Run it against a throwaway container with a writable mount pointed at your host's
`config/` directory (build the image first if you haven't yet):

```sh
docker compose build
docker run --rm -it -v "$(pwd)/config:/out" cosigner:latest init --out /out/wallet.toml
```

That writes `config/wallet.toml` on your host, already confirmed to parse and validate before
the wizard writes it. `[bitcoind]`/`[server]` are still generated by the container itself - the
wizard won't add them, and you shouldn't either.

## 3a. Back up your config: the recovery kit

Losing the box that runs this service loses `wallet.toml` and the SERVER xprv with it - even
though your SATOCHIP and MOBILE keys are completely unaffected, you can't reconstruct the
descriptor without it. `recovery-kit export` encrypts `wallet.toml` plus the SERVER xprv (read
from wherever `[server_signing]` points) into a single passphrase-protected blob.

Add a throwaway bind mount of the current directory for the one-off command, so the blob lands
directly on the host - a `--rm` container is gone by the time it exits, so there's no container
left afterward to copy the file back out of:

```sh
# on the host: put a strong passphrase (12+ chars) somewhere the container can read it -
# config/ is bind-mounted read-only, which is fine since export/import only ever read it
echo "your long passphrase here" > config/recovery-kit-passphrase.txt

docker compose run --rm -v "$(pwd):/host" cosigner recovery-kit export \
  --config /data/config/wallet.toml \
  --passphrase-file /data/config/recovery-kit-passphrase.txt \
  --out /host/recovery-kit.age
```

`./recovery-kit.age` now exists on the host - move it somewhere OTHER than this machine (a
second device, a paper/QR backup, or Nostr relays below). It's useless as a backup for this
box's own disk failure if it only ever lives on this box.

To store it decentralized instead of (or alongside) a manual copy, publish it to Nostr relays -
the identity used to publish/locate it is derived from the same passphrase, so there's still
only one secret to hold onto:

```sh
docker compose run --rm -v "$(pwd):/host" cosigner recovery-kit publish \
  --in /host/recovery-kit.age \
  --passphrase-file /data/config/recovery-kit-passphrase.txt \
  --relay wss://relay.damus.io --relay wss://nos.lol --relay wss://relay.snort.social
```

Once you're done with both (or whichever of these you actually use), delete the passphrase file
- don't leave it sitting on disk indefinitely:

```sh
rm config/recovery-kit-passphrase.txt
```

Restoring is the mirror image (`recovery-kit fetch` and/or `recovery-kit import`) - see
`docker compose run --rm cosigner recovery-kit --help` for the full command set.

## 3b. Replacing a lost device: migration tooling

If the SATOCHIP, phone, or this server itself is lost or destroyed, `migrate-build-sweep` builds
the unsigned PSBT that sweeps funds off the old descriptor to a new one. It needs `[bitcoind]` in
its `--old-config`, which your static `config/wallet.toml` deliberately doesn't have (the
container generates it) - point it at the *generated* config the running container already
wrote instead, which lives on the persistent volume once `serve` has started at least once:

```sh
docker compose run --rm -v "$(pwd):/host" cosigner migrate-build-sweep \
  --old-config /data/generated.toml \
  --utxo <txid>:<vout> \
  --new-config /data/config/new-wallet.toml \
  --path hot \
  --fee-rate 5 \
  --out /host/sweep.psbt
```

Find the UTXOs to sweep with `bitcoin-cli listunspent` against a watch-only import of the old
descriptor, or a block explorer - this command doesn't scan for them itself. Signing the result
still goes through the normal channels: SATOCHIP/MOBILE's own apps, then this service's usual
`/sign_psbt` for the SERVER co-sign.

## 3c. Optional: the Nostr transport

`[nostr_transport]` in `config/wallet.toml` gives the service its own Nostr identity, receiving
signing requests as NIP-17 private messages instead of (or alongside) plain HTTP - see the
README's "Where Nostr fits" section for why. To turn it on:

1. Generate a Nostr keypair for this service (any Nostr client can do this - it's just a
   secp256k1 keypair, same shape as Bitcoin's).
2. Set `COSIGNER_NOSTR_NSEC` in `.env` to the resulting nsec - `docker-compose.yml` passes it
   through to the container as an optional variable, same mechanism as `COSIGNER_SERVER_XPRV`.
3. Uncomment `[nostr_transport]` in `config/wallet.toml`, leaving `nsec_env_var =
   "COSIGNER_NOSTR_NSEC"` as-is, and fill in your relays and the npub(s) of whichever devices
   should be allowed to submit requests this way.
4. Recreate the container so it picks up the new `.env` value: `docker compose up -d` (no
   `--build` needed - nothing about the image itself changed).

Removing a device's npub from `allowed_npubs` and restarting is how you cut it off - its
messages are still cryptographically genuine, they're just no longer answered.

## 4. Validate the descriptor before starting the server

```sh
docker compose run --rm cosigner descriptor build --config /data/config/wallet.toml
```

This proves your three keys form a valid wallet and prints the invariant report (no single key
can spend, exactly one immediate path, etc.) - fix any `FAIL` before continuing.

## 5. Start the service

```sh
docker compose -f docker-compose.yml -f docker-compose.signet.yml up -d
curl http://localhost:8080/health
```

You should get back `{"service":"cosigner","version":"...","network":"signet","policy_version":1}`.

From here, fund a signet address from your wallet's receive address (get one via
`docker compose run --rm cosigner descriptor build --config /data/config/wallet.toml` - it prints
`receive[0]`, etc.), build a PSBT spending it, and try `POST /inspect` and `POST /sign_psbt`
against `http://localhost:8080`.

## Moving to a VPS

Same steps, minus the signet override if you already run your own node there - just set
`BITCOIND_RPC_URL` (and auth) in `.env` to point at it, and run:

```sh
docker compose up -d --build
```

Only change `network` to `"mainnet"` (and set `i_understand_this_is_mainnet = true`) once you've
verified this entire flow - descriptor, inspect, sign, hold/veto, policy changes - for real on
signet.

## Updating

```sh
git pull
docker compose up -d --build
```

The ledger database and your `wallet.toml` live in the `cosigner-data` volume and survive
rebuilds. Back that volume up - it's the record of every spend this service has ever signed.
