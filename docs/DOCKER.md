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

`config/` is bind-mounted straight into the container (read-only), so you just edit a normal
file on your host:

```sh
cp config/wallet.toml.example config/wallet.toml
$EDITOR config/wallet.toml
```

Fill in real values for `[keys.satochip]`, `[keys.mobile]`, `[keys.server]` (see "What you need
first" above), and adjust `[policy]`/`[notify]` to taste. Leave `network = "signet"` and don't
touch `[bitcoind]`/`[server]` - they don't belong in this file (see the comments in the file
itself for why). `config/wallet.toml` is gitignored - it will hold your real xpubs, never commit
it.

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
