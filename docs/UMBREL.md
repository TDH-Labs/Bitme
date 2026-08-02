# Running cosigner on Umbrel

**Honesty first: this packaging has been validated as far as I could without a real Umbrel
instance to install it on** - the manifest matches Umbrel's documented schema, the compose file
was checked with `docker compose config`, and the injected-variable names for the Bitcoin Core
dependency were confirmed against Umbrel's own app store source. What I could *not* do is
actually install it on an Umbrel and watch it come up - please treat the first install as a real
test, not a known-good deployment, and expect to troubleshoot.

**Start on signet.** Set your Umbrel's Bitcoin Core app to signet mode before installing this
(Umbrel's Bitcoin Core app supports it), and don't set `i_understand_this_is_mainnet = true`
until you've verified everything end-to-end.

Before touching real Umbrel hardware, `scripts/simulate-umbrel.sh` (run from a machine with
Docker and real internet access) exercises this exact directory's `docker-compose.yml` - build
context, entrypoint, startup - against faked Umbrel-shaped environment variables and a
throwaway regtest node standing in for Umbrel's Bitcoin Core app. A pass there means the
packaging is structurally sound; it doesn't replace an install on real hardware, but it catches
build/wiring mistakes for free before you spend time on a device.

## Why this differs from a typical Umbrel app

Two deliberate departures from the usual Umbrel app pattern, both because of this project's own
design rule (see the main README): **no web UI, HTTP API only**.

- No `app_proxy`/browser-auth wrapper. This app's port is published directly, reachable on your
  LAN like any other service - not proxied through Umbrel's authenticated web UI. Treat network
  access to it as sensitive.
- Opening it from the Umbrel dashboard shows a bare JSON health check (`GET /health`), not a
  page. That's intentional, not a bug.

## Install

1. In your Umbrel: **App Store → ⋮ → Community App Stores → Add App Store**, and paste:
   `https://github.com/TDH-Labs/Bitme`
2. Find **Bitme Cosigner** in the store and install it.
3. It will fail to start the first time - that's expected. It has no config yet.

## Configure

Umbrel gives every app a persistent data directory at
`~/umbrel/app-data/bitme-cosigner/data` on the host (exact path may vary by Umbrel version -
check **Settings → Advanced → Terminal**, or SSH in). You need to place two files under
`.../data/config/`:

1. `wallet.toml` - copy [`bitme-cosigner/wallet.toml.example`](../bitme-cosigner/wallet.toml.example)
   from this repo and fill in your real SATOCHIP/MOBILE/SERVER xpubs, `[policy]`, and `[notify]`.
   Leave `network = "signet"` and don't add `[bitcoind]`/`[server]` - see the comments in the
   file.
2. `server.xprv` - a plain text file containing only your SERVER account-level xprv (matching
   `[keys.server]` in `wallet.toml`). This service never generates keys - generate this yourself,
   the same way you would for the plain Docker deployment (see [`docs/DOCKER.md`](DOCKER.md)).

```sh
ssh umbrel@umbrel.local
cd ~/umbrel/app-data/bitme-cosigner/data
mkdir -p config
# copy wallet.toml.example in from this repo (scp, or paste with an editor), then:
$EDITOR config/wallet.toml
$EDITOR config/server.xprv   # just the xprv, nothing else
chmod 600 config/server.xprv
```

Then restart the app from the Umbrel dashboard (**Bitme Cosigner → ⋮ → Restart**).

## Verify it's up

From your Umbrel's LAN, or via SSH:

```sh
curl http://umbrel.local:8080/health
```

Expect `{"service":"cosigner","version":"...","network":"signet","policy_version":1}`. If
`network` isn't what you expect, or the container keeps restarting, check its logs
(**Bitme Cosigner → ⋮ → Logs**, or `docker logs bitme-cosigner_app_1`) -
`docker-entrypoint.sh` prints a specific reason (missing config, missing xprv, or a network
mismatch between `wallet.toml` and your Bitcoin Core app) rather than failing silently.

## Updating

Umbrel's App Store update mechanism handles pulling new versions of this repo; since the app is
built from source (`build: context: ..` in `bitme-cosigner/docker-compose.yml`, not a
pre-published image), the first install and every update rebuild the Rust binary on your device.
On Umbrel Home (Intel N100) this is a few minutes; on a Raspberry Pi it will be noticeably
slower. Your `wallet.toml`, `server.xprv`, and the ledger database all live in the persistent
data directory and survive updates.
