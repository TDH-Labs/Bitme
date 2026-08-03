# Running cosigner on Umbrel

**Status: installed and started on real Umbrel hardware** (umbrelOS on x86_64, Bitcoin Core app
present) as of the commit that added this note. What is verified: the app store picks the repo
up, the image builds on-device from source, the container is created and started, Umbrel's
Bitcoin Core connection details are injected correctly, and the app publishes on its manifest
port. What is *not* yet verified: anything past that point - `/health`, a real descriptor, or a
signing round trip - because all of those need the three real keys, which no amount of packaging
work can substitute for.

That first install found two packaging bugs that only appear on a real device (a build context
that resolved outside the app's folder, and a port variable Umbrel doesn't actually export to
apps); both are fixed, and `scripts/simulate-umbrel.sh` now reproduces the conditions that hid
them. Still treat your own first install as a test rather than a known-good deployment.

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

## Setup wizard, recovery kit, and migration

`cosigner init` (interactive setup wizard), `recovery-kit export/import/publish/fetch`
(encrypted off-machine backup of `wallet.toml` + the SERVER xprv), and `migrate-build-sweep`
(the mechanism for replacing a lost SATOCHIP/phone/server) are all one-shot commands, not part
of the running `app` container's normal lifecycle - `docker-entrypoint.sh` passes anything other
than `serve` straight through, so they work the same way here as in a plain Docker deployment
(see [`docs/DOCKER.md`](DOCKER.md) for the full command reference and reasoning).

The one Umbrel-specific wrinkle: Umbrel manages this app's compose lifecycle itself, so there's
no `docker compose run` from a checkout the way DOCKER.md describes - use `docker run` directly
against the image Umbrel already built for this app instead. Confirm the exact image name/tag on
your device first (this wasn't verified against real Umbrel hardware - see the honesty note at
the top of this doc):

```sh
ssh umbrel@umbrel.local
docker images | grep bitme-cosigner   # find the built image name/tag
cd ~/umbrel/app-data/bitme-cosigner/data
```

`config/` is mounted read-only into the running `app` container, so anything that *writes*
there (the wizard) needs its own writable mount instead of going through the running container:

```sh
docker run --rm -it -v "$(pwd)/config:/out" <image-from-above> init --out /out/wallet.toml
```

`recovery-kit`/`migrate-build-sweep` read `wallet.toml` (fine, read-only) and write their
output to `/data` (the *other* mount, which is writable) - run them the same way, e.g.:

```sh
echo "your long passphrase here" > config/recovery-kit-passphrase.txt

docker run --rm \
  -v "$(pwd)/data:/data" -v "$(pwd)/config:/data/config:ro" \
  <image-from-above> recovery-kit export \
    --config /data/config/wallet.toml \
    --passphrase-file /data/config/recovery-kit-passphrase.txt \
    --out /data/recovery-kit.age

rm config/recovery-kit-passphrase.txt   # don't leave the passphrase sitting on disk afterward
```

The full command set (`recovery-kit publish/fetch/import`, `migrate-build-sweep`'s other flags)
is the same as [`docs/DOCKER.md`](DOCKER.md) - only the invocation shape (`docker run` with
explicit mounts, not `docker compose run`) differs here.

## Optional: the Nostr transport

`[nostr_transport]` gives the service its own Nostr identity, receiving signing requests as
NIP-17 private messages instead of (or alongside) plain HTTP - see the README's "Where Nostr
fits" section. Umbrel has no per-app secret-entry UI, so - same as `server.xprv` above - this
service's Nostr secret key goes in as a third mounted file, not an environment variable:

```sh
ssh umbrel@umbrel.local
cd ~/umbrel/app-data/bitme-cosigner/data
$EDITOR config/nostr.nsec   # just the nsec, nothing else
chmod 600 config/nostr.nsec
$EDITOR config/wallet.toml  # uncomment [nostr_transport]; nsec_file = "/data/config/nostr.nsec"
```

Then restart the app from the Umbrel dashboard. Removing a device's npub from
`allowed_npubs` and restarting is how you cut it off - its messages are still cryptographically
genuine, they're just no longer answered.

## Updating

Umbrel's App Store update mechanism handles pulling new versions of this repo; since the app is
built from source (`build: context: ..` in `bitme-cosigner/docker-compose.yml`, not a
pre-published image), the first install and every update rebuild the Rust binary on your device.
On Umbrel Home (Intel N100) this is a few minutes; on a Raspberry Pi it will be noticeably
slower. Your `wallet.toml`, `server.xprv`, and the ledger database all live in the persistent
data directory and survive updates.
