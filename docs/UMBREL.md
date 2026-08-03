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

A known consequence of the first point, seen on the device this was verified on: if your Umbrel
has **remote Tor access enabled**, Umbrel adds a `tor_server` sidecar to every app and points its
hidden service at that app's `app_proxy` container. This app has no `app_proxy`, so the address
is unresolvable and the sidecar (`bitme-cosigner-tor_server-1`) crash-loops with "Unparseable
address in hidden service port configuration". The cosigner itself is unaffected - it's a
separate container - but you'll see a container restarting forever.

Deciding what *should* happen here is a security question, not a packaging one, so it's
deliberately left open: pointing the hidden service straight at the app container would work,
but it would publish an unauthenticated signing API as an onion service, which is exactly the
kind of thing the "treat network access to it as sensitive" warning above is about. If you don't
want that, the options are to leave the sidecar crash-looping (harmless, noisy) or turn off
remote Tor access for the device.

## Install

1. In your Umbrel: **App Store → ⋮ → Community App Stores → Add App Store**, and paste:
   `https://github.com/TDH-Labs/Bitme`
2. Find **Bitme Cosigner** in the store and install it.
3. It will fail to start the first time - that's expected. It has no config yet.

## Configure

Umbrel gives every app a persistent data directory at `~/umbrel/app-data/bitme-cosigner` on the
host (exact path may vary by Umbrel version - check **Settings → Advanced → Terminal**, or SSH
in). Two host directories are mounted into the container, and the config one is easy to get
wrong:

| host | container | |
|---|---|---|
| `~/umbrel/app-data/bitme-cosigner/data` | `/data` | read-write - ledger DB, generated.toml |
| `~/umbrel/app-data/bitme-cosigner/config` | `/data/config` | read-only - **your config goes here** |

Note `config/` sits **next to** `data/`, not inside it. `data/config/` on the host looks like the
right place and is not - the second mount shadows it, so anything you put there is invisible to
the service and you'll just keep getting "missing /data/config/wallet.toml".

You need to place two files in `~/umbrel/app-data/bitme-cosigner/config/`:

1. `wallet.toml` - copy [`bitme-cosigner/wallet.toml.example`](../bitme-cosigner/wallet.toml.example)
   from this repo and fill in your real SATOCHIP/MOBILE/SERVER xpubs, `[policy]`, and `[notify]`.
   Leave `network = "signet"` and don't add `[bitcoind]`/`[server]` - see the comments in the
   file.
2. `server.xprv` - a plain text file containing only your SERVER account-level xprv (matching
   `[keys.server]` in `wallet.toml`). This service never generates keys - generate this yourself,
   the same way you would for the plain Docker deployment (see [`docs/DOCKER.md`](DOCKER.md)).

Both directories are created by Docker on first start and are owned by `root`, so writing into
them needs `sudo` even though the app directory above them belongs to `umbrel`:

```sh
ssh umbrel@umbrel.local
cd ~/umbrel/app-data/bitme-cosigner/config     # NOT .../data/config - see the table above
# copy wallet.toml.example in from this repo (scp, or paste with an editor), then:
sudo $EDITOR wallet.toml
sudo $EDITOR server.xprv     # just the xprv, nothing else
sudo chmod 600 server.xprv
sudo chown 1000:1000 wallet.toml server.xprv   # the container runs as uid 1000
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
against the image Umbrel already built for this app instead. On the device this was verified on,
Umbrel names that image `bitme-cosigner-app:latest` (Compose derives it from the project and
service names), but confirm on your own device rather than assuming:

```sh
ssh umbrel@umbrel.local
docker images | grep bitme-cosigner   # expect bitme-cosigner-app
cd ~/umbrel/app-data/bitme-cosigner
```

`config/` is mounted read-only into the running `app` container, so anything that *writes*
there (the wizard) needs its own writable mount instead of going through the running container:

```sh
docker run --rm -it -v "$(pwd)/config:/out" <image-from-above> init --out /out/wallet.toml
```

`recovery-kit`/`migrate-build-sweep` read `wallet.toml` (fine, read-only) and write their
output to `/data` (the *other* mount, which is writable) - run them the same way, e.g.:

```sh
# config/ is root-owned (Docker created it), hence the sudo - see the Configure section
echo "your long passphrase here" | sudo tee config/recovery-kit-passphrase.txt >/dev/null
sudo chown 1000:1000 config/recovery-kit-passphrase.txt

docker run --rm \
  -v "$(pwd)/data:/data" -v "$(pwd)/config:/data/config:ro" \
  <image-from-above> recovery-kit export \
    --config /data/config/wallet.toml \
    --passphrase-file /data/config/recovery-kit-passphrase.txt \
    --out /data/recovery-kit.age

sudo rm config/recovery-kit-passphrase.txt   # don't leave the passphrase sitting on disk

# the blob lands in the writable mount, i.e. on the host at:
#   ~/umbrel/app-data/bitme-cosigner/data/recovery-kit.age
# move it OFF this device - see docs/DOCKER.md §3a
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
cd ~/umbrel/app-data/bitme-cosigner
sudo $EDITOR config/nostr.nsec   # just the nsec, nothing else
sudo chmod 600 config/nostr.nsec && sudo chown 1000:1000 config/nostr.nsec
sudo $EDITOR config/wallet.toml  # uncomment [nostr_transport]; nsec_file = "/data/config/nostr.nsec"
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
