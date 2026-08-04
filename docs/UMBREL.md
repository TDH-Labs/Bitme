# Running cosigner on Umbrel

**Status: installed and started on real Umbrel hardware** (umbrelOS on x86_64, Bitcoin Core app
present) as of the commit that added this note. What is verified: the app store picks the repo
up, the image builds on-device from source, the container is created and started, Umbrel's
Bitcoin Core connection details are injected correctly, and the app publishes on its manifest
port. What is *not* yet verified: anything past that point - `/health`, a real descriptor, or a
signing round trip - because all of those need the three real keys, which no amount of packaging
work can substitute for.

That first install found three packaging bugs that only appear on a real device: a build context
that resolved outside the app's folder, a port variable Umbrel doesn't actually export to apps,
and a runtime uid that couldn't write its own data directory (the last one stayed hidden because
the missing-config check fires first). All three are fixed, and `scripts/simulate-umbrel.sh` now
reproduces the conditions that hid the first two. Still treat your own first install as a test
rather than a known-good deployment.

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

One departure from the usual Umbrel app pattern, and it's smaller than it used to be. This app
has a browser UI for exactly one thing - first-run setup. Once that's done it goes back to being
what the main README describes: an HTTP API, with `GET /health` as the only thing worth looking
at in a browser.

It does sit behind Umbrel's `app_proxy` like any other app, which means **Umbrel's session
authentication gates the API**. That is deliberate: the API has no authentication of its own
(see the threat-model table in the main README), so the proxy is the only thing between a device
on your LAN and an endpoint that can burn spending limits. The app container publishes no host
port of its own, so that auth can't be walked around by connecting to the container directly.

> Earlier versions of this app deliberately had no `app_proxy`, on the theory that a headless API
> didn't need one. That was a mistake, and a load-bearing one: Umbrel starts a `tor_server`
> sidecar for **every** app and builds its torrc from `app_proxy_<id>`. With no such container to
> resolve, the sidecar died with `Unparseable address in hidden service port configuration` and
> restart-looped forever. Opting out of `app_proxy` isn't something Umbrel actually supports.

## Install

1. In your Umbrel: **App Store → ⋮ → Community App Stores → Add App Store**, and paste:
   `https://github.com/TDH-Labs/Bitme`
2. Find **Bitme Cosigner** in the store and install it.
3. Open it. It has no config yet, so it serves the setup wizard instead of the API.

## Configure

Open the app from your Umbrel dashboard and follow the wizard. It will:

1. Show you which network it's on, taken from the Bitcoin Core app it depends on - you don't
   choose it here, and it refuses to start later if the two ever disagree.
2. Take your **SATOCHIP** key (master fingerprint, derivation path, account xpub), validating
   each field as you enter it - a wrong-network xpub, or one exported at the wrong depth, is
   rejected on the spot rather than at the end.
3. Take your **Bitcoin Keeper** key the same way.
4. **Generate the SERVER key on the box**, from the OS CSPRNG. You never see or handle the
   private key; it's written to `config/server.xprv` mode `0600`. Only the account-level xprv is
   kept - the master it came from is dropped after derivation.
5. Collect your spending limits, hold window, and a notification URL.
6. Write `config/wallet.toml`, then show you the **descriptor** - as text and as a QR - to
   register in Bitcoin Keeper, along with the first receive address to cross-check against what
   Keeper shows you.

Clicking **Start the cosigner** shuts the wizard down; Umbrel restarts the container and it comes
back serving the real API. It is a wizard *or* the API, never both, and a restart is the only
transition - so a half-configured process never holds a signing key.

[Screenshots of every step](screenshots/) - captured by driving the real wizard, not mocked up.
The SERVER key is generated on the box from the kernel CSPRNG; if you want to know exactly how,
or would rather supply your own key, see [`KEY-GENERATION.md`](KEY-GENERATION.md).

Nothing is written to disk until the last step, and it refuses to overwrite an existing
`wallet.toml`. If you want to start over, delete both files from
`~/umbrel/app-data/bitme-cosigner/config/` and restart the app.

> **Keep a copy of the descriptor.** Your three keys alone cannot rebuild the wallet without it.
> It contains no private keys, so it's safe to store as plain text - and `recovery-kit export`
> (below) is the encrypted, more complete version of the same idea.

### Where the files actually live

Two host directories are mounted into the container, and the config one is easy to get wrong:

| host | container | |
|---|---|---|
| `~/umbrel/app-data/bitme-cosigner/data` | `/data` | ledger DB, generated.toml |
| `~/umbrel/app-data/bitme-cosigner/config` | `/data/config` | **wallet.toml + server.xprv** |

Note `config/` sits **next to** `data/`, not inside it. `data/config/` on the host looks like the
right place and is not - the second mount shadows it, so anything you put there is invisible to
the service.

Both directories ship empty in this app's folder, so Umbrel's installer creates them owned by
`1000:1000` - the same uid the container runs as - and no `sudo`/`chown` dance is needed.

> If you installed a version before this was fixed, those directories may still exist as
> `root:root` from when Docker auto-created them. The wizard will refuse to start and say so.
> Fix with `sudo chown -R 1000:1000 ~/umbrel/app-data/bitme-cosigner/{data,config}`.

You can still write both files by hand instead of using the wizard - see
[`docs/DOCKER.md`](DOCKER.md) - and `cosigner init` (below) is the terminal equivalent of the same
flow. The wizard is the recommended path on Umbrel simply because Umbrel has no file editor.

## Verify it's up

Open the app from the dashboard - once configured, it answers with a JSON health check rather
than a page. Or from your Umbrel's LAN:

```sh
curl http://umbrel.local:8080/health
```

Expect `{"service":"cosigner","version":"...","network":"signet","policy_version":1}`. A
`"status":"awaiting-setup"` field instead means it's still unconfigured and serving the wizard.

If `network` isn't what you expect, or the container keeps restarting, check its logs
(**Bitme Cosigner → ⋮ → Logs**, or `docker logs bitme-cosigner_app_1`) -
`docker-entrypoint.sh` prints a specific reason (missing xprv, an unwritable config directory, or
a network mismatch between `wallet.toml` and your Bitcoin Core app) rather than failing silently.

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
echo "your long passphrase here" > config/recovery-kit-passphrase.txt

docker run --rm \
  -v "$(pwd)/data:/data" -v "$(pwd)/config:/data/config:ro" \
  <image-from-above> recovery-kit export \
    --config /data/config/wallet.toml \
    --passphrase-file /data/config/recovery-kit-passphrase.txt \
    --out /data/recovery-kit.age

rm config/recovery-kit-passphrase.txt   # don't leave the passphrase sitting on disk

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
$EDITOR config/nostr.nsec   # just the nsec, nothing else
chmod 600 config/nostr.nsec
$EDITOR config/wallet.toml  # uncomment [nostr_transport]; nsec_file = "/data/config/nostr.nsec"
```

Then restart the app from the Umbrel dashboard. Removing a device's npub from
`allowed_npubs` and restarting is how you cut it off - its messages are still cryptographically
genuine, they're just no longer answered.

## Updating

Umbrel's App Store update mechanism handles pulling new versions of this repo; since the app is
built from source (`build: context: ${APP_DATA_DIR}` in `bitme-cosigner/docker-compose.yml`, not
a pre-published image), the first install and every update rebuild the Rust binary on your
device. On Umbrel Home (Intel N100) this is a few minutes; on a Raspberry Pi it will be
noticeably slower. Your `wallet.toml`, `server.xprv`, and the ledger database all live in the
persistent data directory and survive updates.

**One gotcha found on-device:** Umbrel injects this app's Bitcoin Core connection details
(including `APP_BITCOIN_NETWORK`) as environment variables baked in when the container is
*created*, not re-read on every start. If you change your Bitcoin Core app's network *after*
installing Bitme Cosigner, a plain restart won't pick up the new value - the container needs to
be recreated (uninstall and reinstall) before `docker logs` will show the network you actually
switched to. Config file changes (`wallet.toml`, `server.xprv`) don't have this problem - those
are read fresh from the mounted volume on every start, restart is enough for those.
