#!/usr/bin/env bash
# Simulates Umbrel's app environment locally, without real Umbrel hardware: brings up a
# throwaway regtest bitcoind (standing in for Umbrel's own Bitcoin Core app) plus this
# project's bitme-cosigner/docker-compose.yml, wired together with the same $APP_BITCOIN_*
# variables Umbrel actually injects for a `dependencies: [bitcoin]` app (confirmed against
# Umbrel's own app store source - see docs/UMBREL.md).
#
# What a PASS here proves: the build context resolves correctly, the image builds, the
# container starts, and it correctly derives [bitcoind] from Umbrel-shaped env vars.
# What it does NOT prove: that it actually works on real Umbrel hardware (different
# architecture unless you're on Apple Silicon/arm64 already, different filesystem/permissions
# behavior, Umbrel's own app lifecycle). Treat a pass here as "packaging is structurally
# sound", not "verified on Umbrel" - see docs/UMBREL.md for the real hardware install steps.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT_DIR/bitme-cosigner"
PROJECT="cosigner-umbrel-sim"
DATA_DIR="$(mktemp -d)"
FRAGMENT_DIR="$(mktemp -d)"

# Umbrel always passes its own compose fragments BEFORE the app's, and never passes
# --project-directory. Compose therefore resolves relative paths against the FIRST file's
# directory - somewhere inside umbreld, not the app's folder. This stand-in fragment lives in an
# unrelated temp dir purely to reproduce that, so a relative build context fails here the same
# way it fails on a real device instead of silently passing.
cat >"$FRAGMENT_DIR/docker-compose.umbrel-fragment.yml" <<'EOF'
services:
  app:
    labels:
      dev.tdhlabs.umbrel-sim: "true"
EOF

COMPOSE_FILES=(
    -f "$FRAGMENT_DIR/docker-compose.umbrel-fragment.yml"
    -f "$APP_DIR/docker-compose.yml"
    -f "$APP_DIR/docker-compose.simulate-umbrel.yml"
)

cleanup() {
    echo
    echo "--- tearing down (data dir $DATA_DIR removed) ---"
    docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v || true
    rm -rf "$DATA_DIR" "$FRAGMENT_DIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR/data" "$DATA_DIR/config"

# Mirror what Umbrel's installer actually does: rsync THIS app folder (and nothing else from the
# repo) into the app's data directory, then build from there. The earlier version of this script
# skipped this and ran compose straight from the repo checkout, which is why it missed two real
# bugs that only bite after the copy - a relative build context resolving outside the copied
# folder, and the Dockerfile not being inside it at all. Keep this faithful.
rsync --archive --exclude ".gitkeep" --exclude "docker-compose.simulate-umbrel.yml" \
    "$APP_DIR/." "$DATA_DIR"
cat >"$DATA_DIR/config/README.txt" <<EOF
To get past "missing wallet.toml" and actually see this reach /health:
  cp $APP_DIR/wallet.toml.example $DATA_DIR/config/wallet.toml   # then fill in real xpubs
  # and write a server.xprv here (see docs/UMBREL.md) matching wallet.toml's [keys.server]
Then restart the app container (re-run this script, or):
  docker compose -p $PROJECT \\
    -f $FRAGMENT_DIR/docker-compose.umbrel-fragment.yml \\
    -f $APP_DIR/docker-compose.yml \\
    -f $APP_DIR/docker-compose.simulate-umbrel.yml restart app
EOF

# Umbrel-injected variables, faked. Real Umbrel would set these to its actual Bitcoin Core
# app's connection details; here they point at the bitcoind service added by
# docker-compose.simulate-umbrel.yml, reachable by service-name DNS within this compose project.
# APP_PROXY_PORT, not APP_PORT: Umbrel derives this from `port:` in umbrel-app.yml and it's what
# the app's compose file publishes on. See the note in bitme-cosigner/docker-compose.yml.
export APP_PROXY_PORT="${APP_PROXY_PORT:-18099}"
export APP_DATA_DIR="$DATA_DIR"
export APP_BITCOIN_NODE_IP=bitcoind
export APP_BITCOIN_RPC_PORT=18443
export APP_BITCOIN_RPC_USER=umbrelsim
export APP_BITCOIN_RPC_PASS=umbrelsim
export APP_BITCOIN_NETWORK=regtest

# no cd: every compose file is referenced by absolute path, matching how Umbrel invokes it
echo "--- building and starting (this rebuilds the Rust binary from source - can take a few minutes) ---"
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" up -d --build

echo
echo "--- without a real wallet.toml in place, the app container will exit/restart-loop - that's"
echo "    expected, see $DATA_DIR/config/README.txt to get past it ---"
sleep 3
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" ps
echo
echo "--- app logs ---"
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" logs app --no-color | tail -30

echo
echo "Once a real wallet.toml + server.xprv are in place and the app is restarted:"
echo "    curl http://localhost:${APP_PROXY_PORT}/health"
echo
echo "Press Enter to tear everything down (or Ctrl-C to leave it running and clean up yourself)."
read -r || true
