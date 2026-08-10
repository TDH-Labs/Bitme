#!/bin/sh
# Generates the deployment-specific parts of the wallet config ([bitcoind], [server]) fresh on
# every container start, from environment variables, and appends them to the operator-edited
# static config - so the same image works unmodified both for a plain docker-compose deployment
# and for Umbrel (which injects different values for the same variables). See docs/DOCKER.md.
set -eu

DATA_DIR="${COSIGNER_DATA_DIR:-/data}"
CONFIG_DIR="$DATA_DIR/config"
USER_CONFIG="$CONFIG_DIR/wallet.toml"
GENERATED_CONFIG="$DATA_DIR/generated.toml"

mkdir -p "$CONFIG_DIR"

# Anything other than the default `serve` command (e.g. `descriptor build`) is passed straight
# through - those don't need [bitcoind]/[server] and shouldn't require a full deployment config.
if [ "${1:-}" != "serve" ]; then
    exec cosigner "$@"
fi
shift

# No config yet: serve the browser-based setup wizard on the app's own port instead of dying.
# This used to be a hard `exit 1` telling the operator to go and write TOML by hand, which on
# Umbrel meant SSHing into the box - there is no file editor or secret-entry UI there. The
# wizard writes wallet.toml and server.xprv and then shuts itself down, at which point Docker's
# restart policy brings the container back here and the branch below takes over. It is only
# ever a wizard OR the API, never both, so an unconfigured process never holds a signing key.
if [ ! -f "$USER_CONFIG" ]; then
    if [ ! -w "$CONFIG_DIR" ]; then
        cat >&2 <<EOF
ERROR: $CONFIG_DIR is not writable by this container (running as uid $(id -u)).

The setup wizard needs to write wallet.toml and server.xprv there. On Umbrel this directory
should already be owned by 1000:1000; if you bind-mounted it yourself, chown it to the uid
above. See docs/DOCKER.md.
EOF
        exit 1
    fi
    echo "No $USER_CONFIG yet - starting the setup wizard." >&2
    exec cosigner setup \
        --config-dir "$CONFIG_DIR" \
        --data-dir "$DATA_DIR" \
        --bind "0.0.0.0:${COSIGNER_HTTP_PORT:-8080}" \
        --network "${APP_BITCOIN_NETWORK:-${COSIGNER_NETWORK:-signet}}" \
        --bitcoind-rpc-url "${BITCOIND_RPC_URL:-}"
fi

if [ -z "${BITCOIND_RPC_URL:-}" ]; then
    echo "ERROR: BITCOIND_RPC_URL is not set." >&2
    exit 1
fi

# --- Optional safety net: catch a config/deployment mismatch before it can matter -------------
# APP_BITCOIN_NETWORK is injected by Umbrel when this app depends on the official Bitcoin Core
# app (see umbrel/bitme-cosigner/docker-compose.yml) - it is never set outside Umbrel.
if [ -n "${APP_BITCOIN_NETWORK:-}" ]; then
    configured_network=$(grep -E '^[[:space:]]*network[[:space:]]*=' "$USER_CONFIG" \
        | head -n1 | sed -E 's/^[^"]*"([^"]*)".*/\1/')
    case "$APP_BITCOIN_NETWORK" in
        testnet4) expected_network=testnet ;;
        *) expected_network="$APP_BITCOIN_NETWORK" ;;
    esac
    if [ -n "$configured_network" ] && [ "$configured_network" != "$expected_network" ]; then
        echo "ERROR: wallet.toml declares network = \"$configured_network\", but the Bitcoin" >&2
        echo "Core app this depends on is running \"$APP_BITCOIN_NETWORK\". Refusing to start" >&2
        echo "rather than run against a mismatched node." >&2
        exit 1
    fi
fi

# --- Generate the deployment-specific sections -------------------------------------------------
{
    cat "$USER_CONFIG"
    echo ""
    echo "[bitcoind]"
    printf 'rpc_url = "%s"\n' "$BITCOIND_RPC_URL"
    if [ -n "${BITCOIND_RPC_COOKIE_FILE:-}" ]; then
        printf 'rpc_cookie_file = "%s"\n' "$BITCOIND_RPC_COOKIE_FILE"
    else
        : "${BITCOIND_RPC_USER:?BITCOIND_RPC_USER or BITCOIND_RPC_COOKIE_FILE is required}"
        : "${BITCOIND_RPC_PASSWORD:?BITCOIND_RPC_PASSWORD or BITCOIND_RPC_COOKIE_FILE is required}"
        printf 'rpc_user = "%s"\n' "$BITCOIND_RPC_USER"
        printf 'rpc_password = "%s"\n' "$BITCOIND_RPC_PASSWORD"
    fi
    echo ""
    echo "[server]"
    printf 'bind_addr = "0.0.0.0:%s"\n' "${COSIGNER_HTTP_PORT:-8080}"
    printf 'gap_limit = %s\n' "${COSIGNER_GAP_LIMIT:-1000}"
    printf 'ledger_db_path = "%s"\n' "$DATA_DIR/ledger.sqlite3"
    # Written by the setup wizard. Emitted unconditionally: if the file is absent (an install
    # that predates it) the service logs a warning and runs unauthenticated, exactly as before,
    # rather than refusing to start. Delete the file to turn authentication off.
    printf 'api_token_file = "%s"\n' "$CONFIG_DIR/api.token"
} >"$GENERATED_CONFIG"

exec cosigner serve --config "$GENERATED_CONFIG" "$@"
