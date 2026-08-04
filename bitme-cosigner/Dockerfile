### Build stage ################################################################################
FROM rust:1-slim-bookworm AS builder

# secp256k1-sys and the bundled libsqlite3-sys both compile C code via the `cc` crate - a
# plain rust:slim image has no C compiler.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency compilation separately from application code: a dummy src/ lets `cargo
# build` resolve and compile every dependency once, so editing src/*.rs later doesn't force
# recompiling axum, sqlx, bitcoin, etc. from scratch.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin cosigner \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin cosigner

### Runtime stage ###############################################################################
FROM debian:bookworm-slim

# The runtime user is uid/gid 1000 deliberately, not a floating --system id. Umbrel chowns app
# data to 1000:1000 and its own apps run as '1000:1000'. With a --system uid (999 in practice)
# this container cannot write /data/generated.toml - which docker-entrypoint.sh regenerates on
# EVERY start - so it exits with "Permission denied" the moment a valid wallet.toml exists.
# That stayed invisible for a long time because the missing-config check fires first, masking it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /data --uid 1000 --user-group \
        --shell /usr/sbin/nologin cosigner \
    && mkdir -p /data/config \
    && chown -R cosigner:cosigner /data

COPY --from=builder /app/target/release/cosigner /usr/local/bin/cosigner
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER cosigner
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${COSIGNER_HTTP_PORT:-8080}/health" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
