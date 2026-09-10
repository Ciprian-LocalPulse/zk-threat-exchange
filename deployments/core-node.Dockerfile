# zk-threat-exchange :: core-node image
# Author: Ciprian Ștefan Pleșca
#
# Pinned to the "1" major-version-floating tag (always the latest stable
# 1.x release) rather than a specific minor version like "1.75" — the
# libp2p dependency tree (added in v0.3.0) requires a current Rust
# toolchain (edition2024-aware Cargo); pinning to an old minor version here
# would silently break this build again the next time a transitive
# dependency bumps its MSRV.
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
# rusqlite's "bundled" feature (v0.4.0+) compiles SQLite from its C source,
# which requires a C compiler and make — not present in the slim image by
# default.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY core-node/Cargo.toml ./Cargo.toml
COPY core-node/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
LABEL maintainer="Ciprian Ștefan Pleșca"
COPY --from=builder /build/target/release/zk-node /usr/local/bin/zk-node
ENV NODE_ID=docker-node
# Persist the SQLite pool file outside the container's writable layer by
# mounting a volume at /data in docker-compose.yml; DB_DIR tells core-node
# to write there (namespaced per NODE_ID) instead of the default ./data/
# relative to the container's working directory.
ENV DB_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/zk-node"]
