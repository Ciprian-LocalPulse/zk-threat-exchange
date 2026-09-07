# zk-threat-exchange :: core-node image
# Author: Ciprian Ștefan Pleșca
FROM rust:1.75-slim AS builder
WORKDIR /build
COPY core-node/Cargo.toml ./Cargo.toml
COPY core-node/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
LABEL maintainer="Ciprian Ștefan Pleșca"
COPY --from=builder /build/target/release/zk-node /usr/local/bin/zk-node
ENV NODE_ID=docker-node
ENTRYPOINT ["/usr/local/bin/zk-node"]
