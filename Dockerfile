FROM rust:trixie as builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock* ./
COPY src src

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/proxylb /usr/local/bin/proxylb

WORKDIR /etc/proxylb
ENTRYPOINT ["proxylb", "-c", "config.yaml"]
