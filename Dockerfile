# Stage 1: Build the React frontend
FROM node:24-slim AS frontend-builder
WORKDIR /usr/src/app/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# Stage 2: Build the Rust backend
FROM rust:trixie AS backend-builder
WORKDIR /usr/src/app
COPY . .
# Copy the compiled web UI so rust-embed can bundle it into the binary
COPY --from=frontend-builder /usr/src/app/web/dist ./web/dist
RUN cargo build --release --features filter

# Stage 3: Runtime image
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy Rust backend binary (now contains the bundled frontend)
COPY --from=backend-builder /usr/src/app/target/release/proxylb /usr/local/bin/proxylb

WORKDIR /etc/proxylb
ENTRYPOINT ["/usr/local/bin/proxylb", "-c", "config.yaml", "run"]
