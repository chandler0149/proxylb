# Stage 1: Build the Rust backend
FROM rust:trixie AS backend-builder
WORKDIR /usr/src/app
COPY . .
RUN make box


# Stage 2: Build the React frontend
FROM node:24-slim AS frontend-builder
WORKDIR /usr/src/app/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build


# Stage 3: Runtime image
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y ca-certificates nginx && \
    rm -rf /var/lib/apt/lists/*

# Copy built frontend assets to Nginx html directory
COPY --from=frontend-builder /usr/src/app/web/dist /var/www/html

# Copy Nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy Rust backend binary
COPY --from=backend-builder /usr/src/app/target/release/proxylb /usr/local/bin/proxylb

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /etc/proxylb
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
