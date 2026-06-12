# Variables
APP_NAME := proxylb
CARGO := cargo

# Targets
AMD64_TARGET := x86_64-unknown-linux-gnu
ARM64_TARGET := aarch64-unknown-linux-gnu

.PHONY: all arm64 amd64 clean help bench bench_clean

## Default target: build for the native architecture (assumed arm64 based on your command)
all: arm64 amd64

release:
	$(CARGO) build --release

arm64:
	@echo "Building for ARM64..."
	$(CARGO) build --target=$(ARM64_TARGET) --release

box:
	@echo "Building for ARM64 (box)..."
	RUSTFLAGS="-C target-cpu=cortex-a53" $(CARGO) build --release
	
amd64:
	@echo "Building for AMD64..."
	$(CARGO) build --target=$(AMD64_TARGET) --release

ali:
	@echo "Building for AMD64..."
	RUSTFLAGS="-C target-cpu=x86-64-v4" $(CARGO) build --target=$(AMD64_TARGET) --release

docker:
	docker build -t proxylb .

## Remove build artifacts
clean:
	@echo "Cleaning project..."
	$(CARGO) clean

## Run SOCKS5 CPS Benchmark
bench: release
	ulimit -n 1024000
	@echo "Starting SOCKS5 CPS benchmark..."
	@killall -9 proxylb || true
	@killall -9 dummy_uds_backend || true
	@killall -9 benchmark_cps || true
	@rm -f /tmp/mock_socks5.sock
	@echo "Starting Rust SOCKS5 mock backend on CPU core 3..."
	@taskset -c 3 ./target/release/dummy_uds_backend /tmp/mock_socks5.sock > /dev/null 2>&1 &
	@sleep 1
	@echo "Starting ProxyLB in release mode..."
	@./target/release/proxylb -c ./bench/bench_config.yaml --log-level info > bench.log 2>&1 &
	@sleep 1
	@echo "Running Rust SOCKS5 CPS benchmark..."
	@taskset -c 4,5,6 ./target/release/benchmark_cps --proxy-host 127.0.0.1 --proxy-port 1080 --target-host 127.0.0.1 --target-port 10800 --concurrency 300 --duration 10
	@echo "Cleaning up processes..."
	@killall -9 proxylb || true
	@killall -9 dummy_uds_backend || true
	@killall -9 benchmark_cps || true
	@rm -f /tmp/mock_socks5.sock
	@echo "Benchmark complete."

## Clean SOCKS5 CPS Benchmark processes and sockets
bench_clean:
	@echo "Cleaning up SOCKS5 benchmark processes and sockets..."
	@killall -9 proxylb || true
	@killall -9 dummy_uds_backend || true
	@killall -9 benchmark_cps || true
	@rm -f /tmp/mock_socks5.sock

## Show help
help:
	@      
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  arm64       Build release binary for ARM64 (native)"
	@echo "  amd64       Build release binary for AMD64 (x86_64-unknown-linux-gnu)"
	@echo "  clean       Remove target directory"
	@echo "  bench       Run SOCKS5 CPS benchmark"
	@echo "  bench_clean Stop benchmark processes and remove socket files"
