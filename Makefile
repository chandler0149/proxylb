# Variables
APP_NAME := proxylb
CARGO := cargo
PGO_DIR := $(CURDIR)/pgo-data

# Targets
AMD64_TARGET := x86_64-unknown-linux-gnu
ARM64_TARGET := aarch64-unknown-linux-gnu

.PHONY: all arm64 amd64 clean help bench bench_clean pgo pgo_clean

## Default target: build for the native architecture (assumed arm64 based on your command)
all: arm64 amd64

FEATURES := --features filter

release:
	$(CARGO) build --release $(FEATURES)

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

## ── PGO (Profile-Guided Optimization) ────────────────────────────────────────
## Usage:
##   make pgo                      — full PGO pipeline (instrument → bench → optimize)
##   make pgo BENCH_UDS=1          — same, using UDS transport for benchmark

pgo: pgo_clean
	@echo "══════════════════════════════════════════════════════════════"
	@echo " Stage 1/3: Building instrumented binary"
	@echo "══════════════════════════════════════════════════════════════"
	@rustup component add llvm-tools-preview 2>/dev/null || true
	RUSTFLAGS="-Cprofile-generate=$(PGO_DIR)" $(CARGO) build --release $(FEATURES)
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo " Stage 2/3: Collecting profile data via benchmark"
	@echo "══════════════════════════════════════════════════════════════"
	@killall -9 proxylb 2>/dev/null || true
	@killall -9 dummy_uds_backend 2>/dev/null || true
	@killall -9 benchmark_cps 2>/dev/null || true
	@rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock
	@echo "Starting mock backend..."
	@./target/release/dummy_uds_backend /tmp/mock_socks5.sock > /dev/null 2>&1 &
	@sleep 1
	@echo "Starting instrumented ProxyLB..."
	@rm /tmp/bench.log
	@LLVM_PROFILE_FILE="$(PGO_DIR)/proxylb_%m_%p.profraw" \
		./target/release/proxylb -c ./bench/bench_config.yaml --log-level info > /tmp/bench.log 2>&1 &
	@sleep 5
	@echo "Running benchmark workload (profile collection)..."
	@if [ "$(BENCH_UDS)" = "1" ]; then \
		./target/release/benchmark_cps \
			--proxy-uds /tmp/proxylb_bench.sock \
			--target-host 127.0.0.1 --target-port 10800 \
			--concurrency 300 --duration 10 --random-domains; \
	else \
		./target/release/benchmark_cps \
			--proxy-host 127.0.0.1 --proxy-port 1080 \
			--target-host 127.0.0.1 --target-port 10800 \
			--concurrency 300 --duration 10 --random-domains; \
	fi
	@echo "Stopping instrumented processes..."
	@killall proxylb 2>/dev/null || true
	@sleep 2
	@killall -9 proxylb 2>/dev/null || true
	@killall -9 dummy_uds_backend 2>/dev/null || true
	@killall -9 benchmark_cps 2>/dev/null || true
	@rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock
	@echo ""
	@echo "Merging profile data..."
	@LLVM_PROFDATA=$$(find $$(rustc --print sysroot) -name llvm-profdata -type f 2>/dev/null | head -n1); \
	if [ -z "$$LLVM_PROFDATA" ]; then \
		echo "ERROR: llvm-profdata not found. Run: rustup component add llvm-tools-preview"; \
		exit 1; \
	fi; \
	$$LLVM_PROFDATA merge -o $(PGO_DIR)/merged.profdata $(PGO_DIR)/*.profraw
	@echo "Profile data merged: $(PGO_DIR)/merged.profdata"
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo " Stage 3/3: Building PGO-optimized binary"
	@echo "══════════════════════════════════════════════════════════════"
	RUSTFLAGS="-Cprofile-use=$(PGO_DIR)/merged.profdata" \
		$(CARGO) build --release $(FEATURES)
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo " PGO build complete! Binary: target/release/proxylb"
	@echo "══════════════════════════════════════════════════════════════"
# 	make bench_clean
# 	make bench BENCH_UDS=1

## Clean PGO profile data
pgo_clean:
	@rm -rf $(PGO_DIR)
	@mkdir -p $(PGO_DIR)

## Run SOCKS5 CPS Benchmark
# Usage:
#   make bench                   — TCP mode  (may hit port limits on macOS)
#   make bench BENCH_UDS=1       — UDS mode  (no port exhaustion, macOS-friendly)
bench: release bench_run

bench_run:
	@echo "Starting SOCKS5 CPS benchmark..."
	@killall -9 proxylb 2>/dev/null || true
	@killall -9 dummy_uds_backend 2>/dev/null || true
	@killall -9 benchmark_cps 2>/dev/null || true
	@rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock
	@echo "Starting Rust SOCKS5 mock backend..."
	@./target/release/dummy_uds_backend /tmp/mock_socks5.sock > /dev/null 2>&1 &
	@sleep 1
	@echo "Starting ProxyLB in release mode..."
	@./target/release/proxylb -c ./bench/bench_config.yaml --log-level info > bench.log 2>&1 &
	@sleep 5
	@echo "Running Rust SOCKS5 CPS benchmark..."
	@if [ "$(BENCH_UDS)" = "1" ]; then \
		./target/release/benchmark_cps \
			--proxy-uds /tmp/proxylb_bench.sock \
			--target-host 127.0.0.1 --target-port 10800 \
			--concurrency 300 --duration 10 --random-domains; \
	else \
		./target/release/benchmark_cps \
			--proxy-host 127.0.0.1 --proxy-port 1080 \
			--target-host 127.0.0.1 --target-port 10800 \
			--concurrency 300 --duration 10 --random-domains; \
	fi
	@echo "Cleaning up processes..."
	@killall -9 proxylb 2>/dev/null || true
	@killall -9 dummy_uds_backend 2>/dev/null || true
	@killall -9 benchmark_cps 2>/dev/null || true
	@rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock
	@echo "Benchmark complete."

## Clean SOCKS5 CPS Benchmark processes and sockets
bench_clean:
	@echo "Cleaning up SOCKS5 benchmark processes and sockets..."
	@killall -9 proxylb 2>/dev/null || true
	@killall -9 dummy_uds_backend 2>/dev/null || true
	@killall -9 benchmark_cps 2>/dev/null || true
	@rm -f /tmp/mock_socks5.sock /tmp/proxylb_bench.sock

## Show help
help:
	@      
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  release     Build release binary (native)"
	@echo "  arm64       Build release binary for ARM64 (native)"
	@echo "  amd64       Build release binary for AMD64 (x86_64-unknown-linux-gnu)"
	@echo "  clean       Remove target directory"
	@echo "  bench       Run SOCKS5 CPS benchmark"
	@echo "  bench_clean Stop benchmark processes and remove socket files"
	@echo "  pgo         Full PGO pipeline: instrument → bench → optimize"
	@echo "  pgo_clean   Remove PGO profile data"

