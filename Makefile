# Variables
APP_NAME := proxylb
CARGO := cargo

# Targets
AMD64_TARGET := x86_64-unknown-linux-gnu

.PHONY: all arm64 amd64 clean help

## Default target: build for the native architecture (assumed arm64 based on your command)
all: arm64

## Build for ARM64 (Native/Release)
arm64:
	@echo "Building for ARM64..."
	$(CARGO) build --release

## Build for AMD64 (Cross-compile/Release)
amd64:
	@echo "Building for AMD64..."
	$(CARGO) build --target=$(AMD64_TARGET) --release

## Remove build artifacts
clean:
	@echo "Cleaning project..."
	$(CARGO) clean

## Show help
help:
	@      
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  arm64   Build release binary for ARM64 (native)"
	@echo "  amd64   Build release binary for AMD64 (x86_64-unknown-linux-gnu)"
	@echo "  clean   Remove target directory"