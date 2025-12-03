#!/bin/bash
# Build arca-services for Linux ARM64 (cross-compile from macOS)
# This is the unified service binary that runs all container extension services

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building arca-services (unified service binary)..."

# Cross-compile for Linux ARM64 (static binary, no cgo)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o arca-services \
    ./cmd/arca-services

echo "  ✓ Built: arca-services ($(du -h arca-services | awk '{print $1}'))"
