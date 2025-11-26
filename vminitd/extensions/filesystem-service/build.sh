#!/bin/bash
# Build Arca Filesystem Service binary for Linux ARM64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building arca-filesystem-service for Linux ARM64..."

# Cross-compile for Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -o arca-filesystem-service \
    -ldflags="-s -w" \
    ./cmd/arca-filesystem-service

if [ ! -f arca-filesystem-service ]; then
    echo "ERROR: Build failed - arca-filesystem-service binary not created"
    exit 1
fi

echo "✓ Built arca-filesystem-service ($(du -h arca-filesystem-service | awk '{print $1}')"
