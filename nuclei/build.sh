#!/bin/bash
# Build script for WAF Testing Tool
# Supports Windows, Linux, and macOS

set -e

echo "Building WAF Testing Tool..."
echo ""

# Build for current platform
echo "Building for current platform..."
go build -o nuclei-waf ./cmd/nuclei-waf
echo "✓ Built: nuclei-waf"

# Cross-compile for other platforms
echo ""
echo "Cross-compiling for other platforms..."

# Windows
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o nuclei-waf-windows-amd64.exe ./cmd/nuclei-waf
echo "✓ Built: nuclei-waf-windows-amd64.exe"

# Linux
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o nuclei-waf-linux-amd64 ./cmd/nuclei-waf
echo "✓ Built: nuclei-waf-linux-amd64"

# macOS
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o nuclei-waf-darwin-amd64 ./cmd/nuclei-waf
echo "✓ Built: nuclei-waf-darwin-amd64"

echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o nuclei-waf-darwin-arm64 ./cmd/nuclei-waf
echo "✓ Built: nuclei-waf-darwin-arm64"

echo ""
echo "Build complete! Executables:"
ls -lh nuclei-waf* | awk '{print "  " $9 " (" $5 ")"}'
