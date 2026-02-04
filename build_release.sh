#!/bin/bash
set -e

echo "[*] Cleaning old builds..."
cargo clean

CROSS_BIN="$HOME/.cargo/bin/cross"

# Explanation: 'musl' target creates a STATIC binary.
# It includes all dependencies inside the file.
# This means it runs on Debian, Arch, Ubuntu, Kali, and even Alpine without issues.
echo "[*] Building for Linux (Universal Static Binary)..."
$CROSS_BIN build --target x86_64-unknown-linux-musl --release

echo "[*] Building for Windows (x64)..."
export RUSTFLAGS="-L /project/libs"
$CROSS_BIN build --target x86_64-pc-windows-gnu --release
unset RUSTFLAGS

echo "[*] Creating 'dist' directory..."
mkdir -p dist
cp target/x86_64-unknown-linux-musl/release/arp-poison dist/arp-poison-linux-amd64
cp target/x86_64-pc-windows-gnu/release/arp-poison.exe dist/arp-poison-windows-amd64.exe

echo "[+] Build Complete! Binaries are in 'dist/'"
ls -lh dist/
