#!/bin/bash
# ========================================
# Ubuntu/Linux Build Script for Rust Provider
# ========================================
# This script checks dependencies, builds, and deploys the provider

set -e

echo ""
echo "========================================"
echo "Azure Managed HSM OpenSSL Provider"
echo "Rust Implementation - Linux Build Script"
echo "========================================"
echo ""

# Default settings
BUILD_TYPE="release"
SKIP_DEPS_CHECK=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --skip-deps)
            SKIP_DEPS_CHECK=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug      Build in debug mode instead of release"
            echo "  --skip-deps  Skip dependency checks (faster for rebuilds)"
            echo "  -h, --help   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ========================================
# 1. Check Rust toolchain
# ========================================
echo "[1/4] Checking Rust toolchain..."

if ! command -v cargo &> /dev/null; then
    echo "[ERROR] Rust toolchain not found!"
    echo "Please install Rust from: https://rustup.rs/"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

CARGO_VERSION=$(cargo --version | cut -d' ' -f2)
echo "[OK] Cargo $CARGO_VERSION found"

# ========================================
# 2. Check OpenSSL
# ========================================
if [[ $SKIP_DEPS_CHECK -eq 0 ]]; then
    echo "[2/4] Checking OpenSSL dependencies..."

    if ! command -v openssl &> /dev/null; then
        echo "[ERROR] OpenSSL not found!"
        echo "Please install OpenSSL:"
        echo "  sudo apt-get install openssl libssl-dev"
        exit 1
    fi

    OPENSSL_VERSION=$(openssl version)
    echo "[OK] $OPENSSL_VERSION"

    # Check for OpenSSL development headers
    if ! pkg-config --exists openssl 2>/dev/null; then
        echo "[WARNING] OpenSSL development headers may not be installed"
        echo "If build fails, try: sudo apt-get install libssl-dev"
    else
        OPENSSL_PKG_VERSION=$(pkg-config --modversion openssl)
        echo "[OK] OpenSSL dev headers $OPENSSL_PKG_VERSION"
    fi

    # Check OpenSSL version is 3.x
    if [[ ! "$OPENSSL_VERSION" =~ ^OpenSSL\ 3\. ]]; then
        echo "[WARNING] OpenSSL 3.x recommended for provider support"
        echo "Current version: $OPENSSL_VERSION"
    fi
else
    echo "[2/4] Skipping dependency checks..."
fi

# ========================================
# 3. Build
# ========================================
echo "[3/4] Building provider..."
echo ""

if [[ "$BUILD_TYPE" == "debug" ]]; then
    echo "Building in DEBUG mode..."
    cargo build
else
    echo "Building in RELEASE mode..."
    cargo build --release
fi

echo ""
echo "========================================"
echo "Build Successful!"
echo "========================================"
echo ""

if [[ "$BUILD_TYPE" == "debug" ]]; then
    SO_PATH="$SCRIPT_DIR/target/debug/lib/akv_provider.so"
    TARGET_DIR="$SCRIPT_DIR/target/debug"
else
    SO_PATH="$SCRIPT_DIR/target/release/lib/akv_provider.so"
    TARGET_DIR="$SCRIPT_DIR/target/release"
fi

# Create symlink with OpenSSL-expected name (without lib prefix)
if [[ -f "$SO_PATH" ]]; then
    ln -sf libakv_provider.so "$TARGET_DIR/akv_provider.so"
    echo "[OK] Created symlink: $TARGET_DIR/akv_provider.so -> libakv_provider.so"
fi

echo "Provider library: $SO_PATH"
echo ""

if [[ -f "$SO_PATH" ]]; then
    SIZE=$(stat --printf="%s" "$SO_PATH" 2>/dev/null || stat -f%z "$SO_PATH" 2>/dev/null)
    echo "Size: $SIZE bytes"
    echo ""
fi

# ========================================
# 4. Deploy provider to OpenSSL modules dir
# ========================================
echo "[4/4] Deploying provider..."
echo ""

# Get OpenSSL modules directory
MODULES_DIR=$(openssl version -m | grep -oP 'MODULESDIR: "\K[^"]+' 2>/dev/null || \
              openssl version -m | sed 's/MODULESDIR: "\(.*\)"/\1/')

if [[ -z "$MODULES_DIR" ]]; then
    echo "[WARNING] Could not detect OpenSSL modules directory"
    echo "Provider built at: $SO_PATH"
    echo ""
    echo "To deploy manually, copy to your OpenSSL modules directory:"
    echo "  sudo cp \"$SO_PATH\" /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so"
    exit 0
fi

echo "[INFO] OpenSSL modules directory: $MODULES_DIR"

if [[ ! -d "$MODULES_DIR" ]]; then
    echo "[WARNING] Modules directory does not exist: $MODULES_DIR"
    echo "Creating it..."
    sudo mkdir -p "$MODULES_DIR"
fi

echo "[INFO] Copying $SO_PATH"
echo "       to $MODULES_DIR/akv_provider.so"

if sudo cp "$SO_PATH" "$MODULES_DIR/akv_provider.so"; then
    echo "[OK] Provider deployed successfully!"
else
    echo "[ERROR] Failed to copy provider"
    echo "Try running with sudo or copy manually:"
    echo "  sudo cp \"$SO_PATH\" \"$MODULES_DIR/akv_provider.so\""
    exit 1
fi

echo ""
echo "========================================"
echo "Ready to Test!"
echo "========================================"
echo ""
echo "Run tests with:"
echo "  ./runtest.sh"
echo ""
echo "Or verify the provider is visible to OpenSSL:"
echo "  openssl list -providers -provider akv_provider -provider-path \"$MODULES_DIR\""
echo ""
