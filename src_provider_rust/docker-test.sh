#!/bin/bash
# ============================================================================
# Docker Test Script for Azure Managed HSM OpenSSL Provider
# ============================================================================
# This script builds and tests the provider in a clean Ubuntu container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "========================================"
echo "Azure Managed HSM OpenSSL Provider"
echo "Docker Build and Test"
echo "========================================"
echo ""

# Parse arguments
SKIP_BUILD=0
INTERACTIVE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --interactive|-i)
            INTERACTIVE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build     Skip Docker image rebuild"
            echo "  --interactive    Start interactive shell instead of running tests"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker not found!"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "[INFO] Docker version: $(docker --version)"
echo ""

# Build Docker image
if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "[1/2] Building Docker image..."
    echo ""
    docker build -t akv-provider:latest .
    echo ""
    echo "[OK] Docker image built successfully"
else
    echo "[INFO] Skipping Docker build"
fi
echo ""

# Get Azure access token if not already set
if [[ -z "$AZURE_CLI_ACCESS_TOKEN" ]] && command -v az &> /dev/null; then
    echo "[INFO] Acquiring Azure CLI access token..."
    export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
        --resource https://managedhsm.azure.net \
        --query accessToken -o tsv)
    if [[ -n "$AZURE_CLI_ACCESS_TOKEN" ]]; then
        echo "[OK] Access token acquired"
    fi
fi
echo ""

# Run tests in container
if [[ $INTERACTIVE -eq 1 ]]; then
    echo "[2/2] Starting interactive shell in container..."
    echo ""
    docker run --rm -it \
        -e AZURE_CLI_ACCESS_TOKEN="${AZURE_CLI_ACCESS_TOKEN}" \
        -e AKV_VAULT="${AKV_VAULT:-ManagedHSMOpenSSLEngine}" \
        -e AKV_RSA_KEY="${AKV_RSA_KEY:-myrsakey}" \
        -e AKV_EC_KEY="${AKV_EC_KEY:-ecckey}" \
        -e AKV_AES_KEY="${AKV_AES_KEY:-myaeskey}" \
        -v "$SCRIPT_DIR/logs:/app/logs" \
        akv-provider:latest /bin/bash
else
    echo "[2/2] Running tests in container..."
    echo ""
    docker run --rm \
        -e AZURE_CLI_ACCESS_TOKEN="${AZURE_CLI_ACCESS_TOKEN}" \
        -e AKV_VAULT="${AKV_VAULT:-ManagedHSMOpenSSLEngine}" \
        -e AKV_RSA_KEY="${AKV_RSA_KEY:-myrsakey}" \
        -e AKV_EC_KEY="${AKV_EC_KEY:-ecckey}" \
        -e AKV_AES_KEY="${AKV_AES_KEY:-myaeskey}" \
        -v "$SCRIPT_DIR/logs:/app/logs" \
        akv-provider:latest ./runtest.sh
    
    echo ""
    echo "========================================"
    echo "Tests Completed!"
    echo "========================================"
    echo ""
    echo "Logs available at: ./logs/"
fi
