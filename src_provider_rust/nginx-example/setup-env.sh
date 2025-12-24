#!/bin/bash
# Setup environment configuration for nginx HSM example
# Creates .env from .env.example if it doesn't exist

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

if [ -f "$ENV_FILE" ]; then
    echo "Configuration file already exists: $ENV_FILE"
    echo ""
    echo "Current settings:"
    grep -E "^[A-Z]" "$ENV_FILE" | head -10
    echo ""
    read -p "Do you want to overwrite it? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing configuration."
        exit 0
    fi
fi

if [ ! -f "$ENV_EXAMPLE" ]; then
    echo "Error: Template file not found: $ENV_EXAMPLE"
    exit 1
fi

cp "$ENV_EXAMPLE" "$ENV_FILE"
echo "Created configuration file: $ENV_FILE"
echo ""
echo "Please edit the following settings in $ENV_FILE:"
echo ""
echo "  HSM_NAME         - Your Azure Managed HSM name"
echo "  HSM_KEY_NAME     - Key name in the HSM"
echo "  AZURE_TENANT_ID  - Your Azure tenant ID"
echo ""
echo "Then run:"
echo "  ./generate-cert.sh   # Generate certificate"
echo "  ./start-server.sh    # Start nginx"
