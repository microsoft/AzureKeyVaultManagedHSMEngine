#!/bin/bash
# One-liner script to test nginx keyless TLS with Azure Managed HSM
# Usage: ./run-all.sh

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

# 1. Clean up
./cleanup.sh
rm -f nginx.conf openssl-provider.cnf

# 2. Create certificates
./generate-cert.sh

# 3. Start server
./start-server.sh

# 4. Run tests
./test-client.sh
