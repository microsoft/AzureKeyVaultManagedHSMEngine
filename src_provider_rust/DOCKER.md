# Docker Testing for Azure Managed HSM OpenSSL Provider

This directory contains Docker configuration for building and testing the provider in a clean Ubuntu 22.04 environment.

## Quick Start

### Prerequisites

- Docker installed and running
- Azure CLI installed on host (for authentication)
- Access to Azure Managed HSM with RSA, EC, and AES keys

### Option 1: Run Tests (Automated)

```bash
# From src_provider_rust/ directory
./docker-test.sh
```

This will:
1. Build the Docker image with the provider
2. Acquire Azure access token
3. Run the test suite in the container
4. Display results

### Option 2: Interactive Shell

```bash
./docker-test.sh --interactive
```

This starts a bash shell inside the container where you can manually run commands:

```bash
# Inside container:
openssl list -providers -provider libakv_provider -provider default
./runtest.sh
./runtest.sh --validate
```

### Option 3: Docker Compose

```bash
docker-compose up --build
```

## Configuration

### Environment Variables

Set these before running docker-test.sh:

```bash
export AKV_VAULT=ManagedHSMOpenSSLEngine
export AKV_RSA_KEY=myrsakey
export AKV_EC_KEY=ecckey
export AKV_AES_KEY=myaeskey
```

### Authentication

The container supports multiple authentication methods:

1. **Azure CLI Token** (Recommended for testing):
   ```bash
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://managedhsm.azure.net --query accessToken -o tsv)
   ```

2. **Azure CLI Config** (mounted from host):
   - The container mounts `~/.azure` from the host
   - Run `az login` on host before starting container

3. **Service Principal**:
   ```bash
   export AZURE_TENANT_ID=your-tenant-id
   export AZURE_CLIENT_ID=your-client-id
   export AZURE_CLIENT_SECRET=your-client-secret
   ```

## Docker Image Details

### Multi-Stage Build

- **Stage 1 (builder)**: 
  - Ubuntu 22.04
  - Installs Rust toolchain and OpenSSL dev headers
  - Builds `libakv_provider.so` in release mode

- **Stage 2 (runtime)**:
  - Ubuntu 22.04
  - Only runtime dependencies (OpenSSL, Azure CLI)
  - Copies compiled provider to `/usr/lib/x86_64-linux-gnu/ossl-modules/`

### Provider Location

- Build output: `/build/target/release/libakv_provider.so`
- Installed location: `/usr/lib/x86_64-linux-gnu/ossl-modules/libakv_provider.so`
- Config file: `/app/testOpenssl.cnf`

## Testing Commands

### Verify Provider Installation

```bash
docker run --rm akv-provider:latest \
    openssl list -providers -provider libakv_provider -provider default
```

Expected output:
```
Providers:
  default
    name: OpenSSL Default Provider
    ...
  libakv_provider
    name: Azure Managed HSM Provider
    ...
```

### Run Specific Tests

```bash
# Run with validation
docker run --rm \
    -e AZURE_CLI_ACCESS_TOKEN="$AZURE_CLI_ACCESS_TOKEN" \
    akv-provider:latest ./runtest.sh --validate

# Use DefaultAzureCredential
docker run --rm \
    -v ~/.azure:/root/.azure:ro \
    akv-provider:latest ./runtest.sh --noenv
```

## Troubleshooting

### Provider Not Loading

If you see "Provider not loadable" error:

1. Check the provider file exists:
   ```bash
   docker run --rm akv-provider:latest \
       ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/libakv_provider.so
   ```

2. Check OpenSSL can find it:
   ```bash
   docker run --rm akv-provider:latest \
       openssl version -m
   ```

### Authentication Errors

If tests fail with "401 Unauthorized":

1. Verify token is valid:
   ```bash
   echo $AZURE_CLI_ACCESS_TOKEN | cut -c1-50
   ```

2. Re-acquire token:
   ```bash
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://managedhsm.azure.net --query accessToken -o tsv)
   ```

### Build Failures

If Docker build fails:

1. Clean up and rebuild:
   ```bash
   docker build --no-cache -t akv-provider:latest .
   ```

2. Check Rust installation:
   ```bash
   docker run --rm -it akv-provider:latest cargo --version
   ```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Docker Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: |
          cd src_provider_rust
          docker build -t akv-provider:latest .
      
      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Run Tests
        run: |
          cd src_provider_rust
          ./docker-test.sh
```

## Performance Notes

- **Build time**: ~5-10 minutes (first build with Rust installation)
- **Rebuild time**: ~1-2 minutes (with Docker cache)
- **Image size**: ~500MB (runtime stage only)
- **Test runtime**: ~30 seconds (without validation), ~2 minutes (with validation)

## Advanced Usage

### Custom OpenSSL Configuration

Mount your own config file:

```bash
docker run --rm \
    -v $(pwd)/custom.cnf:/app/testOpenssl.cnf \
    -e AZURE_CLI_ACCESS_TOKEN="$AZURE_CLI_ACCESS_TOKEN" \
    akv-provider:latest ./runtest.sh
```

### Debug Build

Modify Dockerfile to use debug build:

```dockerfile
# Change in builder stage:
RUN cargo build  # instead of cargo build --release
```

### Mount Source for Development

```bash
docker run --rm -it \
    -v $(pwd):/src \
    -w /src \
    akv-provider:latest bash
```

## Files

| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build configuration |
| `docker-compose.yml` | Docker Compose configuration |
| `.dockerignore` | Files excluded from Docker context |
| `docker-test.sh` | Automated test script |
| `DOCKER.md` | This documentation |
