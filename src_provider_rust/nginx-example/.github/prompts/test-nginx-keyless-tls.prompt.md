# Test nginx Keyless TLS with Azure Managed HSM

Guide me through testing the nginx keyless TLS example that uses Azure Managed HSM for private key operations.

## Prerequisites

Before starting, ensure:
1. The AKV provider is built (`cargo build --release` in the parent directory)
2. Azure CLI is installed and logged in
3. You have access to an Azure Managed HSM with an RSA key named `myrsakey`
4. nginx 1.27+ is installed (check with `nginx -v`)

## Test Steps

### Step 1: Install nginx 1.27+ (if needed)

If nginx version is below 1.27, install from the official mainline repository:

```bash
sudo apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | \
    sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | \
    sudo tee /etc/apt/sources.list.d/nginx.list
sudo apt update && sudo apt install -y nginx
```

### Step 2: Generate Certificate

Run the certificate generation script which creates a certificate signed by the HSM key:

```bash
./generate-cert.sh
```

This will:
- Create a CSR using the HSM private key
- Self-sign the certificate using the HSM
- Store the certificate in `certs/server.crt`

### Step 3: Start nginx

Start nginx with the HSM-backed TLS configuration:

```bash
./start-server.sh
```

This will:
- Get an Azure access token
- Set up the OpenSSL provider configuration
- Start nginx listening on port 8443

### Step 4: Test the Connection

Run the test client to verify TLS is working:

```bash
./test-client.sh
```

Or manually test with curl:

```bash
curl -k https://localhost:8443/
curl -k https://localhost:8443/health
```

Expected output:
```
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: ...
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
```

### Step 5: Verify HSM Operations

Check the provider logs to confirm signing operations are happening via the HSM:

```bash
cat logs/akv_provider.log | grep -E "signature|Sign"
```

You should see entries like:
```
akv_signature_digest_sign -> 1 (signature 384 bytes)
```

### Step 6: Stop nginx

When finished testing:

```bash
./stop-server.sh
```

## Troubleshooting

If you encounter issues:

1. **Certificate decode error**: Check that `openssl-provider.cnf` lists `default` provider before `akv_provider`
2. **Token errors**: Ensure `AZURE_CLI_ACCESS_TOKEN` is set (run `az login` first)
3. **nginx won't start**: Check `logs/error.log` for details
4. **TLS handshake fails**: Check `logs/akv_provider.log` for HSM operation errors

## Key Files

- `nginx.conf` - nginx configuration with `store:managedhsm:...` key URI
- `openssl-provider.cnf` - OpenSSL provider configuration (order matters!)
- `certs/server.crt` - Generated certificate
- `logs/` - nginx and provider logs
