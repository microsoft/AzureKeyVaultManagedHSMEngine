# nginx Keyless TLS Test Results

**Date:** Tue Dec 23 23:52:53 UTC 2025

## Step 1: Check nginx Version

```
nginx version: nginx/1.29.4
```

## Step 2: Generate Certificate

```
=== Generating certificate using Azure Managed HSM ===
Creating CSR with HSM key...
Signing certificate with HSM key...
Certificate request self-signature ok
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost

=== Certificate generated successfully ===
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
issuer=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
notBefore=Dec 23 23:52:56 2025 GMT
notAfter=Dec 23 23:52:56 2026 GMT

Certificate: /home/puliu/AzureKeyVaultManagedHSMEngine/src_provider_rust/nginx-example/certs/server.crt
CSR:         /home/puliu/AzureKeyVaultManagedHSMEngine/src_provider_rust/nginx-example/certs/server.csr
```

## Step 3: Start nginx

```
=== Starting nginx with Azure Managed HSM keyless TLS ===
Starting nginx...
nginx started successfully (PID: 123019)

Test with: curl -k https://localhost:8443/
Logs:      /home/puliu/AzureKeyVaultManagedHSMEngine/src_provider_rust/nginx-example/logs/
```

## Step 4: Test the Connection

### HTTPS Request

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0100   151  100   151    0     0    395      0 --:--:-- --:--:-- --:--:--   396
Hello from Nginx with Azure Managed HSM keyless TLS!

Server Time: 23/Dec/2025:23:52:58 +0000
SSL Protocol: TLSv1.3
SSL Cipher: TLS_AES_256_GCM_SHA384
```

### Health Check

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0100    63  100    63    0     0    170      0 --:--:-- --:--:-- --:--:--   171
{"status": "healthy", "ssl": true, "hsm": "Azure Managed HSM"}
```

### TLS Connection Info

```
subject=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
issuer=C = US, ST = Washington, L = Redmond, O = Microsoft, OU = Azure HSM Demo, CN = localhost
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
```

## Step 5: Verify HSM Operations

```
[2025-12-23T23:52:58.865Z INFO akv_provider::signature:1273] akv_signature_digest_sign -> 1 (signature 384 bytes)
[2025-12-23T23:52:59.250Z INFO akv_provider::signature:1273] akv_signature_digest_sign -> 1 (signature 384 bytes)
[2025-12-23T23:52:59.685Z INFO akv_provider::signature:1273] akv_signature_digest_sign -> 1 (signature 384 bytes)
```

## Step 6: Stop nginx

```
Stopping nginx (PID: 123019)...
nginx stopped
```

## Summary

| Step | Result |
|------|--------|
| nginx version | ✅ 1.27+ installed |
| Certificate generation | ✅ Signed by HSM |
| nginx startup | ✅ Running |
| TLS connection | ✅ TLSv1.3 |
| HSM signing | ✅ Verified in logs |
| Cleanup | ✅ Stopped |

**Private key never left the HSM** - all TLS signing operations were performed by Azure Managed HSM!
