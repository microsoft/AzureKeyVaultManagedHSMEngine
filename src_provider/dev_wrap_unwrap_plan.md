1. Add AkvWrap and AkvUnwrap functions to curl.c that call the Azure Managed HSM wrap/unwrap APIs
2. Create an AES cipher implementation (similar to akv_cipher.c for RSA)
3. Add AES key management support to akv_keymgmt.c
Register the AES cipher in the provider's algorithm table
4. Update the test to use the appropriate OpenSSL command (likely still pkeyutl -encrypt/-decrypt with AES keys)


To implement **wrap** and **unwrap** support in a custom OpenSSL provider (for example, to use Azure Managed HSM for key wrapping/unwrapping), you must implement the **Key Management** (KEYMGMT) and possibly **Cipher** operations, supporting the relevant PARAMS and dispatch functions.

Below is a practical, OpenSSL 3.x/4.x-aligned summary:

---

## 1. **Understand the OpenSSL Provider API for Wrap/Unwrap**

- **Wrap**: Export a key, often encrypted ("wrapped") with another key or mechanism.
- **Unwrap**: Import a key, decrypting ("unwrapping") it from its wrapped form.
- The OpenSSL **provider interface** has `export`, `import`, `export_types`, and `import_types` in the key management (KEYMGMT) operation set.
- Wrap/unwrap in OpenSSL is often performed via `EVP_PKEY_wrap()`/`EVP_PKEY_unwrap()` or by using `EVP_PKEY_export()`/`EVP_PKEY_import()` with the right parameters.

---

## 2. **Implement Key Management Dispatch Table (KEYMGMT)**

You need to implement these functions (see [provider-keymgmt(7)](https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html)):

- `OP_keymgmt_export`
- `OP_keymgmt_import`
- `OP_keymgmt_export_types`
- `OP_keymgmt_import_types`

You must advertise these with the provider dispatch table for your algorithm.

---

## 3. **Support Export/Import Formats**

OpenSSL passes a format string, such as `"DER"`, `"PEM"`, `"RAW"`, or a custom format (e.g., `"AZURE_WRAPPED"`).

- For **wrap**: Accept a request to export the key in a wrapped (encrypted) format, possibly using a wrapping key identifier.
- For **unwrap**: Accept a wrapped key blob, and import it into the HSM or return a provider-side key reference.

---

## 4. **Implement PARAMS for Wrapping**

- `OSSL_KEYMGMT_PARAM_WRAPPED_KEY` (or similar, see [core_names.h](https://github.com/openssl/openssl/blob/master/include/openssl/core_names.h))
- `OSSL_KEYMGMT_PARAM_CEK_ALG` (Content Encryption Key algorithm, if relevant)
- `OSSL_KEYMGMT_PARAM_WRAP_TYPE` (Type of wrap/unwrap)
- `OSSL_KEYMGMT_PARAM_WRAP_KEY` (wrapping key identifier)
- `OSSL_KEYMGMT_PARAM_IV` (IV for wrapping, if needed)

You may also need custom parameters for Azure HSM, such as a key URI or access token.

---

## 5. **Dispatch Function Example**

```c
static int my_keymgmt_export(void *provctx, void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    // ... validate selection, e.g., OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    // ... perform wrap using Azure HSM SDK, get wrapped blob

    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KEYMGMT_PARAM_WRAPPED_KEY, wrapped_blob, wrapped_blob_len),
        OSSL_PARAM_END
    };
    return param_cb(params, cbarg);
}
```

For import (unwrap), you would receive a wrapped blob via an OSSL_PARAM and send it to Azure HSM to create a key.

---

## 6. **Advertise Supported Export/Import Types**

```c
static const OSSL_PARAM my_export_types[] = {
    OSSL_PARAM_DEFN(OSSL_KEYMGMT_PARAM_WRAPPED_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0),
    OSSL_PARAM_END
};
```

---

## 7. **Provider Algorithm Definition**

You must include `"wrap"` and `"unwrap"` in your algorithm property string:

```c
static const OSSL_ALGORITHM my_keymgmt[] = {
    { "RSA:remote_rsa", "provider=azurehsm,wrap,unwrap", keymgmt_dispatch_table },
    { NULL, NULL, NULL }
};
```

---

## 8. **OpenSSL CLI Usage**

To use wrap/unwrap via OpenSSL commands, you should ensure your provider is loaded and the algorithm advertised for wrap/unwrap.  
For example:

```sh
openssl pkey -provider azurehsm -algorithm RSA -wrap ...
openssl pkey -provider azurehsm -algorithm RSA -unwrap ...
```

---

## 9. **Reference: OpenSSL Source**

- [provider-keymgmt.pod](https://github.com/openssl/openssl/blob/master/doc/man7/provider-keymgmt.pod)
- [core_names.h](https://github.com/openssl/openssl/blob/master/include/openssl/core_names.h)
- [OpenSSL built-in providers for wrap/unwrap example](https://github.com/openssl/openssl/blob/master/providers/implementations/keymgmt/rsa_kmgmt.c)

---

## 10. **Summary Table**

| Step              | Function/Parameter                | Purpose                                  |
|-------------------|-----------------------------------|------------------------------------------|
| Export (wrap)     | OP_keymgmt_export, export_types   | Output wrapped key blob                  |
| Import (unwrap)   | OP_keymgmt_import, import_types   | Input wrapped key blob                   |
| Parameters        | OSSL_KEYMGMT_PARAM_WRAPPED_KEY, OSSL_KEYMGMT_PARAM_WRAP_KEY, etc | Wrap/unwrap control, key references      |

---

