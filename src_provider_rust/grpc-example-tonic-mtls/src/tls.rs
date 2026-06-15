//! Shared TLS context construction for both server and client.
//!
//! Both endpoints in this demo load their private key from the same Azure
//! Managed HSM key (different cert identities, same RSA key). This module is
//! the single place that knows how to:
//!   * activate ALPN h2 (gRPC over HTTP/2 requires it)
//!   * pin TLS 1.2 minimum
//!   * load the leaf cert from disk and the matching private key from MHSM
//!   * require mutual peer verification against a CA bundle

use openssl::ssl::{
    SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod,
    SslVerifyMode, SslVersion,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use std::fs;
use std::path::Path;

use crate::hsm_key::load_pkey_from_store;

const ALPN_H2: &[u8] = b"\x02h2";

pub struct TlsPaths<'a> {
    pub cert_pem: &'a Path,
    pub ca_pem: &'a Path,
    pub hsm_key_uri: &'a str,
}

/// Build a server-side acceptor that:
///   * presents `cert_pem` as its leaf
///   * signs handshakes with the MHSM-resident key at `hsm_key_uri`
///   * requires a valid client cert chained to `ca_pem`
pub fn build_acceptor(paths: TlsPaths<'_>) -> Result<SslAcceptor, String> {
    let mut builder: SslAcceptorBuilder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(|e| format!("SslAcceptor::mozilla_intermediate_v5: {e}"))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| format!("set_min_proto_version: {e}"))?;

    // Leaf + optional chain. NGINX example reuses the CA for chaining so we do the same.
    builder
        .set_certificate_file(paths.cert_pem, SslFiletype::PEM)
        .map_err(|e| format!("set_certificate_file({}): {e}", paths.cert_pem.display()))?;

    // Private key comes from the HSM, not from disk.
    let pkey = load_pkey_from_store(paths.hsm_key_uri)?;
    builder
        .set_private_key(&pkey)
        .map_err(|e| format!("set_private_key (HSM uri={}): {e}", paths.hsm_key_uri))?;

    builder
        .check_private_key()
        .map_err(|e| format!("HSM key does not match leaf cert: {e}"))?;

    // mTLS: require + verify client cert against CA bundle.
    let ca_store = build_ca_store(paths.ca_pem)?;
    builder.set_verify_cert_store(ca_store)
        .map_err(|e| format!("set_verify_cert_store: {e}"))?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    // ALPN h2 — gRPC requires HTTP/2.
    builder.set_alpn_protos(ALPN_H2)
        .map_err(|e| format!("set_alpn_protos: {e}"))?;
    builder.set_alpn_select_callback(|_, client_protos| {
        openssl::ssl::select_next_proto(ALPN_H2, client_protos)
            .ok_or(openssl::ssl::AlpnError::ALERT_FATAL)
    });

    Ok(builder.build())
}

/// Build a client-side connector that:
///   * presents `cert_pem` as its client cert
///   * signs handshakes with the MHSM-resident key at `hsm_key_uri`
///   * verifies the server cert against `ca_pem`
pub fn build_connector(paths: TlsPaths<'_>) -> Result<SslConnector, String> {
    let mut builder: SslConnectorBuilder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| format!("SslConnector::builder: {e}"))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| format!("set_min_proto_version: {e}"))?;

    builder
        .set_certificate_file(paths.cert_pem, SslFiletype::PEM)
        .map_err(|e| format!("set_certificate_file({}): {e}", paths.cert_pem.display()))?;

    let pkey = load_pkey_from_store(paths.hsm_key_uri)?;
    builder
        .set_private_key(&pkey)
        .map_err(|e| format!("set_private_key (HSM uri={}): {e}", paths.hsm_key_uri))?;

    builder
        .check_private_key()
        .map_err(|e| format!("HSM key does not match client cert: {e}"))?;

    let ca_store = build_ca_store(paths.ca_pem)?;
    builder.set_verify_cert_store(ca_store)
        .map_err(|e| format!("set_verify_cert_store: {e}"))?;
    builder.set_verify(SslVerifyMode::PEER);

    builder.set_alpn_protos(ALPN_H2)
        .map_err(|e| format!("set_alpn_protos: {e}"))?;

    Ok(builder.build())
}

fn build_ca_store(ca_pem: &Path) -> Result<openssl::x509::store::X509Store, String> {
    let pem = fs::read(ca_pem)
        .map_err(|e| format!("read CA bundle {}: {e}", ca_pem.display()))?;
    let mut sb = X509StoreBuilder::new()
        .map_err(|e| format!("X509StoreBuilder::new: {e}"))?;
    for cert in X509::stack_from_pem(&pem)
        .map_err(|e| format!("parse CA bundle {}: {e}", ca_pem.display()))?
    {
        sb.add_cert(cert)
            .map_err(|e| format!("add CA to verify store: {e}"))?;
    }
    Ok(sb.build())
}
