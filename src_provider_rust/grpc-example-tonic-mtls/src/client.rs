//! Tonic gRPC client with native mTLS, private key in Azure Managed HSM.
//!
//! Strategy: build an openssl SslConnector that loads the client cert from
//! disk and the private key from MHSM via OSSL_STORE, then plug it into
//! tonic via `Channel::connect_with_connector(tower::service_fn(...))`.
//!
//! Required env:
//!   OPENSSL_CONF        path to openssl-provider.cnf (akv_provider activated)
//!   HSM_KEY_URI         e.g. managedhsm:myhsm:myrsakey
//!   GRPC_SERVER_ADDR    e.g. https://localhost:50443
//!   GRPC_SERVER_NAME    SNI hostname; must match server cert CN/SAN
//!   CLIENT_CERT_PEM     path to client leaf cert
//!   CA_CERT_PEM         path to CA bundle used to verify server cert

mod hsm_key;
mod tls;

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use http::Uri;
use openssl::ssl::{Ssl, SslConnector};
use tokio_openssl::SslStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use greeter::greeter_client::GreeterClient;
use greeter::HelloRequest;

pub mod greeter {
    tonic::include_proto!("greeter");
}

fn require_env(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(key).map_err(|_| format!("required env {key} is not set").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let openssl_conf = require_env("OPENSSL_CONF")?;
    if !std::path::Path::new(&openssl_conf).exists() {
        return Err(format!("OPENSSL_CONF={openssl_conf} does not exist").into());
    }
    let server_addr = std::env::var("GRPC_SERVER_ADDR")
        .unwrap_or_else(|_| "https://localhost:50443".into());
    let server_name = std::env::var("GRPC_SERVER_NAME").unwrap_or_else(|_| "localhost".into());
    let cert_path = PathBuf::from(require_env("CLIENT_CERT_PEM")?);
    let ca_path = PathBuf::from(require_env("CA_CERT_PEM")?);
    let hsm_uri = require_env("HSM_KEY_URI")?;

    println!("== tonic-mtls-client ==");
    println!("  server addr:  {server_addr}");
    println!("  SNI name:     {server_name}");
    println!("  client cert:  {}", cert_path.display());
    println!("  CA bundle:    {}", ca_path.display());
    println!("  HSM key URI:  {hsm_uri}");

    let connector: SslConnector = tls::build_connector(tls::TlsPaths {
        cert_pem: &cert_path,
        ca_pem: &ca_path,
        hsm_key_uri: &hsm_uri,
    })
    .map_err(|e| format!("build_connector: {e}"))?;
    let connector = Arc::new(connector);
    println!("  TLS context built (client private key loaded from HSM).");

    // Endpoint URI is only used by tonic for HTTP layer plumbing; the actual
    // TCP target comes from the URI authority below.
    let endpoint = Endpoint::from_shared(server_addr.clone())?
        .http2_keep_alive_interval(std::time::Duration::from_secs(30));

    let sni = server_name.clone();
    let channel: Channel = endpoint
        .connect_with_connector(service_fn(move |uri: Uri| {
            let connector = Arc::clone(&connector);
            let sni = sni.clone();
            async move {
                let host = uri.host().ok_or_else(|| io_other("uri missing host"))?;
                let port = uri.port_u16().unwrap_or(443);
                let tcp = tokio::net::TcpStream::connect((host, port)).await?;

                // SNI = server_name from env (may differ from connect host).
                let ssl_config = connector
                    .configure()
                    .map_err(|e| io_other(format!("SslConnector::configure: {e}")))?;
                let ssl: Ssl = ssl_config
                    .into_ssl(&sni)
                    .map_err(|e| io_other(format!("Ssl::from(config, sni={sni}): {e}")))?;

                let mut stream = SslStream::new(ssl, tcp)
                    .map_err(|e| io_other(format!("SslStream::new: {e}")))?;
                Pin::new(&mut stream)
                    .connect()
                    .await
                    .map_err(|e| io_other(format!("TLS handshake: {e}")))?;

                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;

    let mut client = GreeterClient::new(channel);

    println!("\n=== Unary call ===");
    let req = tonic::Request::new(HelloRequest { name: "World".into() });
    let resp = client.say_hello(req).await?;
    println!("response: {}", resp.into_inner().message);

    println!("\n=== Server-streaming call ===");
    let req = tonic::Request::new(HelloRequest { name: "Streamer".into() });
    let mut stream = client.say_hello_stream(req).await?.into_inner();
    while let Some(msg) = stream.message().await? {
        println!("  stream: {}", msg.message);
    }

    println!("\nDone.");
    Ok(())
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
