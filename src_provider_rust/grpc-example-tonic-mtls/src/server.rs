//! Tonic gRPC server with native mTLS, private key in Azure Managed HSM.
//!
//! Architecture (no sidecar):
//!     TCP accept  ->  openssl SslAcceptor (priv key in MHSM via akv provider)
//!                  ->  tokio_openssl SslStream  (AsyncRead+AsyncWrite)
//!                  ->  TlsIo newtype (impls tonic::Connected)
//!                  ->  tonic::transport::Server::serve_with_incoming
//!
//! Required env:
//!   OPENSSL_CONF        path to openssl-provider.cnf (akv_provider activated)
//!   HSM_KEY_URI         e.g. managedhsm:myhsm:myrsakey
//!   GRPC_BIND_ADDR      e.g. 0.0.0.0:50443
//!   SERVER_CERT_PEM     path to server leaf cert
//!   CA_CERT_PEM         path to CA bundle used to verify client certs

mod hsm_key;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use openssl::ssl::Ssl;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::{transport::Server, Request, Response, Status};

use greeter::greeter_server::{Greeter, GreeterServer};
use greeter::{HelloReply, HelloRequest};

pub mod greeter {
    tonic::include_proto!("greeter");
}

// ----- Service impl -----------------------------------------------------

#[derive(Debug, Default)]
pub struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let peer = request
            .extensions()
            .get::<TlsConnectInfo>()
            .map(|i| i.peer_addr.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        println!("unary request from {peer}: {:?}", request.get_ref());

        Ok(Response::new(HelloReply {
            message: format!("Hello {} (mTLS via HSM)!", request.into_inner().name),
        }))
    }

    type SayHelloStreamStream = ReceiverStream<Result<HelloReply, Status>>;

    async fn say_hello_stream(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<Self::SayHelloStreamStream>, Status> {
        let name = request.into_inner().name;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            for i in 1..=5 {
                let reply = HelloReply {
                    message: format!("Hello {name} - mTLS message {i}!"),
                };
                if tx.send(Ok(reply)).await.is_err() {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// ----- TlsIo: SslStream<TcpStream> wrapper that tonic accepts ---------
//
// tonic 0.12's serve_with_incoming requires items implementing
// `tonic::transport::server::Connected`. openssl's SslStream doesn't
// (orphan rule prevents us from impl'ing it elsewhere), so we wrap and
// delegate AsyncRead+AsyncWrite, plus expose the underlying TcpStream's
// peer address as ConnectInfo for logging.

pub struct TlsIo {
    inner: SslStream<TcpStream>,
}

impl TlsIo {
    fn new(inner: SslStream<TcpStream>) -> Self {
        Self { inner }
    }
}

#[derive(Clone)]
pub struct TlsConnectInfo {
    pub peer_addr: SocketAddr,
}

impl Connected for TlsIo {
    type ConnectInfo = TlsConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        let peer_addr = self
            .inner
            .get_ref()
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        TlsConnectInfo { peer_addr }
    }
}

impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ----- main -------------------------------------------------------------

fn require_env(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(key).map_err(|_| format!("required env {key} is not set").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hard-fail on missing config rather than silently fall back to defaults
    // that would mask the HSM integration.
    let openssl_conf = require_env("OPENSSL_CONF")?;
    if !std::path::Path::new(&openssl_conf).exists() {
        return Err(format!("OPENSSL_CONF={openssl_conf} does not exist").into());
    }
    let bind_addr = std::env::var("GRPC_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:50443".into());
    let cert_path = PathBuf::from(require_env("SERVER_CERT_PEM")?);
    let ca_path = PathBuf::from(require_env("CA_CERT_PEM")?);
    let hsm_uri = require_env("HSM_KEY_URI")?;

    println!("== tonic-mtls-server ==");
    println!("  bind:         {bind_addr}");
    println!("  server cert:  {}", cert_path.display());
    println!("  CA bundle:    {}", ca_path.display());
    println!("  HSM key URI:  {hsm_uri}");
    println!("  OPENSSL_CONF: {openssl_conf}");

    let acceptor = tls::build_acceptor(tls::TlsPaths {
        cert_pem: &cert_path,
        ca_pem: &ca_path,
        hsm_key_uri: &hsm_uri,
    })
    .map_err(|e| format!("build_acceptor: {e}"))?;
    let acceptor = Arc::new(acceptor);
    println!("  TLS context built (private key loaded from HSM).");

    let listener = TcpListener::bind(&bind_addr).await?;
    println!("listening on {bind_addr}");

    // Forward successfully-handshaken streams into a bounded channel that
    // serve_with_incoming consumes. Per-connection handshake failures are
    // logged and dropped without affecting other clients.
    let (conn_tx, conn_rx) =
        tokio::sync::mpsc::channel::<Result<TlsIo, std::io::Error>>(32);

    let accept_acceptor = Arc::clone(&acceptor);
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("tcp accept failed: {e}");
                    continue;
                }
            };
            let acceptor = Arc::clone(&accept_acceptor);
            let tx = conn_tx.clone();
            tokio::spawn(async move {
                let ssl = match Ssl::new(acceptor.context()) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[{peer}] Ssl::new failed: {e}");
                        return;
                    }
                };
                let mut tls = match SslStream::new(ssl, tcp) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[{peer}] SslStream::new failed: {e}");
                        return;
                    }
                };
                if let Err(e) = Pin::new(&mut tls).accept().await {
                    eprintln!("[{peer}] TLS handshake failed: {e}");
                    return;
                }
                if tx.send(Ok(TlsIo::new(tls))).await.is_err() {
                    eprintln!("[{peer}] server shutting down, dropping connection");
                }
            });
        }
    });

    Server::builder()
        .add_service(GreeterServer::new(MyGreeter::default()))
        .serve_with_incoming(ReceiverStream::new(conn_rx))
        .await?;

    Ok(())
}
