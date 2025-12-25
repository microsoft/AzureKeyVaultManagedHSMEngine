use std::path::Path;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};

use greeter::greeter_server::{Greeter, GreeterServer};
use greeter::{HelloReply, HelloRequest};

pub mod greeter {
    tonic::include_proto!("greeter");
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(Response::new(reply))
    }

    type SayHelloStreamStream = tokio_stream::wrappers::ReceiverStream<Result<HelloReply, Status>>;

    async fn say_hello_stream(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<Self::SayHelloStreamStream>, Status> {
        println!("Got a streaming request: {:?}", request);

        let name = request.into_inner().name;
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        tokio::spawn(async move {
            for i in 1..=5 {
                let reply = HelloReply {
                    message: format!("Hello {} - message {}!", name, i),
                };
                if tx.send(Ok(reply)).await.is_err() {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let greeter = MyGreeter::default();

    // Check if UDS mode is requested via environment variable
    let uds_path = std::env::var("GRPC_UDS_PATH").ok();

    if let Some(socket_path) = uds_path {
        // Unix Domain Socket mode (for sidecar architecture)
        let path = Path::new(&socket_path);
        
        // Remove existing socket file if it exists
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let uds = UnixListener::bind(path)?;
        let incoming = UnixListenerStream::new(uds);

        println!("GreeterServer listening on Unix socket: {}", socket_path);

        Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve_with_incoming(incoming)
            .await?;
    } else {
        // TCP mode (for direct access or testing)
        let addr = std::env::var("GRPC_ADDR")
            .unwrap_or_else(|_| "[::1]:50051".to_string())
            .parse()?;

        println!("GreeterServer listening on {}", addr);

        Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve(addr)
            .await?;
    }

    Ok(())
}
