use greeter::greeter_client::GreeterClient;
use greeter::HelloRequest;
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod greeter {
    tonic::include_proto!("greeter");
}

async fn connect_uds(socket_path: &str) -> Result<Channel, Box<dyn std::error::Error>> {
    // For UDS, we need a dummy URI but the actual connection goes through the socket
    let socket_path = socket_path.to_string();
    
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    
    Ok(channel)
}

async fn connect_tcp(addr: &str) -> Result<Channel, Box<dyn std::error::Error>> {
    let channel = Channel::from_shared(addr.to_string())?
        .connect()
        .await?;
    Ok(channel)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if UDS mode is requested via environment variable
    let uds_path = std::env::var("GRPC_UDS_PATH").ok();
    let tcp_addr = std::env::var("GRPC_ADDR").ok();

    let channel = if let Some(socket_path) = uds_path {
        // Unix Domain Socket mode (for sidecar architecture)
        println!("Connecting via Unix socket: {}", socket_path);
        connect_uds(&socket_path).await?
    } else {
        // TCP mode (for direct access or testing)
        let addr = tcp_addr.unwrap_or_else(|| "http://[::1]:50051".to_string());
        println!("Connecting via TCP: {}", addr);
        connect_tcp(&addr).await?
    };

    let mut client = GreeterClient::new(channel);

    // Simple unary request
    println!("\n=== Unary Request ===");
    let request = tonic::Request::new(HelloRequest {
        name: "World".into(),
    });

    let response = client.say_hello(request).await?;
    println!("RESPONSE: {:?}", response.into_inner().message);

    // Streaming request
    println!("\n=== Streaming Request ===");
    let request = tonic::Request::new(HelloRequest {
        name: "Streamer".into(),
    });

    let mut stream = client.say_hello_stream(request).await?.into_inner();

    while let Some(response) = stream.message().await? {
        println!("STREAM RESPONSE: {:?}", response.message);
    }

    println!("\nDone!");
    Ok(())
}
