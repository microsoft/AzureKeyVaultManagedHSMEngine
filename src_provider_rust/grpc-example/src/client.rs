use greeter::greeter_client::GreeterClient;
use greeter::HelloRequest;

pub mod greeter {
    tonic::include_proto!("greeter");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = GreeterClient::connect("http://[::1]:50051").await?;

    // Simple unary request
    println!("=== Unary Request ===");
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
