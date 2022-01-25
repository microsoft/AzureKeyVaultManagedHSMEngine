set GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=root.pem  
greeter_client.exe -address %ComputerName%:50051 -name %ComputerName% -roots root.pem -cert chain.pem -keyFile leaf.keyid