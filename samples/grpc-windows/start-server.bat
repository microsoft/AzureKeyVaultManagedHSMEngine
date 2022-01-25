set GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=root.pem  
greeter_server.exe -address 0.0.0.0:50051 -roots root.pem -cert chain.pem -keyFile leaf.keyid -verifyClient