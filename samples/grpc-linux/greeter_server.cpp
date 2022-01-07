// --------------------------------------------------------------------------------------------------------------------
// <copyright file="greeter_server.cpp" company="Microsoft">
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#pragma warning(push)
#pragma warning(disable : 4100 4127 4244 4702)
#include <grpcpp/grpcpp.h>
#include <grpc/grpc_security.h>
#include <grpcpp/security/server_credentials.h>
#pragma warning (disable : 25014 25007 25058)
#include "helloworld.grpc.pb.h"
#pragma warning(pop)

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::AuthContext;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

bool verify_client = false;
char* roots_file = nullptr;
char* pem_roots = nullptr;
int pem_roots_length = 0;
char* certs_file = nullptr;
char* pem_cert_chain = nullptr;
char* keyId = nullptr;
char* keyIdFile = nullptr;
bool userLocation = true;
char* server_address = nullptr;

typedef struct ::grpc::experimental::TlsServerAuthorizationCheckInterface TlsServerAuthorizationCheckInterface;
typedef class ::grpc::experimental::TlsServerAuthorizationCheckArg TlsServerAuthorizationCheckArg;
typedef class ::grpc::experimental::TlsServerAuthorizationCheckConfig TlsServerAuthorizationCheckConfig;
typedef class ::grpc::experimental::TlsCredentialsOptions TlsCredentialsOptions;

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

static inline bool isVerified(std::shared_ptr<const AuthContext>  auth_ctx, const std::string& expectedSAN)
{
    auto commonName =
         auth_ctx->FindPropertyValues(GRPC_X509_CN_PROPERTY_NAME);
    for (auto cn : commonName)
	    printf("common name: %s\n", cn.data());

    if (expectedSAN.compare("*") == 0 && commonName.size() >0)
	    return true;

    auto altName =
         auth_ctx->FindPropertyValues(GRPC_X509_SAN_PROPERTY_NAME);

    for (auto san : altName)
	    if (san.compare(expectedSAN) == 0)
	    {
		    printf("'%s' matched san '%s'\n", expectedSAN.c_str(), san.data());
		    return true;
	    }
    return false;

}

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
    Status SayHello(ServerContext* context, const HelloRequest* request,
        HelloReply* reply) override {

        std::shared_ptr<const AuthContext> auth_ctx = context->auth_context();

        if (auth_ctx)
        {
            printf("\nGot Auth Context\n");
            fflush(stdout);

            if (verify_client)
            {
                printf("mTLS checking...\n");
                if (isVerified(auth_ctx, "*"))
		{
		   printf("client cert AuthN & AuthZ passed\n");
		}
		else
		{
		   return Status(grpc::PERMISSION_DENIED, "client cert is rejected");
		}

	        std::string prefix("Hello ");
                if (isVerified(auth_ctx, "TESTVMMHSM"))
		{
			prefix += "TESTVMMHSM:";
		}

                reply->set_message(prefix + request->name());
                return Status::OK;
            }
            else
            {
                printf("Sending Hello\n");
                fflush(stdout);
                std::string prefix("Hello ");
                reply->set_message(prefix + request->name());
                return Status::OK;
            }
        }
        else
        {
            printf("\nNO Auth Context\n");
            printf("Insecurely Sending Hello\n");
            fflush(stdout);
            std::string prefix("Hello ");
            reply->set_message(prefix + request->name());
            return Status::OK;
        }
    }
};

/// setup gRPC server credentials
std::shared_ptr<grpc::ServerCredentials> _grpc_get_server_credentials()
{
    std::shared_ptr<grpc::ServerCredentials> server_credentials = nullptr;
    grpc::string server_pem_root_certs; // root certs on the server side to verify client certs
    grpc::string server_pem_private_key; // Server's private key to setup TLS
    grpc::string server_pem_cert_chain; // Server's cert chain as server's identity

    if (pem_roots)
    { 
        server_pem_root_certs = pem_roots;
    }

    if (pem_cert_chain)
    {
        server_pem_cert_chain = pem_cert_chain;
    }

    if (keyId)
    {
        server_pem_private_key = keyId;
    }


    grpc::experimental::IdentityKeyCertPair key_cert_pair;
    key_cert_pair.private_key = server_pem_private_key;
    key_cert_pair.certificate_chain = server_pem_cert_chain;

    std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs;
    identity_key_cert_pairs.emplace_back(key_cert_pair);
    auto certificate_provider =
        std::make_shared<grpc::experimental::StaticDataCertificateProvider>(identity_key_cert_pairs);
    grpc::experimental::TlsServerCredentialsOptions options(certificate_provider);
    
    if (verify_client)
    {
        options.set_cert_request_type(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY);
    }
    else
    {
        options.set_cert_request_type(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    }
    
    options.set_root_cert_name(roots_file);
    /*seems not working on server side: 
      E1008 06:25:43.759000000 19628 tls_security_connector.cc:627] TlsServerCertificateWatcher getting root_cert_error: 
      {"created":"@1633699543.759000000","description":"Unable to get latest root certificates.",
      "file":"C:\vcpkg\buildtrees\grpc\src\17cc203898-2fe48f7d61.clean\src\core\lib\security\credentials\tls\grpc_tls_certificate_provider.cc","file_line":67}
    */ 
    // options.watch_root_certs(); 
    options.set_identity_cert_name(certs_file);
    options.watch_identity_key_cert_pairs();

    server_credentials = TlsServerCredentials(options);
    return server_credentials;
}

/// Run gRPC server
void RunServer() {
    printf("Server Address: %s\n", server_address);
    std::string serverAddress(server_address);
    GreeterServiceImpl service;
    std::shared_ptr<grpc::ServerCredentials> serverChannelCredentials =  _grpc_get_server_credentials();

    ServerBuilder builder;
    builder.AddListeningPort(serverAddress, serverChannelCredentials);
    builder.RegisterService(&service);
    printf("ServerBuilder: Build and Start listening\n");
    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (server) {
        printf("Server listening on %s\n", server_address);
        fflush(stdout);
        server->Wait();
    }
    else {
        printf("Server Builder Failed\n");
    }
}

void Usage(void)
{
    printf("Usage: greeter_server [options]\n");
    printf("Options are:\n");
    printf("  -?                            - This message\n");
    printf("  -v                            - Verbose\n");
    printf("  -address <string>             - Server address Example: 0.0.0.0:50051 \n");
    printf("  -roots <filename>             - Roots certs in PEM format\n");
    printf("  -cert <filename>              - Server cert chain PEM file\n");
    printf("  -keyFile <filename>           - File containing engine key id string\n");
    printf("  -verifyClient                 - Verify client cert \n");
    printf("\n");
}

int main(int argc, char** argv)
{
    int ReturnStatus = 0;

    while (--argc > 0)
    {
        if (**++argv == '-')
        {
            if (strcmp(argv[0] + 1, "address") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                server_address = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "roots") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                roots_file = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "cert") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                certs_file = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "keyFile") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                keyIdFile = argv[1];
                argc -= 1;
                argv += 1;
            }
            else if (strcmp(argv[0] + 1, "verifyClient") == 0)
            {
                verify_client = true;
            }
            else if (strcmp(argv[0] + 1, "?") == 0)
            {
                goto BadUsage;
            }
        }
    }

    if (roots_file)
    {
        std::ifstream fileStream(roots_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)),std::istreambuf_iterator<char>());

        pem_roots = (char*)malloc(fileContents.length() + 1);
        if (pem_roots == nullptr) {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(pem_roots, fileContents.c_str(), fileContents.length());
        pem_roots[fileContents.length()] = '\0';
    }

    if (certs_file)
    {
        std::ifstream serverCertFile(certs_file);
        std::string fileContents((std::istreambuf_iterator<char>(serverCertFile)), std::istreambuf_iterator<char>());
        pem_cert_chain = (char*)malloc(fileContents.length() + 1);
        if (pem_cert_chain == nullptr) {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(pem_cert_chain, fileContents.c_str(), fileContents.length());
        pem_cert_chain[fileContents.length()] = '\0';
    }

    if (keyIdFile)
    {
        std::ifstream fileStream(keyIdFile);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        rtrim(fileContents);
        keyId = (char*)malloc(fileContents.length() + 1);
        if (keyId == nullptr)
        {
            printf("Can't allocate \n");
            ReturnStatus = -1;
            goto CommonReturn;
        }
        memcpy(keyId, fileContents.c_str(), fileContents.length());
        keyId[fileContents.length()] = '\0';
    }

    fflush(stdout);
    if (!pem_roots)
    {
        printf("Missing Root Information\n");
        goto BadUsage;
    }
    else
    {
        printf("Root Certs:\n%s", pem_roots);
        printf("\n\n");
    }

    if (!pem_cert_chain)
    {
        printf("Missing server chain information\n");
        goto BadUsage;
    }
    else
    {
        printf("Cert Chain:\n%s", pem_cert_chain);
        printf("\n\n");
    }

    if (!keyId)
    {
        printf("Missing key Id\n");
        goto BadUsage;
    }
    else
    {
        printf("KeyId:\n%s", keyId);
        printf("\n\n");
    }

    fflush(stdout);
    RunServer();
    ReturnStatus = 0;
    goto CommonReturn;

BadUsage:
    Usage();
    ReturnStatus = -1;

CommonReturn:
    free(pem_roots);
    free(pem_cert_chain);
    free(keyId);

    return ReturnStatus;
}
