// --------------------------------------------------------------------------------------------------------------------
// <copyright file="greeter_client.cpp" company="Microsoft">
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
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <grpcpp/security/server_credentials.h>


#pragma warning (disable : 25014 25007 25058)
#include "helloworld.grpc.pb.h"
#pragma warning(pop)

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::AuthContext;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;

char* roots_file = nullptr;
char* pem_roots = nullptr;
int pem_roots_length = 0;
char* certs_file = nullptr;
char* pem_cert_chain = nullptr;
char* keyId = nullptr;
char* keyIdFile = nullptr;
bool userLocation = true;
char* server_address = nullptr;
char* server_name = nullptr;

typedef struct ::grpc::experimental::TlsServerAuthorizationCheckInterface TlsServerAuthorizationCheckInterface;
typedef class ::grpc::experimental::TlsServerAuthorizationCheckArg TlsServerAuthorizationCheckArg;
typedef class ::grpc::experimental::TlsServerAuthorizationCheckConfig TlsServerAuthorizationCheckConfig;
typedef class ::grpc::experimental::TlsCredentialsOptions TlsCredentialsOptions;
typedef class TestTlsServerAuthorizationCheck TestTlsServerAuthorizationCheck;

static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

class GreeterClient {
public:
    GreeterClient(std::shared_ptr<Channel> channel)
        : stub_(Greeter::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back
    // from the server.
    std::string SayHello(const std::string& user) {
        // Data we are sending to the server.
        HelloRequest request;
        request.set_name(user);

        // Container for the data we expect from the server.
        HelloReply reply;

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->SayHello(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            return reply.message();
        }
        else {
            std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
            return "RPC failed";
        }
    }

private:
    std::unique_ptr<Greeter::Stub> stub_;
};


bool verify_peer(const char* peer_pem)
{
    if (peer_pem == nullptr)
    {
        printf("No Certificates\n");
        return false;
    }

    printf("Chain is verified\n");
    return true;
}

class TestTlsServerAuthorizationCheck
    : public TlsServerAuthorizationCheckInterface {
    int Schedule(TlsServerAuthorizationCheckArg* arg) override {
        printf("Callback Schedule\n");

        if (arg) {
            if (arg->target_name().c_str())
            {
                printf("Callback TargetName: %s\n", arg->target_name().c_str());
            }

            if (verify_peer(arg->peer_cert_full_chain().c_str()))
            {
                // Chain is verified
                arg->set_cb_user_data(nullptr);
                arg->set_success(1);
                arg->set_status(GRPC_STATUS_OK);
            }
            else
            {
                // Chain is not verified
                arg->set_cb_user_data(nullptr);
                arg->set_success(0);
                arg->set_status(GRPC_STATUS_UNAUTHENTICATED);
            }
        }

        return 0; // must return 0, otherwise it is hanging
    }

    void Cancel(TlsServerAuthorizationCheckArg* arg) override {
        if (arg) {
            arg->set_success(0);
            arg->set_status(GRPC_STATUS_PERMISSION_DENIED);
        }
    }
};

void RunClient() {
    printf("Server Address: %s\n", server_address);
    printf("Server Name: %s\n", server_name);
    fflush(stdout);

    grpc::experimental::TlsChannelCredentialsOptions options;
    options.set_server_verification_option(GRPC_TLS_SKIP_ALL_SERVER_VERIFICATION);
    auto test_server_authorization_check =
        std::make_shared<TestTlsServerAuthorizationCheck>();
    auto server_authorization_check_config =
        std::make_shared<TlsServerAuthorizationCheckConfig>(
            test_server_authorization_check);
    options.set_server_authorization_check_config(
        server_authorization_check_config);
    options.set_root_cert_name(roots_file);
    /*
    It is important to add watch_root_certs. Otherwise, you will see the following error
       ssl_utils.cc:406 Could not get default pem root certs.
    Another workaround is to define enviornment variable 
       set GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=C:\Users\azureuser\TestGRPC\script\root.pem
    But adding this is cleaner.
    */
    options.watch_root_certs();
    if (pem_cert_chain && keyId)
    {
        printf("Set client cert\n");
        options.set_identity_cert_name(certs_file);
        grpc::experimental::IdentityKeyCertPair key_cert_pair;
        key_cert_pair.private_key = keyId;
        key_cert_pair.certificate_chain = pem_cert_chain;
        std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs;
        identity_key_cert_pairs.emplace_back(key_cert_pair);
        auto certificate_provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
            pem_roots, identity_key_cert_pairs);
        options.set_certificate_provider(certificate_provider);
        /*
        It is extremly important to add this for client cert.
        Otherwise, you will see errors on server side
        ssl_transport_security.cc:1455 Handshake failed with fatal error SSL_ERROR_SSL: error:1417C0C7:SSL routines:tls_process_client_certificate:peer did not return a certificate.
        */
        options.watch_identity_key_cert_pairs();
    }
    else
    {
        auto certificate_provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(pem_roots);
        options.set_certificate_provider(certificate_provider);
    }

    auto clientChannelCredentials = grpc::experimental::TlsCredentials(options);

    grpc::ChannelArguments args;
    args.SetSslTargetNameOverride(server_name);
    args.SetInt(GRPC_ARG_ENABLE_CHANNELZ, 1);
    args.SetInt(GRPC_ARG_MAX_CHANNEL_TRACE_EVENT_MEMORY_PER_NODE, 1024);
    printf("Creating Custom Channel\n");
    fflush(stdout);
    auto channel = grpc::CreateCustomChannel(server_address, clientChannelCredentials, args);
    GreeterClient greeter(channel);
   
    std::string user("world");
    std::string reply = greeter.SayHello(user);
    printf("Greeter %s received: %s\n", user.c_str(), reply.c_str());

    printf("Reuse Custom Channel\n");
    fflush(stdout);
    GreeterClient greeter2(channel);
   
    std::string user2("azure");
    std::string reply2 = greeter2.SayHello(user2);
    printf("Greeter %s received: %s\n", user2.c_str(), reply2.c_str());

}

void Usage(void)
{
    printf("Usage: greeter_client [options]\n");
    printf("Options are:\n");
    printf("  -?                        - This message\n");
    printf("  -v                        - Verbose\n");
    printf("  -address <string>         - Server address Example: 0.0.0.0:50051 \n");
    printf("  -name <string>            - Server name: 0.0.0.0:50051 \n");
    printf("  -roots <filename>         - Roots certs in PEM format\n");
    printf("  -cert <filename>          - Server cert chain PEM file\n");
    printf("  -keyFile <filename>       - File containing engine key id string\n");
    printf("\n");
}

int main(int argc, char** argv) {

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
            if (strcmp(argv[0] + 1, "name") == 0)
            {
                if (argc < 2 || argv[1][0] == '-') {
                    printf("Option (-%s) : missing argument\n", argv[0] + 1);
                    goto BadUsage;
                }
                server_name = argv[1];
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
            else if (strcmp(argv[0] + 1, "?") == 0)
            {
                goto BadUsage;
            }
        }
    }

    if (roots_file)
    {
        std::ifstream fileStream(roots_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());

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
        std::ifstream fileStream(certs_file);
        std::string fileContents((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        pem_cert_chain = (char*)malloc(fileContents.length() + 1);
        if (pem_cert_chain == NULL) {
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

    if (!pem_roots)
    {
        printf("Missing Root Information\n");
        goto BadUsage;
    }
    else
    {
        printf("Root Certs:\n%s\n\n", pem_roots);
    }

    if (pem_cert_chain)
    {
        printf("Cert Chain:\n%s\n\n", pem_cert_chain);
    }

    if (keyId)
    {
        printf("KeyId:\n'%s'\n\n", keyId);
    }

    fflush(stdout);
    RunClient();
    ReturnStatus = 0;
    goto CommonReturn;

BadUsage:
    Usage();
    ReturnStatus = -1;

CommonReturn:
    free(pem_roots);
    free(keyId);
    free(pem_cert_chain);

    return ReturnStatus;
}
