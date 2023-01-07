# Introduction 
The Azure Key Vault and Managed HSM Engine allows OpenSSL-based applications to use RSA/EC private keys protected by Azure Key Vault and Managed HSM. It leverages the OpenSSL engine interface to perform cryptographic operations inside Azure Key Vault and Managed HSM. The goal is to seamlessly onboard OpenSSL-based applications with Azure Key Vault and Managed HSM, for example, NGINX, gRPC etc.

> NOTE: Azure Key Vault should ONLY be used for development purposes with small numbers of requests. For production workloads, use Azure Managed HSM. For more information, see [Azure Key Vault Service Limits](https://docs.microsoft.com/en-us/azure/key-vault/general/service-limits)

# Blog
[Introducing Azure Key Vault and Managed HSM Engine: An Open-Source Project](https://techcommunity.microsoft.com/t5/azure-confidential-computing/introducing-azure-key-vault-and-managed-hsm-engine-an-open/ba-p/3032273)

# Getting Started

## Linux/Ubuntu

1. Install dependencies
   ```
    sudo apt install -y build-essential
    sudo apt install -y libssl-dev
    sudo apt install -y libcurl4-openssl-dev
    sudo apt install -y libjson-c-dev
   ```
2. Clone Repo
3. Build
   ```
    cd src
    mkdir build
    cd build
    cmake ..
    make
    sudo mkdir -p /usr/lib/x86_64-linux-gnu/engines-1.1/
    sudo cp e_akv.so /usr/lib/x86_64-linux-gnu/engines-1.1/e_akv.so
   ```
4. Test
   ```
   openssl engine -vvv -t e_akv
   ```
[NOTE] if the openssl version is 3.0 or 3.0+, please reinstall the openssl 
```
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.16_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb
sudo dpkg -i libssl-dev_1.1.1f-1ubuntu2.16_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
sudo dpkg -i openssl_1.1.1f-1ubuntu2.16_amd64.deb
```
## Windows

1. Install Visual Studio 2019
2. Install `vcpk` in command window "Developer Command Prompt for VS 2019"
    ```
    c:
    cd \
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    bootstrap-vcpkg.bat -disableMetrics
    vcpkg.exe install json-c:x64-windows-static
    vcpkg.exe install curl:x64-windows-static
    vcpkg.exe install openssl:x64-windows
    mkdir C:\vcpkg\packages\openssl_x64-windows\lib\engines-1_1
    ```
3. Clone Repo
4. Build 
   ```
   cd src
   msbuild e_akv.vcxproj /p:PkgCurl="C:\vcpkg\packages\curl_x64-windows-static" /p:PkgJson="C:\vcpkg\packages\json-c_x64-windows-static" /p:PkgZ="C:\vcpkg\packages\zlib_x64-windows-static" /p:PkgOpenssl="C:\vcpkg\packages\openssl_x64-windows" /p:Configuration=Release;Platform=x64
   copy /Y x64\Release\e_akv.dll C:\vcpkg\packages\openssl_x64-windows\lib\engines-1_1\e_akv.dll
   ```
5. Test 
   ```
   C:\vcpkg\packages\openssl_x64-windows\tools\openssl\openssl.exe engine -vvv -t e_akv
   ```
   
NOTE: new vcpkg is using openssl 3.0 and please use vcpkg.json to override openssl version
```
vcpkg.json
{ 
  "name": "dbkg", 
  "version-string": "1.0.0", 
  "dependencies": [ "zlib", "json-c", "curl", "abseil", "c-ares", "grpc", "protobuf", "re2", "upb", "openssl"],
  "builtin-baseline": "2ac61f87f69f0484b8044f95ab274038fbaf7bdd", 
  "overrides": [ 
     { "name": "openssl", "version-string": "1.1.1n" },
     { "name": "zlib", "version-string": "1.2.13" }
  ] 
} 

vcpkg\vcpkg install --triplet=x64-windows-static
cd D:\AzureKeyVaultManagedHSMEngine\src
set VCPKG_ROOT=D:\vcpkg
msbuild  e_akv.vcxproj /p:PkgOpenssl="%VCPKG_ROOT%\packages\openssl_x64-windows" /p:PkgCurl="%VCPKG_ROOT%\packages\curl_x64-windows-static" /p:PkgJson="%VCPKG_ROOT%\packages\json-c_x64-windows-static" /p:PkgZ="%VCPKG_ROOT%\packages\zlib_x64-windows-static" /p:Configuration=Release;Platform=x64
```
# Samples

Please check out the samples including nginx, gRPC, and openssl command line.
NEW: AZURE CLI Credentials are supported, details in https://github.com/microsoft/AzureKeyVaultManagedHSMEngine/blob/main/samples/openssl/UseAzureCliCredential.md

# Contribute

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademark Notice

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies. Azure Key Vault and Managed HSM Engine is not affiliated with OpenSSL. OpenSSL is a registered trademark owned by OpenSSL Software Foundation.
