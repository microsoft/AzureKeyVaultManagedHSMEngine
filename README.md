# Introduction 
OpenSSL engine for Azure Key Vault and Managed HSM

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

# Contribute

To contribute to this project, see [Contributing](/CONTRIBUTING.md)

# Trademark Notice

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.

# Security

Microsoft takes the security of our software products and services seriously, which includes all source code repositories managed through our GitHub organizations, which include [Microsoft](https://github.com/Microsoft), [Azure](https://github.com/Azure), [DotNet](https://github.com/dotnet), [AspNet](https://github.com/aspnet), [Xamarin](https://github.com/xamarin), and [our GitHub organizations](https://opensource.microsoft.com/).

If you believe you have found a security vulnerability in any Microsoft-owned repository that meets [Microsoft's definition of a security vulnerability](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc751383(v=technet.10)), please report it to us as described below.

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them to the Microsoft Security Response Center (MSRC) at [https://msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report).

If you prefer to submit without logging in, send email to [secure@microsoft.com](mailto:secure@microsoft.com).  If possible, encrypt your message with our PGP key; please download it from the [Microsoft Security Response Center PGP Key page](https://www.microsoft.com/en-us/msrc/pgp-key-msrc).

You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message. Additional information can be found at [microsoft.com/msrc](https://www.microsoft.com/msrc). 

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

  * Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
  * Full paths of source file(s) related to the manifestation of the issue
  * The location of the affected source code (tag/branch/commit or direct URL)
  * Any special configuration required to reproduce the issue
  * Step-by-step instructions to reproduce the issue
  * Proof-of-concept or exploit code (if possible)
  * Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

If you are reporting for a bug bounty, more complete reports can contribute to a higher bounty award. Please visit our [Microsoft Bug Bounty Program](https://microsoft.com/msrc/bounty) page for more details about our active programs.

## Preferred Languages

We prefer all communications to be in English.

## Policy

Microsoft follows the principle of [Coordinated Vulnerability Disclosure](https://www.microsoft.com/en-us/msrc/cvd).
