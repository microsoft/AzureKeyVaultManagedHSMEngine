@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Azure Managed HSM OpenSSL Provider Test Suite
REM ============================================================================

echo.
echo === Azure Managed HSM signing tests ===
echo.

REM Change to script directory
cd /d "%~dp0"
echo Working directory: %CD%

REM Fetch Azure CLI access token using pure batch commands
echo Fetching Azure CLI access token...
for /f "tokens=2 delims=:," %%i in ('az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net ^| findstr "accessToken"') do (
    set AZURE_CLI_ACCESS_TOKEN=%%i
)

REM Remove quotes and spaces from token
set AZURE_CLI_ACCESS_TOKEN=!AZURE_CLI_ACCESS_TOKEN:"=!
set AZURE_CLI_ACCESS_TOKEN=!AZURE_CLI_ACCESS_TOKEN: =!

if "%AZURE_CLI_ACCESS_TOKEN%"=="" (
    echo ERROR: Failed to get access token
    goto :error
)

REM Set up logging
set AKV_LOG_FILE=.\logs\akv_provider.log
set AKV_LOG_LEVEL=3
if not exist logs mkdir logs >nul 2>&1
echo Logging to %AKV_LOG_FILE% at level %AKV_LOG_LEVEL%

REM Create timestamped temp folder for test files
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do set DATE=%%c%%a%%b
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set TIME=%%a%%b
set TIME=%TIME: =0%
set TEMP_FOLDER=temp_%DATE%_%TIME%
if not exist %TEMP_FOLDER% mkdir %TEMP_FOLDER% >nul 2>&1
echo Test files will be generated in .\%TEMP_FOLDER%\
echo.

REM Generate test payload if needed
if not exist %TEMP_FOLDER%\input.bin (
    echo Generating %TEMP_FOLDER%\input.bin payload...
    echo Azure Managed HSM signing test> %TEMP_FOLDER%\input.bin
) else (
    echo Found existing %TEMP_FOLDER%\input.bin payload.
)

REM Set vault and key names
if "%AKV_VAULT%"=="" set AKV_VAULT=ManagedHSMOpenSSLEngine
if "%AKV_RSA_KEY%"=="" set AKV_RSA_KEY=myrsakey
if "%AKV_EC_KEY%"=="" set AKV_EC_KEY=ecckey
if "%AKV_AES_KEY%"=="" set AKV_AES_KEY=myaeskey

set RSA_PROVIDER_PATH=managedhsm:%AKV_VAULT%:%AKV_RSA_KEY%
set EC_PROVIDER_PATH=managedhsm:%AKV_VAULT%:%AKV_EC_KEY%
set AES_PROVIDER_PATH=managedhsm:%AKV_VAULT%:%AKV_AES_KEY%

echo Using vault '%AKV_VAULT%' with RSA key '%AKV_RSA_KEY%', EC key '%AKV_EC_KEY%', and AES key '%AKV_AES_KEY%'.
echo.

REM Compute digest for verification
echo Computing SHA-256 digest for %TEMP_FOLDER%\input.bin...
openssl dgst -sha256 -binary -out %TEMP_FOLDER%\input.sha256.bin %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo.
echo --- Exporting public keys via provider ---
echo Running: openssl pkey -provider akv_provider -provider default -in %RSA_PROVIDER_PATH% -pubout -out %TEMP_FOLDER%\myrsakey_pub.pem
openssl pkey -provider akv_provider -provider default -in %RSA_PROVIDER_PATH% -pubout -out %TEMP_FOLDER%\myrsakey_pub.pem
if errorlevel 1 goto :error

echo Running: openssl pkey -provider akv_provider -provider default -in %EC_PROVIDER_PATH% -pubout -out %TEMP_FOLDER%\ecckey_pub.pem
openssl pkey -provider akv_provider -provider default -in %EC_PROVIDER_PATH% -pubout -out %TEMP_FOLDER%\ecckey_pub.pem
if errorlevel 1 goto :error

echo.
echo --- RSA PS256 signing roundtrip ---
echo Running: openssl dgst -sha256 -sign %RSA_PROVIDER_PATH% -provider akv_provider -provider default -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 -out %TEMP_FOLDER%\ps256.sig %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -sign %RSA_PROVIDER_PATH% -provider akv_provider -provider default -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 -out %TEMP_FOLDER%\ps256.sig %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo Running: openssl dgst -sha256 -verify %TEMP_FOLDER%\myrsakey_pub.pem -signature %TEMP_FOLDER%\ps256.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -verify %TEMP_FOLDER%\myrsakey_pub.pem -signature %TEMP_FOLDER%\ps256.sig -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo.
echo --- RSA RS256 signing roundtrip ---
echo Running: openssl dgst -sha256 -sign %RSA_PROVIDER_PATH% -provider akv_provider -provider default -sigopt rsa_padding_mode:pkcs1 -out %TEMP_FOLDER%\rs256.sig %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -sign %RSA_PROVIDER_PATH% -provider akv_provider -provider default -sigopt rsa_padding_mode:pkcs1 -out %TEMP_FOLDER%\rs256.sig %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo Running: openssl dgst -sha256 -verify %TEMP_FOLDER%\myrsakey_pub.pem -signature %TEMP_FOLDER%\rs256.sig -sigopt rsa_padding_mode:pkcs1 %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -verify %TEMP_FOLDER%\myrsakey_pub.pem -signature %TEMP_FOLDER%\rs256.sig -sigopt rsa_padding_mode:pkcs1 %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo.
echo --- RSA OAEP decrypt roundtrip ---
echo Running: openssl pkeyutl -encrypt -pubin -inkey %TEMP_FOLDER%\myrsakey_pub.pem -in %TEMP_FOLDER%\input.bin -out %TEMP_FOLDER%\rsa_cipher.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1
openssl pkeyutl -encrypt -pubin -inkey %TEMP_FOLDER%\myrsakey_pub.pem -in %TEMP_FOLDER%\input.bin -out %TEMP_FOLDER%\rsa_cipher.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1
if errorlevel 1 goto :error

echo Running: openssl pkeyutl -decrypt -provider akv_provider -provider default -inkey %RSA_PROVIDER_PATH% -in %TEMP_FOLDER%\rsa_cipher.bin -out %TEMP_FOLDER%\rsa_roundtrip.bin
openssl pkeyutl -decrypt -provider akv_provider -provider default -inkey %RSA_PROVIDER_PATH% -in %TEMP_FOLDER%\rsa_cipher.bin -out %TEMP_FOLDER%\rsa_roundtrip.bin
if errorlevel 1 goto :error

fc /b %TEMP_FOLDER%\input.bin %TEMP_FOLDER%\rsa_roundtrip.bin >nul
if errorlevel 1 (
    echo ERROR: RSA decrypt roundtrip does not match!
    goto :error
)
echo RSA decrypt roundtrip matches input.bin.

echo.
echo --- EC ES256 signing roundtrip ---
echo Running: openssl dgst -sha256 -sign %EC_PROVIDER_PATH% -provider akv_provider -provider default -out %TEMP_FOLDER%\es256.sig %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -sign %EC_PROVIDER_PATH% -provider akv_provider -provider default -out %TEMP_FOLDER%\es256.sig %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo Running: openssl dgst -sha256 -verify %TEMP_FOLDER%\ecckey_pub.pem -signature %TEMP_FOLDER%\es256.sig %TEMP_FOLDER%\input.bin
openssl dgst -sha256 -verify %TEMP_FOLDER%\ecckey_pub.pem -signature %TEMP_FOLDER%\es256.sig %TEMP_FOLDER%\input.bin
if errorlevel 1 goto :error

echo.
echo.
echo === X.509 CSR and Certificate Tests ===
echo.

echo --- RSA CSR generation and verification ---
if exist testOpenssl.cnf (
    echo Running: openssl req -config testOpenssl.cnf -new -provider akv_provider -provider default -key %RSA_PROVIDER_PATH% -sha256 -sigopt rsa_padding_mode:pkcs1 -out %TEMP_FOLDER%\cert.csr
    openssl req -config testOpenssl.cnf -new -provider akv_provider -provider default -key %RSA_PROVIDER_PATH% -sha256 -sigopt rsa_padding_mode:pkcs1 -out %TEMP_FOLDER%\cert.csr
) else (
    echo Running: openssl req -new -provider akv_provider -provider default -key %RSA_PROVIDER_PATH% -sha256 -sigopt rsa_padding_mode:pkcs1 -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\cert.csr
    openssl req -new -provider akv_provider -provider default -key %RSA_PROVIDER_PATH% -sha256 -sigopt rsa_padding_mode:pkcs1 -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\cert.csr
)
if errorlevel 1 goto :error

echo Running: openssl req -in %TEMP_FOLDER%\cert.csr -noout -verify -provider akv_provider -provider default
openssl req -in %TEMP_FOLDER%\cert.csr -noout -verify -provider akv_provider -provider default
if errorlevel 1 goto :error
echo CSR verification successful.

echo.
echo --- RSA self-signed certificate generation ---
if exist testOpenssl.cnf (
    echo Running: openssl req -config testOpenssl.cnf -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %RSA_PROVIDER_PATH% -sha256 -days 365 -out %TEMP_FOLDER%\cert.pem
    openssl req -config testOpenssl.cnf -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %RSA_PROVIDER_PATH% -sha256 -days 365 -out %TEMP_FOLDER%\cert.pem
) else (
    echo Running: openssl req -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %RSA_PROVIDER_PATH% -sha256 -days 365 -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\cert.pem
    openssl req -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %RSA_PROVIDER_PATH% -sha256 -days 365 -subj "/CN=Azure Managed HSM Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\cert.pem
)
if errorlevel 1 goto :error

echo Running: openssl verify -provider akv_provider -provider default -CAfile %TEMP_FOLDER%\cert.pem %TEMP_FOLDER%\cert.pem
openssl verify -provider akv_provider -provider default -CAfile %TEMP_FOLDER%\cert.pem %TEMP_FOLDER%\cert.pem
if errorlevel 1 goto :error
echo Self-signed certificate verification successful.

echo.
echo --- EC CSR generation and verification ---
if exist testOpenssl.cnf (
    echo Running: openssl req -config testOpenssl.cnf -new -provider akv_provider -provider default -key %EC_PROVIDER_PATH% -sha256 -out %TEMP_FOLDER%\ec_cert.csr
    openssl req -config testOpenssl.cnf -new -provider akv_provider -provider default -key %EC_PROVIDER_PATH% -sha256 -out %TEMP_FOLDER%\ec_cert.csr
) else (
    echo Running: openssl req -new -provider akv_provider -provider default -key %EC_PROVIDER_PATH% -sha256 -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\ec_cert.csr
    openssl req -new -provider akv_provider -provider default -key %EC_PROVIDER_PATH% -sha256 -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\ec_cert.csr
)
if errorlevel 1 goto :error

echo Running: openssl req -in %TEMP_FOLDER%\ec_cert.csr -noout -verify -provider akv_provider -provider default
openssl req -in %TEMP_FOLDER%\ec_cert.csr -noout -verify -provider akv_provider -provider default
if errorlevel 1 goto :error
echo EC CSR verification successful.

echo.
echo --- EC self-signed certificate generation ---
if exist testOpenssl.cnf (
    echo Running: openssl req -config testOpenssl.cnf -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %EC_PROVIDER_PATH% -sha256 -days 365 -out %TEMP_FOLDER%\ec_cert.pem
    openssl req -config testOpenssl.cnf -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %EC_PROVIDER_PATH% -sha256 -days 365 -out %TEMP_FOLDER%\ec_cert.pem
) else (
    echo Running: openssl req -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %EC_PROVIDER_PATH% -sha256 -days 365 -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\ec_cert.pem
    openssl req -new -x509 -provider akv_provider -provider default -propquery ?provider=akv_provider -key %EC_PROVIDER_PATH% -sha256 -days 365 -subj "/CN=Azure Managed HSM EC Test/O=Microsoft/C=US" -out %TEMP_FOLDER%\ec_cert.pem
)
if errorlevel 1 goto :error

echo Running: openssl verify -provider akv_provider -provider default -CAfile %TEMP_FOLDER%\ec_cert.pem %TEMP_FOLDER%\ec_cert.pem
openssl verify -provider akv_provider -provider default -CAfile %TEMP_FOLDER%\ec_cert.pem %TEMP_FOLDER%\ec_cert.pem
if errorlevel 1 goto :error
echo EC self-signed certificate verification successful.

echo.
echo.
echo === AES Key Wrap/Unwrap Tests ===
echo.

echo --- Generating 32-byte test key ---
echo Running: openssl rand -out %TEMP_FOLDER%\local.key 32
openssl rand -out %TEMP_FOLDER%\local.key 32
if errorlevel 1 goto :error
for %%A in (%TEMP_FOLDER%\local.key) do echo Generated %TEMP_FOLDER%\local.key (%%~zA bytes)

echo.
echo --- Wrapping key with Azure Managed HSM AES key ---
echo Running: openssl pkeyutl -encrypt -inkey %AES_PROVIDER_PATH% -provider akv_provider -provider default -in %TEMP_FOLDER%\local.key -out %TEMP_FOLDER%\local.key.wrap
openssl pkeyutl -encrypt -inkey %AES_PROVIDER_PATH% -provider akv_provider -provider default -in %TEMP_FOLDER%\local.key -out %TEMP_FOLDER%\local.key.wrap
if errorlevel 1 goto :error
for %%A in (%TEMP_FOLDER%\local.key.wrap) do echo Wrapped successfully -^> %TEMP_FOLDER%\local.key.wrap (%%~zA bytes)

echo.
echo --- Unwrapping key with Azure Managed HSM AES key ---
echo Running: openssl pkeyutl -decrypt -inkey %AES_PROVIDER_PATH% -provider akv_provider -provider default -in %TEMP_FOLDER%\local.key.wrap -out %TEMP_FOLDER%\local.key.unwrapped
openssl pkeyutl -decrypt -inkey %AES_PROVIDER_PATH% -provider akv_provider -provider default -in %TEMP_FOLDER%\local.key.wrap -out %TEMP_FOLDER%\local.key.unwrapped
if errorlevel 1 goto :error
for %%A in (%TEMP_FOLDER%\local.key.unwrapped) do echo Unwrapped successfully -^> %TEMP_FOLDER%\local.key.unwrapped (%%~zA bytes)

echo.
echo --- Comparing original and unwrapped keys ---
fc /b %TEMP_FOLDER%\local.key %TEMP_FOLDER%\local.key.unwrapped >nul
if errorlevel 1 (
    echo ERROR: Keys do not match!
    goto :error
)
echo Keys match perfectly!

echo.
echo --- Negative test: Tamper with wrapped key ---
echo Attempting to unwrap tampered key (should fail)...
copy /y %TEMP_FOLDER%\local.key.wrap %TEMP_FOLDER%\local.key.wrap.tampered >nul
REM Flip a bit in the wrapped key
echo X>> %TEMP_FOLDER%\local.key.wrap.tampered
openssl pkeyutl -decrypt -inkey %AES_PROVIDER_PATH% -provider akv_provider -provider default -in %TEMP_FOLDER%\local.key.wrap.tampered -out %TEMP_FOLDER%\local.key.bad 2>nul
if not errorlevel 1 (
    echo ERROR: Tampered key unwrap should have failed!
    goto :error
)
echo Expected failure on tampered key - PASSED

echo.
echo.
echo === All tests completed successfully ===
echo.

REM Write test summary
echo Writing test summary to %TEMP_FOLDER%\test_summary.txt...
(
    echo Azure Managed HSM OpenSSL Provider - Test Summary
    echo ================================================
    echo.
    echo Test Run Date: %DATE%
    echo Test Run Time: %TIME%
    echo Working Directory: %CD%
    echo.
    echo Environment:
    echo   Vault: %AKV_VAULT%
    echo   RSA Key: %AKV_RSA_KEY%
    echo   EC Key: %AKV_EC_KEY%
    echo   AES Key: %AKV_AES_KEY%
    echo.
    echo Test Results:
    echo   [PASS] RSA PS256 signing roundtrip
    echo   [PASS] RSA RS256 signing roundtrip
    echo   [PASS] RSA OAEP decrypt roundtrip
    echo   [PASS] EC ES256 signing roundtrip
    echo   [PASS] RSA CSR generation and verification
    echo   [PASS] RSA self-signed certificate generation
    echo   [PASS] EC CSR generation and verification
    echo   [PASS] EC self-signed certificate generation
    echo   [PASS] AES key wrap/unwrap roundtrip
    echo   [PASS] AES tamper detection test
    echo.
    echo Test Files Generated:
    echo   - input.bin ^(test payload^)
    echo   - input.sha256.bin ^(digest^)
    echo   - myrsakey_pub.pem ^(RSA public key^)
    echo   - ecckey_pub.pem ^(EC public key^)
    echo   - ps256.sig, rs256.sig, es256.sig ^(signatures^)
    echo   - cert.csr, ec_cert.csr ^(certificate requests^)
    echo   - cert.pem, ec_cert.pem ^(self-signed certificates^)
    echo   - rsa_cipher.bin, rsa_roundtrip.bin ^(RSA encryption test^)
    echo   - local.key, local.key.wrap, local.key.unwrapped ^(AES wrap test^)
    echo   - local.key.wrap.tampered, local.key.bad ^(tamper test^)
    echo.
    echo All tests completed successfully!
) > %TEMP_FOLDER%\test_summary.txt

echo Test files preserved in .\%TEMP_FOLDER%\ folder
echo Test summary written to .\%TEMP_FOLDER%\test_summary.txt

echo.
goto :end

:error
echo.
echo ========================================================
echo ERROR: Test failed!
echo ========================================================
echo.

REM Write error summary
echo Writing error summary to %TEMP_FOLDER%\test_summary.txt...
(
    echo Azure Managed HSM OpenSSL Provider - Test Summary
    echo ================================================
    echo.
    echo Test Run Date: %DATE%
    echo Test Run Time: %TIME%
    echo Working Directory: %CD%
    echo.
    echo Environment:
    echo   Vault: %AKV_VAULT%
    echo   RSA Key: %AKV_RSA_KEY%
    echo   EC Key: %AKV_EC_KEY%
    echo   AES Key: %AKV_AES_KEY%
    echo.
    echo TEST FAILED!
    echo.
    echo Check the log file at: %AKV_LOG_FILE%
    echo Test files preserved for debugging in: %TEMP_FOLDER%
) > %TEMP_FOLDER%\test_summary.txt

echo Test files preserved in .\%TEMP_FOLDER%\ folder for debugging
exit /b 1

:end
endlocal
