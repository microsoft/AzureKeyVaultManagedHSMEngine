@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Azure Managed HSM Validation Script
REM ============================================================================
REM This script validates access to Azure Managed HSM and required keys
REM Usage: validate_hsm.bat [vault_name] [rsa_key] [ec_key] [aes_key]
REM ============================================================================

REM Get parameters or use defaults
set AKV_VAULT=%1
set AKV_RSA_KEY=%2
set AKV_EC_KEY=%3
set AKV_AES_KEY=%4

if "%AKV_VAULT%"=="" set AKV_VAULT=ManagedHSMOpenSSLEngine
if "%AKV_RSA_KEY%"=="" set AKV_RSA_KEY=myrsakey
if "%AKV_EC_KEY%"=="" set AKV_EC_KEY=ecckey
if "%AKV_AES_KEY%"=="" set AKV_AES_KEY=myaeskey

echo.
echo === Azure Managed HSM Validation ===
echo Vault: %AKV_VAULT%
echo RSA Key: %AKV_RSA_KEY%
echo EC Key: %AKV_EC_KEY%
echo AES Key: %AKV_AES_KEY%
echo.

REM Check if Azure CLI is installed
where az >nul 2>&1
if errorlevel 1 (
    echo ERROR: Azure CLI is not installed
    echo Download from: https://aka.ms/installazurecliwindows
    exit /b 1
)

REM Get access token
echo Fetching access token...
for /f "tokens=2 delims=:," %%i in ('call az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net ^| findstr "accessToken"') do (
    set AZURE_CLI_ACCESS_TOKEN=%%i
)

REM Remove quotes and spaces from token
set AZURE_CLI_ACCESS_TOKEN=!AZURE_CLI_ACCESS_TOKEN:"=!
set AZURE_CLI_ACCESS_TOKEN=!AZURE_CLI_ACCESS_TOKEN: =!

if "%AZURE_CLI_ACCESS_TOKEN%"=="" (
    echo ERROR: Failed to get access token
    echo Please verify you are logged in with 'az login'
    exit /b 1
)
echo [OK] Access token acquired
echo.

echo --- Validating Managed HSM and keys (this may take 20-30 seconds) ---
echo.

REM Check if vault exists and is accessible
echo [1/4] Checking access to vault '%AKV_VAULT%'...
call az keyvault show --hsm-name %AKV_VAULT% --query "properties.provisioningState" -o tsv
if errorlevel 1 (
    echo ERROR: Cannot access Managed HSM '%AKV_VAULT%'
    echo Please verify:
    echo   1. The Managed HSM name is correct
    echo   2. You have appropriate permissions
    echo   3. You are logged in with 'az login'
    exit /b 1
)
echo [OK] Vault is accessible
echo.

REM Check if RSA key exists
echo [2/4] Checking RSA key '%AKV_RSA_KEY%'...
call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_RSA_KEY% --query "key.kty" -o tsv
if errorlevel 1 (
    echo ERROR: RSA key '%AKV_RSA_KEY%' not found in vault '%AKV_VAULT%'
    echo Create the key with: az keyvault key create --hsm-name %AKV_VAULT% --name %AKV_RSA_KEY% --kty RSA-HSM --size 3072
    exit /b 1
)
for /f %%k in ('call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_RSA_KEY% --query "key.kty" -o tsv') do set RSA_KEY_TYPE=%%k
echo [OK] RSA key found (type: %RSA_KEY_TYPE%)
echo.

REM Check if EC key exists
echo [3/4] Checking EC key '%AKV_EC_KEY%'...
call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_EC_KEY% --query "key.kty" -o tsv
if errorlevel 1 (
    echo ERROR: EC key '%AKV_EC_KEY%' not found in vault '%AKV_VAULT%'
    echo Create the key with: az keyvault key create --hsm-name %AKV_VAULT% --name %AKV_EC_KEY% --kty EC-HSM --curve P-256
    exit /b 1
)
for /f %%k in ('call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_EC_KEY% --query "key.kty" -o tsv') do set EC_KEY_TYPE=%%k
echo [OK] EC key found (type: %EC_KEY_TYPE%)
echo.

REM Check if AES key exists
echo [4/4] Checking AES key '%AKV_AES_KEY%'...
call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_AES_KEY% --query "key.kty" -o tsv
if errorlevel 1 (
    echo ERROR: AES key '%AKV_AES_KEY%' not found in vault '%AKV_VAULT%'
    echo Create the key with: az keyvault key create --hsm-name %AKV_VAULT% --name %AKV_AES_KEY% --kty oct-HSM --size 256
    exit /b 1
)
for /f %%k in ('call az keyvault key show --hsm-name %AKV_VAULT% --name %AKV_AES_KEY% --query "key.kty" -o tsv') do set AES_KEY_TYPE=%%k
echo [OK] AES key found (type: %AES_KEY_TYPE%)
echo.

echo ============================================
echo All validations passed successfully!
echo ============================================
echo.

exit /b 0
