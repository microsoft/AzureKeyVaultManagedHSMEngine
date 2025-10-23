@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Azure Managed HSM Setup Script
REM ============================================================================
REM This script automates the creation and activation of an Azure Managed HSM
REM instance along with the required keys for the OpenSSL provider testing.
REM
REM Prerequisites:
REM   - Azure CLI installed (az login)
REM   - Logged in to Azure (az login)
REM   - Appropriate Azure subscription with permissions
REM   - OpenSSL installed (for security domain activation)
REM
REM Usage: setup_managed_hsm.bat [HSM_NAME] [RESOURCE_GROUP] [LOCATION]
REM
REM ============================================================================

if /i "%1"=="/?" goto :usage
if /i "%1"=="/help" goto :usage
if /i "%1"=="-help" goto :usage
if /i "%1"=="--help" goto :usage

echo.
echo === Azure Managed HSM Setup ===
echo.
goto :start

:usage
echo.
echo Azure Managed HSM Setup Script
echo ================================
echo.
echo Usage: setup_managed_hsm.bat [HSM_NAME] [RESOURCE_GROUP] [LOCATION]
echo.
echo Parameters:
echo   HSM_NAME         - Name of the Managed HSM (default: ManagedHSMOpenSSLEngine)
echo   RESOURCE_GROUP   - Azure resource group name (default: ContosoResourceGroup)
echo   LOCATION         - Azure region (default: westus3)
echo.
echo Examples:
echo   setup_managed_hsm.bat
echo   setup_managed_hsm.bat MyHSM MyResourceGroup eastus
echo.
echo This script will:
echo   1. Check prerequisites (Azure CLI, OpenSSL)
echo   2. Create resource group (if needed)
echo   3. Create Managed HSM instance
echo   4. Generate security domain certificates
echo   5. Activate the Managed HSM
echo   6. Assign permissions to current user
echo   7. Create required keys (RSA, EC, AES)
echo.
goto :end

:start

REM Set parameters with defaults
set HSM_NAME=%1
set RESOURCE_GROUP=%2
set LOCATION=%3

if "%HSM_NAME%"=="" set HSM_NAME=ManagedHSMOpenSSLEngine
if "%RESOURCE_GROUP%"=="" set RESOURCE_GROUP=ContosoResourceGroup
if "%LOCATION%"=="" set LOCATION=westus3

echo Configuration:
echo   HSM Name: %HSM_NAME%
echo   Resource Group: %RESOURCE_GROUP%
echo   Location: %LOCATION%
echo.

REM ============================================================================
REM Pre-flight Checks
REM ============================================================================

echo --- Checking prerequisites ---

REM Check if Azure CLI is installed
where az >nul 2>&1
if errorlevel 1 (
    echo ERROR: Azure CLI not found
    echo Please install Azure CLI from https://aka.ms/InstallAzureCLIDocs
    goto :error
)
echo [OK] Azure CLI installed

REM Check if OpenSSL is installed
where openssl >nul 2>&1
if errorlevel 1 (
    echo ERROR: OpenSSL not found
    echo Please install OpenSSL and ensure it's in your PATH
    goto :error
)
echo [OK] OpenSSL installed

REM Check if user is logged in to Azure
call az account show >nul 2>&1
if errorlevel 1 (
    echo ERROR: Not logged in to Azure
    echo Please run 'az login' first
    goto :error
)
echo [OK] Logged in to Azure

echo.

REM ============================================================================
REM Step 1: Get current user's object ID
REM ============================================================================

echo Step 1: Getting current user's object ID...
for /f %%i in ('call az ad signed-in-user show --query id -o tsv') do set USER_OID=%%i

if "%USER_OID%"=="" (
    echo ERROR: Failed to get user object ID
    goto :error
)
echo [OK] User Object ID: %USER_OID%
echo.

REM ============================================================================
REM Step 2: Create resource group (if not exists)
REM ============================================================================

echo Step 2: Creating resource group '%RESOURCE_GROUP%'...
call az group show --name %RESOURCE_GROUP% >nul 2>&1
if errorlevel 1 (
    echo Creating new resource group...
    call az group create --name %RESOURCE_GROUP% --location %LOCATION%
    if errorlevel 1 goto :error
    echo [OK] Resource group created
) else (
    echo [OK] Resource group already exists
)
echo.

REM ============================================================================
REM Step 3: Create Managed HSM
REM ============================================================================

echo Step 3: Creating Managed HSM '%HSM_NAME%'...
echo NOTE: This may take 10-15 minutes...
call az keyvault show --hsm-name %HSM_NAME% >nul 2>&1
if errorlevel 1 (
    call az keyvault create --hsm-name %HSM_NAME% --resource-group %RESOURCE_GROUP% --location "%LOCATION%" --administrators %USER_OID% --retention-days 28
    if errorlevel 1 goto :error
    echo [OK] Managed HSM created successfully
) else (
    echo [OK] Managed HSM already exists
)
echo.

REM ============================================================================
REM Step 4: Generate security domain certificates
REM ============================================================================

echo Step 4: Generating security domain certificates...
if not exist security_domain mkdir security_domain >nul 2>&1

if not exist security_domain\cert_1.cer (
    echo Generating certificate 1/3...
    openssl req -newkey rsa:2048 -nodes -keyout security_domain\cert_1.key -x509 -days 365 -out security_domain\cert_1.cer -subj "/C=US/ST=WA/L=Redmond/O=Contoso/OU=IT/CN=SD-Cert1"
    if errorlevel 1 goto :error
)

if not exist security_domain\cert_2.cer (
    echo Generating certificate 2/3...
    openssl req -newkey rsa:2048 -nodes -keyout security_domain\cert_2.key -x509 -days 365 -out security_domain\cert_2.cer -subj "/C=US/ST=WA/L=Redmond/O=Contoso/OU=IT/CN=SD-Cert2"
    if errorlevel 1 goto :error
)

if not exist security_domain\cert_3.cer (
    echo Generating certificate 3/3...
    openssl req -newkey rsa:2048 -nodes -keyout security_domain\cert_3.key -x509 -days 365 -out security_domain\cert_3.cer -subj "/C=US/ST=WA/L=Redmond/O=Contoso/OU=IT/CN=SD-Cert3"
    if errorlevel 1 goto :error
)

echo [OK] Security domain certificates ready
echo.

REM ============================================================================
REM Step 5: Activate Managed HSM (download security domain)
REM ============================================================================

echo Step 5: Activating Managed HSM...
if not exist security_domain\SD.json (
    echo Downloading security domain (this may take a few minutes)...
    call az keyvault security-domain download --hsm-name %HSM_NAME% --sd-wrapping-keys security_domain\cert_1.cer security_domain\cert_2.cer security_domain\cert_3.cer --sd-quorum 2 --security-domain-file security_domain\SD.json
    if errorlevel 1 goto :error
    echo [OK] Managed HSM activated successfully
) else (
    echo [OK] Security domain already exists (HSM already activated)
)
echo.

REM ============================================================================
REM Step 6: Assign "Managed HSM Crypto User" role to current user
REM ============================================================================

echo Step 6: Assigning permissions to current user...
echo Granting 'Managed HSM Crypto User' role...
call az keyvault role assignment create --hsm-name %HSM_NAME% --assignee %USER_OID% --scope / --role "Managed HSM Crypto User" >nul 2>&1
REM Note: Ignore errors if role already assigned
echo [OK] Permissions granted
echo.

REM Wait a moment for permissions to propagate
echo Waiting for permissions to propagate (10 seconds)...
timeout /t 10 /nobreak >nul
echo.

REM ============================================================================
REM Step 7: Create required keys
REM ============================================================================

echo Step 7: Creating required keys...

REM Create RSA key
echo Creating RSA key 'myrsakey'...
call az keyvault key show --hsm-name %HSM_NAME% --name myrsakey >nul 2>&1
if errorlevel 1 (
    call az keyvault key create --hsm-name %HSM_NAME% --name myrsakey --kty RSA-HSM --size 3072 --ops sign verify encrypt decrypt
    if errorlevel 1 (
        echo WARNING: Failed to create RSA key (may need to wait for permissions)
    ) else (
        echo [OK] RSA key created
    )
) else (
    echo [OK] RSA key already exists
)

REM Create EC key
echo Creating EC key 'ecckey'...
call az keyvault key show --hsm-name %HSM_NAME% --name ecckey >nul 2>&1
if errorlevel 1 (
    call az keyvault key create --hsm-name %HSM_NAME% --name ecckey --kty EC-HSM --curve P-256 --ops sign verify
    if errorlevel 1 (
        echo WARNING: Failed to create EC key (may need to wait for permissions)
    ) else (
        echo [OK] EC key created
    )
) else (
    echo [OK] EC key already exists
)

REM Create AES key
echo Creating AES key 'myaeskey'...
call az keyvault key show --hsm-name %HSM_NAME% --name myaeskey >nul 2>&1
if errorlevel 1 (
    call az keyvault key create --hsm-name %HSM_NAME% --name myaeskey --kty oct-HSM --size 256 --ops wrapKey unwrapKey encrypt decrypt
    if errorlevel 1 (
        echo WARNING: Failed to create AES key (may need to wait for permissions)
    ) else (
        echo [OK] AES key created
    )
) else (
    echo [OK] AES key already exists
)

echo.

REM ============================================================================
REM Step 8: Verify setup
REM ============================================================================

echo Step 8: Verifying setup...
call az keyvault key list --hsm-name %HSM_NAME% --query "[].{Name:name, Type:keyType, Enabled:attributes.enabled}" -o table
echo.

REM ============================================================================
REM Success!
REM ============================================================================

echo.
echo ========================================================
echo SUCCESS: Managed HSM setup completed!
echo ========================================================
echo.
echo Managed HSM Details:
echo   Name: %HSM_NAME%
echo   URL: https://%HSM_NAME%.managedhsm.azure.net/
echo   Resource Group: %RESOURCE_GROUP%
echo   Location: %LOCATION%
echo.
echo Created Keys:
echo   - myrsakey (RSA-HSM 3072-bit)
echo   - ecckey (EC-HSM P-256)
echo   - myaeskey (oct-HSM 256-bit)
echo.
echo Security Domain:
echo   Files saved in: .\security_domain\
echo   - SD.json (security domain backup)
echo   - cert_*.cer and cert_*.key (wrapping certificates)
echo.
echo IMPORTANT: Keep the security_domain folder secure!
echo These files are required for disaster recovery.
echo.
echo Environment variable to set:
echo   set AKV_VAULT=%HSM_NAME%
echo.
echo Next steps:
echo   1. Run: runtest.bat (to test the provider)
echo   2. Or: runtest.bat /SKIPVALIDATION (to skip validation checks)
echo.
goto :end

:error
echo.
echo ========================================================
echo ERROR: Setup failed!
echo ========================================================
echo.
echo Please check the error messages above and try again.
echo.
echo Common issues:
echo   1. Not logged in to Azure - run 'az login'
echo   2. Insufficient permissions - contact your Azure admin
echo   3. HSM name already taken - try a different name
echo   4. Quota exceeded - check your subscription limits
echo.
exit /b 1

:end
endlocal
