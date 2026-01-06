@echo off
REM ========================================
REM Windows Build Script for Rust Provider
REM ========================================
REM This script checks dependencies, builds, and deploys the provider

setlocal enabledelayedexpansion

echo.
echo ========================================
echo Azure Managed HSM OpenSSL Provider
echo Rust Implementation - Build Script
echo ========================================
echo.

REM Parse command line arguments
set BUILD_TYPE=release
set SKIP_DEPS_CHECK=0

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--debug" set BUILD_TYPE=debug
if /i "%~1"=="--skip-deps" set SKIP_DEPS_CHECK=1
shift
goto parse_args
:args_done

REM ========================================
REM 1. Check Rust toolchain
REM ========================================
echo [1/3] Checking Rust toolchain...
where cargo >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Rust toolchain not found!
    echo Please install Rust from: https://rustup.rs/
    goto :error
)

for /f "tokens=2" %%i in ('cargo --version') do (
    echo [OK] Cargo %%i found
    goto :rust_ok
)
:rust_ok

REM ========================================
REM 2. Check/Setup OpenSSL
REM ========================================
if "%SKIP_DEPS_CHECK%"=="1" (
    echo [2/3] Skipping dependency checks...
    goto :build
)

echo [2/3] Checking OpenSSL dependencies...

REM First check local vcpkg installation
set LOCAL_OPENSSL=%~dp0vcpkg_installed\x64-windows-static
if exist "%LOCAL_OPENSSL%\lib\libssl.lib" (
    echo [OK] Found OpenSSL in local directory
    echo      %LOCAL_OPENSSL%
    set OPENSSL_DIR=%LOCAL_OPENSSL%
    goto :openssl_ok
)

REM Then check if OPENSSL_DIR is already set
if defined OPENSSL_DIR (
    echo [INFO] OPENSSL_DIR already set: %OPENSSL_DIR%
    if exist "%OPENSSL_DIR%\lib\libssl.lib" (
        echo [OK] OpenSSL found at %OPENSSL_DIR%
        goto :openssl_ok
    ) else (
        echo [WARNING] OPENSSL_DIR set but libssl.lib not found
    )
)

REM OpenSSL not found - offer to install
echo.
echo [WARNING] OpenSSL not found!
echo.
echo This will install OpenSSL locally via vcpkg (~10 minutes, ~500MB)
echo.
choice /C YN /M "Install OpenSSL now?"

if errorlevel 2 goto :error
if errorlevel 1 goto :install_local

:install_local
echo.
echo Installing OpenSSL locally via vcpkg...
if exist "%~dp0bootstrap_openssl.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0bootstrap_openssl.ps1"
    if errorlevel 1 goto :error
    
    REM Reload config after bootstrap
    set LOCAL_OPENSSL=%~dp0vcpkg_installed\x64-windows-static
    set OPENSSL_DIR=%LOCAL_OPENSSL%
    goto :openssl_ok
) else (
    echo [ERROR] bootstrap_openssl.ps1 not found!
    goto :error
)

:openssl_ok
REM Set OPENSSL_STATIC for static linking
set OPENSSL_STATIC=1
echo [OK] OpenSSL configuration complete

REM ========================================
REM 3. Build
REM ========================================
:build
echo [3/3] Building provider...
echo.

REM Set OpenSSL environment variables for cargo
if defined OPENSSL_DIR (
    echo [INFO] Setting OPENSSL_DIR=%OPENSSL_DIR%
    echo [INFO] Setting OPENSSL_STATIC=1
)
set OPENSSL_STATIC=1

if "%BUILD_TYPE%"=="debug" (
    echo Building in DEBUG mode...
    cargo build
) else (
    echo Building in RELEASE mode...
    cargo build --release
)

if errorlevel 1 goto :error

echo.
echo ========================================
echo Build Successful!
echo ========================================
echo.

if "%BUILD_TYPE%"=="debug" (
    set DLL_PATH=%~dp0target\debug\akv_provider.dll
) else (
    set DLL_PATH=%~dp0target\release\akv_provider.dll
)

echo Provider DLL: %DLL_PATH%
echo.

if exist "%DLL_PATH%" (
    for %%A in ("%DLL_PATH%") do (
        echo Size: %%~zA bytes
    )
    echo.
    
    REM Always deploy after successful build
    call :deploy_provider "%DLL_PATH%"
    if errorlevel 1 (
        echo.
        echo [WARNING] Deployment failed, but build was successful
        echo To deploy manually: copy "%DLL_PATH%" "C:\OpenSSL\lib\ossl-modules\"
    )
)

goto :end

REM ========================================
REM Deploy provider to OpenSSL modules dir
REM ========================================
:deploy_provider
set SRC_DLL=%~1

echo ========================================
echo Deploying Provider
echo ========================================
echo.

REM Use hardcoded OpenSSL modules directory
set MODULES_DIR=C:\OpenSSL\lib\ossl-modules

echo [INFO] OpenSSL modules directory: %MODULES_DIR%

REM Create directory if it doesn't exist
if not exist "%MODULES_DIR%" (
    echo [INFO] Creating modules directory: %MODULES_DIR%
    mkdir "%MODULES_DIR%" 2>nul
    if errorlevel 1 (
        echo [ERROR] Failed to create modules directory
        echo         You may need administrator privileges
        exit /b 1
    )
)

REM Copy the DLL
echo [INFO] Copying %SRC_DLL%
echo        to %MODULES_DIR%\akv_provider.dll
copy /Y "%SRC_DLL%" "%MODULES_DIR%\akv_provider.dll" >nul

if errorlevel 1 (
    echo [ERROR] Failed to copy provider DLL
    echo         You may need administrator privileges
    echo         Try running this command manually:
    echo         copy "%SRC_DLL%" "%MODULES_DIR%\akv_provider.dll"
    exit /b 1
)

echo [OK] Provider deployed successfully!
echo.
echo ========================================
echo Ready to Test!
echo ========================================
echo.
echo Run tests with:
echo   runtest.bat
echo.

exit /b 0

REM ========================================
REM Error handling
REM ========================================
:error
echo.
echo ========================================
echo Build Failed!
echo ========================================
echo.
exit /b 1

:end
endlocal
exit /b 0
