@echo off
REM ========================================
REM Windows Build Script for Rust Provider
REM ========================================
REM This script checks dependencies and builds the provider

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
set AUTO_DEPLOY=0

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--debug" set BUILD_TYPE=debug
if /i "%~1"=="--skip-deps" set SKIP_DEPS_CHECK=1
if /i "%~1"=="--deploy" set AUTO_DEPLOY=1
shift
goto parse_args
:args_done

REM ========================================
REM 1. Check Rust toolchain
REM ========================================
echo [1/4] Checking Rust toolchain...
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
    echo [2/4] Skipping dependency checks...
    goto :build
)

echo [2/4] Checking OpenSSL dependencies...

REM Check if OPENSSL_DIR is already set
if defined OPENSSL_DIR (
    echo [INFO] OPENSSL_DIR already set: %OPENSSL_DIR%
    if exist "%OPENSSL_DIR%\lib\libssl.lib" (
        echo [OK] OpenSSL found at %OPENSSL_DIR%
        goto :openssl_ok
    ) else (
        echo [WARNING] OPENSSL_DIR set but libssl.lib not found
    )
)

REM Try parent directory's vcpkg installation
set PARENT_OPENSSL=%~dp0..\src_provider\vcpkg_installed\x64-windows-static
if exist "%PARENT_OPENSSL%\lib\libssl.lib" (
    echo [OK] Found OpenSSL in parent directory
    echo      %PARENT_OPENSSL%
    set OPENSSL_DIR=%PARENT_OPENSSL%
    goto :openssl_ok
)

REM Try local vcpkg installation
set LOCAL_OPENSSL=%~dp0vcpkg_installed\x64-windows-static
if exist "%LOCAL_OPENSSL%\lib\libssl.lib" (
    echo [OK] Found OpenSSL in local directory
    echo      %LOCAL_OPENSSL%
    set OPENSSL_DIR=%LOCAL_OPENSSL%
    goto :openssl_ok
)

REM OpenSSL not found - offer to install
echo.
echo [WARNING] OpenSSL not found!
echo.
echo Available options:
echo   1. Install OpenSSL locally (takes ~10 minutes, ~500MB)
echo   2. Use parent directory's OpenSSL (if src_provider is built)
echo   3. Set OPENSSL_DIR environment variable manually
echo.
choice /C 12 /N /M "Choose option (1 or 2): "

if errorlevel 2 goto :use_parent
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

:use_parent
echo.
echo Using parent directory's OpenSSL...
if exist "%~dp0bootstrap_openssl.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0bootstrap_openssl.ps1" -UseParent
    if errorlevel 1 goto :error
    
    set OPENSSL_DIR=%PARENT_OPENSSL%
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
REM 3. Check Visual Studio Build Tools
REM ========================================
echo [3/4] Checking Visual Studio Build Tools...

REM Check if we're already in a VS Developer environment
if defined VSINSTALLDIR (
    echo [OK] Visual Studio environment detected
    goto :build
)

REM Try to find and run vcvarsall.bat
set VS_YEAR=2022
set VS_EDITION=Enterprise

for %%e in (Enterprise Professional Community BuildTools) do (
    set VS_PATH=C:\Program Files\Microsoft Visual Studio\%VS_YEAR%\%%e\VC\Auxiliary\Build\vcvarsall.bat
    if exist "!VS_PATH!" (
        echo [OK] Found Visual Studio %%e
        call "!VS_PATH!" x64
        goto :build
    )
)

echo [WARNING] Visual Studio Build Tools not found
echo           Build may fail if C/C++ compilation is required
echo           Install from: https://visualstudio.microsoft.com/downloads/

REM ========================================
REM 4. Build
REM ========================================
REM 4. Build
REM ========================================
:build
echo [4/4] Building provider...
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
    
    REM Deploy if requested
    if "%AUTO_DEPLOY%"=="1" (
        call :deploy_provider "%DLL_PATH%"
        if errorlevel 1 (
            echo.
            echo [WARNING] Deployment failed, but build was successful
        )
    ) else (
        echo To deploy:
        echo   winbuild.bat --deploy
        echo   or manually: copy "%DLL_PATH%" "C:\OpenSSL\lib\ossl-modules\"
        echo.
        echo To test:
        echo   cd "%~dp0"
        echo   runtest.bat
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

REM Get OpenSSL modules directory
for /f "usebackq delims=" %%i in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0get_modules_dir.ps1"`) do set MODULES_DIR=%%i

if not defined MODULES_DIR (
    echo [ERROR] Could not detect OpenSSL modules directory
    echo         Run 'openssl version -a' to check your OpenSSL installation
    exit /b 1
)

echo [INFO] OpenSSL modules directory: %MODULES_DIR%

REM Check if directory exists
if not exist "%MODULES_DIR%" (
    echo [ERROR] Modules directory does not exist: %MODULES_DIR%
    echo         Please check your OpenSSL installation
    exit /b 1
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
echo To test the deployment:
echo   cd "%~dp0"
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
