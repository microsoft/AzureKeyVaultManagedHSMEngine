@echo off
REM Bootstrap OpenSSL static libraries for Rust provider build
REM This script sets up vcpkg and installs OpenSSL static libraries

setlocal enabledelayedexpansion

echo ========================================
echo Bootstrap OpenSSL for Rust Provider
echo ========================================
echo.

REM Check if vcpkg is already installed
set VCPKG_DIR=%~dp0vcpkg
set OPENSSL_DIR=%~dp0vcpkg_installed\x64-windows-static

if exist "%VCPKG_DIR%\vcpkg.exe" (
    echo [OK] vcpkg found at %VCPKG_DIR%
) else (
    echo Installing vcpkg...
    git clone https://github.com/Microsoft/vcpkg.git "%VCPKG_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to clone vcpkg
        exit /b 1
    )
    
    echo Bootstrapping vcpkg...
    call "%VCPKG_DIR%\bootstrap-vcpkg.bat"
    if errorlevel 1 (
        echo [ERROR] Failed to bootstrap vcpkg
        exit /b 1
    )
    echo [OK] vcpkg installed
)

echo.
echo Checking OpenSSL installation...
if exist "%OPENSSL_DIR%\lib\libssl.lib" (
    echo [OK] OpenSSL static libraries already installed
    echo      Location: %OPENSSL_DIR%
    goto :update_config
)

echo Installing OpenSSL static libraries...
echo This may take several minutes...
"%VCPKG_DIR%\vcpkg.exe" install openssl:x64-windows-static
if errorlevel 1 (
    echo [ERROR] Failed to install OpenSSL
    exit /b 1
)

echo [OK] OpenSSL installed successfully

echo.
echo ========================================
echo Bootstrap Complete!
echo ========================================
echo.
echo OpenSSL Location: %OPENSSL_DIR%
echo.
echo To build, use winbuild.bat (recommended):
echo      winbuild.bat
echo.
echo Or set environment and build manually:
echo      set OPENSSL_DIR=%OPENSSL_DIR%
echo      set OPENSSL_STATIC=1
echo      cargo build --release
echo.

endlocal
exit /b 0
