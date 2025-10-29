# Bootstrap OpenSSL static libraries for Rust provider build
# This script sets up vcpkg and installs OpenSSL static libraries

param(
    [switch]$UseParent = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Bootstrap OpenSSL for Rust Provider" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VcpkgDir = Join-Path $ScriptDir "vcpkg"
$OpenSSLDir = Join-Path $ScriptDir "vcpkg_installed\x64-windows-static"
$ParentOpenSSLDir = Join-Path $ScriptDir "..\src_provider\vcpkg_installed\x64-windows-static"

# Check if user wants to use parent directory's OpenSSL
if ($UseParent -and (Test-Path $ParentOpenSSLDir)) {
    Write-Host "[INFO] Using parent directory's OpenSSL installation" -ForegroundColor Yellow
    $OpenSSLDir = (Resolve-Path $ParentOpenSSLDir).Path
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Bootstrap Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "OpenSSL Location: $OpenSSLDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "To build, use winbuild.bat (recommended):" -ForegroundColor Yellow
    Write-Host "     .\winbuild.bat" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Or set environment and build manually:" -ForegroundColor Yellow
    Write-Host "     `$env:OPENSSL_DIR='$OpenSSLDir'" -ForegroundColor Gray
    Write-Host "     `$env:OPENSSL_STATIC='1'" -ForegroundColor Gray
    Write-Host "     cargo build --release" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# Check if vcpkg is already installed locally
if (Test-Path (Join-Path $VcpkgDir "vcpkg.exe")) {
    Write-Host "[OK] vcpkg found at $VcpkgDir" -ForegroundColor Green
} else {
    Write-Host "Installing vcpkg..." -ForegroundColor Yellow
    git clone https://github.com/Microsoft/vcpkg.git $VcpkgDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to clone vcpkg" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Bootstrapping vcpkg..." -ForegroundColor Yellow
    & "$VcpkgDir\bootstrap-vcpkg.bat"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to bootstrap vcpkg" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] vcpkg installed" -ForegroundColor Green
}

Write-Host ""
Write-Host "Checking OpenSSL installation..." -ForegroundColor Yellow

if (Test-Path (Join-Path $OpenSSLDir "lib\libssl.lib")) {
    Write-Host "[OK] OpenSSL static libraries already installed" -ForegroundColor Green
    Write-Host "     Location: $OpenSSLDir" -ForegroundColor Gray
} else {
    Write-Host "Installing OpenSSL static libraries..." -ForegroundColor Yellow
    Write-Host "This may take several minutes..." -ForegroundColor Yellow
    
    $InstallRoot = Join-Path $ScriptDir "vcpkg_installed"
    & "$VcpkgDir\vcpkg.exe" install openssl:x64-windows-static --x-install-root="$InstallRoot"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install OpenSSL" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[OK] OpenSSL installed successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Bootstrap Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "OpenSSL Location: $OpenSSLDir" -ForegroundColor Green
Write-Host ""
Write-Host "To build, use winbuild.bat (recommended):" -ForegroundColor Yellow
Write-Host "     .\winbuild.bat" -ForegroundColor Yellow
Write-Host ""
Write-Host "Or set environment and build manually:" -ForegroundColor Yellow
Write-Host "     `$env:OPENSSL_DIR='$OpenSSLDir'" -ForegroundColor Gray
Write-Host "     `$env:OPENSSL_STATIC='1'" -ForegroundColor Gray
Write-Host "     cargo build --release" -ForegroundColor Gray
Write-Host ""
Write-Host "Tip: To use parent directory's OpenSSL instead, run:" -ForegroundColor Gray
Write-Host "     .\bootstrap_openssl.ps1 -UseParent" -ForegroundColor Gray
Write-Host ""
