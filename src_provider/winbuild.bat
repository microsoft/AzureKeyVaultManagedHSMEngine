@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Automated Build Script for Azure Key Vault Managed HSM OpenSSL Provider
REM ============================================================================

REM If VCPKG_ROOT not set, try to auto-detect or install vcpkg
if "%VCPKG_ROOT%" == "" (
    echo VCPKG_ROOT not set, attempting auto-detection...
    
    REM Try common locations
    if exist "Q:\.tools\CxCache\Microsoft.Build.Vcpkg.2024.7.1.112-afa12e729\tools\.vcpkg-root" (
        set VCPKG_ROOT=Q:\.tools\CxCache\Microsoft.Build.Vcpkg.2024.7.1.112-afa12e729\tools
        echo Found vcpkg at: !VCPKG_ROOT!
    ) else if exist "C:\vcpkg\.vcpkg-root" (
        set VCPKG_ROOT=C:\vcpkg
        echo Found vcpkg at: !VCPKG_ROOT!
    ) else if exist "%USERPROFILE%\vcpkg\.vcpkg-root" (
        set VCPKG_ROOT=%USERPROFILE%\vcpkg
        echo Found vcpkg at: !VCPKG_ROOT!
    ) else (
        REM vcpkg not found, offer to install it
        echo.
        echo ========================================================
        echo vcpkg not found in common locations
        echo ========================================================
        echo.
        set /p INSTALL_VCPKG="Would you like to install vcpkg to %USERPROFILE%\vcpkg? (Y/N): "
        if /i "!INSTALL_VCPKG!"=="Y" (
            echo.
            echo Installing vcpkg to %USERPROFILE%\vcpkg...
            echo This may take a few minutes...
            
            REM Clone vcpkg
            git clone https://github.com/microsoft/vcpkg.git "%USERPROFILE%\vcpkg"
            if !ERRORLEVEL! NEQ 0 (
                echo ERROR: Failed to clone vcpkg repository
                echo Please ensure git is installed and accessible
                goto end
            )
            
            REM Bootstrap vcpkg
            echo Bootstrapping vcpkg...
            call "%USERPROFILE%\vcpkg\bootstrap-vcpkg.bat"
            if !ERRORLEVEL! NEQ 0 (
                echo ERROR: Failed to bootstrap vcpkg
                goto end
            )
            
            set VCPKG_ROOT=%USERPROFILE%\vcpkg
            echo vcpkg successfully installed at: !VCPKG_ROOT!
        ) else (
            echo.
            echo Please install vcpkg manually:
            echo   git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
            echo   C:\vcpkg\bootstrap-vcpkg.bat
            echo   set VCPKG_ROOT=C:\vcpkg
            echo.
            echo Or set VCPKG_ROOT to your existing installation:
            echo   set VCPKG_ROOT=C:\path\to\vcpkg
            goto end
        )
    )
)

REM Verify vcpkg installation
if not exist "%VCPKG_ROOT%\.vcpkg-root" (
    echo ERROR: %VCPKG_ROOT% does not appear to be a valid vcpkg installation
    echo The .vcpkg-root file is missing
    goto end
)

REM Check if vcpkg executable exists
set VCPKG_EXE=%VCPKG_ROOT%\vcpkg.exe
if not exist "%VCPKG_EXE%" (
    echo ERROR: vcpkg.exe not found at %VCPKG_EXE%
    echo Attempting to bootstrap vcpkg...
    call "%VCPKG_ROOT%\bootstrap-vcpkg.bat"
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: Failed to bootstrap vcpkg
        goto end
    )
)

echo.
echo ========================================================
echo Using vcpkg: %VCPKG_ROOT%
echo ========================================================
echo.

REM Install required vcpkg packages if not present
echo Checking and installing required dependencies...
echo.

set PKG_OPENSSL=%VCPKG_ROOT%\packages\openssl_x64-windows
set PKG_CURL=%VCPKG_ROOT%\packages\curl_x64-windows-static
set PKG_JSON=%VCPKG_ROOT%\packages\json-c_x64-windows-static
set PKG_ZLIB=%VCPKG_ROOT%\packages\zlib_x64-windows-static

if not exist "%PKG_OPENSSL%" (
    echo [1/4] Installing openssl:x64-windows...
    "%VCPKG_EXE%" install openssl:x64-windows
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: Failed to install openssl
        goto end
    )
) else (
    echo [1/4] openssl:x64-windows already installed
)

if not exist "%PKG_CURL%" (
    echo [2/4] Installing curl:x64-windows-static...
    "%VCPKG_EXE%" install curl[core,ssl]:x64-windows-static
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: Failed to install curl
        goto end
    )
) else (
    echo [2/4] curl:x64-windows-static already installed
)

if not exist "%PKG_JSON%" (
    echo [3/4] Installing json-c:x64-windows-static...
    "%VCPKG_EXE%" install json-c:x64-windows-static
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: Failed to install json-c
        goto end
    )
) else (
    echo [3/4] json-c:x64-windows-static already installed
)

if not exist "%PKG_ZLIB%" (
    echo [4/4] Installing zlib:x64-windows-static...
    "%VCPKG_EXE%" install zlib:x64-windows-static
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: Failed to install zlib
        goto end
    )
) else (
    echo [4/4] zlib:x64-windows-static already installed
)

echo.
echo ========================================================
echo All dependencies are ready
echo ========================================================
echo.

REM Build the project
echo Building akv_provider.dll...
echo.
msbuild akv_provider.vcxproj /p:PkgOpenssl="%PKG_OPENSSL%" /p:PkgCurl="%PKG_CURL%" /p:PkgJson="%PKG_JSON%" /p:PkgZ="%PKG_ZLIB%" /p:Configuration=Release /p:Platform=x64 /v:minimal

if !ERRORLEVEL! EQU 0 (
    echo.
    echo ========================================================
    echo Build successful!
    echo ========================================================
    echo Output: x64\Release\akv_provider.dll
    echo.
    echo To deploy, copy the DLL to OpenSSL modules directory:
    echo   copy x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
    echo.
) else (
    echo.
    echo ========================================================
    echo Build failed with error code !ERRORLEVEL!
    echo ========================================================
    echo.
)

:end
endlocal
