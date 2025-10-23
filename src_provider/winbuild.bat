@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Automated Build Script for Azure Key Vault Managed HSM OpenSSL Provider
REM ============================================================================

REM If VCPKG_ROOT not set, try to auto-detect or install vcpkg
if not defined VCPKG_ROOT (
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
            if errorlevel 1 (
                echo ERROR: Failed to clone vcpkg repository
                echo Please ensure git is installed and accessible
                goto end
            )
            
            REM Bootstrap vcpkg
            echo Bootstrapping vcpkg...
            call "%USERPROFILE%\vcpkg\bootstrap-vcpkg.bat"
            if errorlevel 1 (
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
if not exist "!VCPKG_ROOT!\.vcpkg-root" (
    echo ERROR: !VCPKG_ROOT! does not appear to be a valid vcpkg installation
    echo The .vcpkg-root file is missing
    goto end
)

REM Check if vcpkg executable exists
set "VCPKG_EXE=!VCPKG_ROOT!\vcpkg.exe"
if not exist "!VCPKG_EXE!" (
    echo ERROR: vcpkg.exe not found at !VCPKG_EXE!
    echo Attempting to bootstrap vcpkg...
    call "!VCPKG_ROOT!\bootstrap-vcpkg.bat"
    if errorlevel 1 (
        echo ERROR: Failed to bootstrap vcpkg
        goto end
    )
)

echo.
echo ========================================================
echo Using vcpkg: !VCPKG_ROOT!
echo ========================================================
echo.

REM Check if this is the VS Build Tools vcpkg (which may have compatibility issues)
echo !VCPKG_ROOT! | findstr /C:"Visual Studio" >nul
if %ERRORLEVEL% EQU 0 (
    echo WARNING: You are using vcpkg from Visual Studio Build Tools
    echo This version may have compatibility issues with manifest mode.
    echo.
    echo For best results, consider using a standalone vcpkg:
    echo   1. git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
    echo   2. C:\vcpkg\bootstrap-vcpkg.bat
    echo   3. set VCPKG_ROOT=C:\vcpkg
    echo.
    set /p CONTINUE="Do you want to continue anyway? (Y/N): "
    if /i not "!CONTINUE!"=="Y" (
        echo Build cancelled
        goto end
    )
    echo.
)

REM Install required vcpkg packages if not present
echo Checking and installing required dependencies...
echo.

REM Use vcpkg manifest mode - install from vcpkg.json
echo Installing dependencies from vcpkg.json (static libraries)...
"!VCPKG_EXE!" install --triplet=x64-windows-static
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    echo.
    echo If you encounter manifest mode issues, try installing a standalone vcpkg:
    echo   git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
    echo   C:\vcpkg\bootstrap-vcpkg.bat
    echo   set VCPKG_ROOT=C:\vcpkg
    goto end
)

REM Set package paths for manifest mode (static triplet)
set "PKG_OPENSSL=!CD!\vcpkg_installed\x64-windows-static"
set "PKG_CURL=!CD!\vcpkg_installed\x64-windows-static"
set "PKG_JSON=!CD!\vcpkg_installed\x64-windows-static"
set "PKG_ZLIB=!CD!\vcpkg_installed\x64-windows-static"

echo All dependencies installed successfully

echo.
echo ========================================================
echo All dependencies are ready
echo ========================================================
echo.

REM Build the project
echo Building akv_provider.dll...
echo.
msbuild akv_provider.vcxproj /p:PkgOpenssl="!PKG_OPENSSL!" /p:PkgCurl="!PKG_CURL!" /p:PkgJson="!PKG_JSON!" /p:PkgZ="!PKG_ZLIB!" /p:Configuration=Release /p:Platform=x64 /v:minimal

if errorlevel 1 (
    echo.
    echo ========================================================
    echo Build failed with error code %ERRORLEVEL%
    echo ========================================================
    echo.
) else (
    echo.
    echo ========================================================
    echo Build successful!
    echo ========================================================
    echo Output: x64\Release\akv_provider.dll (statically linked)
    echo.
    echo To deploy, copy the DLL to OpenSSL modules directory:
    echo   copy x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
    echo.
    echo Note: The DLL is statically linked with all dependencies.
    echo No additional DLLs need to be deployed.
    echo.
)

:end
endlocal
