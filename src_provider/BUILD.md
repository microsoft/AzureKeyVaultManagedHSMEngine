# Building the Azure Key Vault Managed HSM OpenSSL Provider

## Prerequisites

1. **Visual Studio 2022** with C++ development tools
2. **vcpkg** package manager

## Setup vcpkg

If you don't have vcpkg installed:

```cmd
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
set VCPKG_ROOT=C:\vcpkg
```

Or set `VCPKG_ROOT` to your existing vcpkg installation:

```cmd
set VCPKG_ROOT=C:\path\to\your\vcpkg
```

## Required Dependencies

The build script will automatically install these via vcpkg if not present:

- **openssl:x64-windows** - OpenSSL 3.x provider API
- **curl[core,ssl]:x64-windows-static** - Azure REST API client
- **json-c:x64-windows-static** - JSON parsing
- **zlib:x64-windows-static** - Compression (curl dependency)

## Building

### Option 1: Using build_with_vsdev.bat (Recommended)

This script sets up the Visual Studio environment automatically:

```cmd
cd src_provider
build_with_vsdev.bat
```

The script will:
1. Automatically detect vcpkg in common locations if `VCPKG_ROOT` is not set
2. Install missing dependencies
3. Build the provider DLL

### Option 2: Using winbuild.bat

If you already have a Visual Studio Developer Command Prompt:

```cmd
cd src_provider
set VCPKG_ROOT=C:\path\to\vcpkg
winbuild.bat
```

### Option 3: Visual Studio IDE

1. Open `akv_provider.vcxproj` in Visual Studio 2022
2. Set the following MSBuild properties (Project Properties → Configuration Properties → User Macros):
   - `PkgOpenssl` = `$(VCPKG_ROOT)\packages\openssl_x64-windows`
   - `PkgCurl` = `$(VCPKG_ROOT)\packages\curl_x64-windows-static`
   - `PkgJson` = `$(VCPKG_ROOT)\packages\json-c_x64-windows-static`
   - `PkgZ` = `$(VCPKG_ROOT)\packages\zlib_x64-windows-static`
3. Build → Build Solution (Ctrl+Shift+B)

## Output

The compiled provider will be at:
```
x64\Release\akv_provider.dll
```

## Deployment

To use the provider with OpenSSL:

```cmd
copy x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
```

Or use the path where your OpenSSL installation's provider modules directory is located.

## Troubleshooting

### vcpkg not found
- Ensure `VCPKG_ROOT` is set correctly
- Run `bootstrap-vcpkg.bat` in your vcpkg directory
- Verify `%VCPKG_ROOT%\.vcpkg-root` file exists

### Package installation fails
- Update vcpkg: `git pull` in vcpkg directory
- Clear vcpkg cache: `vcpkg remove <package>` then reinstall

### Build errors
- Ensure Visual Studio 2022 with C++ tools is installed
- Run from "x64 Native Tools Command Prompt for VS 2022"
- Check that all dependencies are properly installed in vcpkg
