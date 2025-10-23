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
## Required Dependencies

The build script will automatically install these via vcpkg as **static libraries** if not present:

- **openssl:x64-windows-static** - OpenSSL 3.x provider API
- **curl[core,ssl]:x64-windows-static** - Azure REST API client
- **json-c:x64-windows-static** - JSON parsing
- **zlib:x64-windows-static** - Compression (curl dependency)

All dependencies are statically linked into the final DLL, so no additional DLLs need to be deployed.

## Building

### Option 1: Using winbuild.bat (Recommended)

This script fully automates the build process:

```cmd
cd src_provider
winbuild.bat
```

The script will:
1. Automatically detect or install vcpkg if needed
2. Install missing dependencies as static libraries
3. Build the provider DLL (statically linked)

### Option 2: Visual Studio IDE

1. Open `akv_provider.vcxproj` in Visual Studio 2022
2. Set the following MSBuild properties (Project Properties → Configuration Properties → User Macros):
1. Open `akv_provider.vcxproj` in Visual Studio 2022
2. Build → Build Solution (Ctrl+Shift+B)

Note: Ensure vcpkg dependencies are already installed before using the IDE.

## Output

The compiled provider will be at:
```
x64\Release\akv_provider.dll
```

This is a **single, self-contained DLL** with all dependencies statically linked.

## Deployment

To deploy the provider to OpenSSL:

```cmd
copy x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
```

**That's it!** No additional DLLs need to be copied since everything is statically linked.

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
