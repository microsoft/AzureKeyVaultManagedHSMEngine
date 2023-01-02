@echo off
if "%VCPKG_ROOT%" == "" (
	echo.Please set VCPKG_ROOT
    goto end
)
msbuild  e_akv.vcxproj /p:PkgOpenssl="%VCPKG_ROOT%\packages\openssl_x64-windows" /p:PkgCurl="%VCPKG_ROOT%\packages\curl_x64-windows-static" /p:PkgJson="%VCPKG_ROOT%\packages\json-c_x64-windows-static" /p:PkgZ="%VCPKG_ROOT%\packages\zlib_x64-windows-static" /p:Configuration=Release;Platform=x64
:end
