@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64
set VCPKG_ROOT=Q:\.tools\CxCache\Microsoft.Build.Vcpkg.2024.7.1.112-afa12e729\tools
cd /d %~dp0
call winbuild.bat %*
