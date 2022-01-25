set vcpkg=C:\vcpkg
set vcpkgroot=C:\vcpkg\packages
set protobufroot=%vcpkgroot%\protobuf_x64-windows
set grpcroot=%vcpkgroot%\grpc_x64-windows
IF exist %vcpkg% (
     echo %vcpkg% exists 
) ELSE ( 
    pushd .
    c:
    cd \
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    bootstrap-vcpkg.bat -disableMetrics
    vcpkg.exe install grpc:x64-windows
    vcpkg.exe install protobuf:x64-windows
    vcpkg.exe install abseil:x64-windows
    vcpkg.exe install upb:x64-windows
    vcpkg.exe install re2:x64-windows
    vcpkg.exe install c-ares:x64-windows
    vcpkg.exe install openssl:x64-windows
    vcpkg.exe install zlib:x64-windows-static
    popd
)
pushd .
md build
cd build
copy ..\..\grpc-linux\greeter_server.cpp .
copy ..\..\grpc-linux\greeter_client.cpp .
copy ..\..\grpc-linux\helloworld.proto .
%protobufroot%\tools\protobuf\protoc.exe -I . --grpc_out=. --plugin=protoc-gen-grpc="%grpcroot%\tools\grpc\grpc_cpp_plugin.exe" helloworld.proto
%protobufroot%\tools\protobuf\protoc.exe -I . --cpp_out=. helloworld.proto

copy ..\..\grpc-linux\root.pem .
copy ..\..\grpc-linux\chain.pem .
copy ..\..\grpc-linux\leaf.keyid .


copy ..\start-server.bat .
copy ..\greeter_server.vcxproj .
msbuild greeter_server.vcxproj /p:PkggRPC="%grpcroot%" /p:PkgAbseil="%vcpkgroot%\abseil_x64-windows" /p:PkgProtobuf="%vcpkgroot%\protobuf_x64-windows" /p:PkgUpb="%vcpkgroot%\upb_x64-windows" /p:PkgRe2="%vcpkgroot%\re2_x64-windows" /p:PkgAres="%vcpkgroot%\c-ares_x64-windows" /p:PkgZ="%vcpkgroot%\zlib_x64-windows-static" /p:PkgOpenssl="%vcpkgroot%\openssl_x64-windows" /p:Configuration=Release;Platform=x64

copy ..\start-client.bat .
copy ..\greeter_client.vcxproj .
msbuild greeter_client.vcxproj /p:PkggRPC="%grpcroot%" /p:PkgAbseil="%vcpkgroot%\abseil_x64-windows" /p:PkgProtobuf="%vcpkgroot%\protobuf_x64-windows" /p:PkgUpb="%vcpkgroot%\upb_x64-windows" /p:PkgRe2="%vcpkgroot%\re2_x64-windows" /p:PkgAres="%vcpkgroot%\c-ares_x64-windows" /p:PkgZ="%vcpkgroot%\zlib_x64-windows-static" /p:PkgOpenssl="%vcpkgroot%\openssl_x64-windows" /p:Configuration=Release;Platform=x64

popd