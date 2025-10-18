cmake_minimum_required(VERSION 3.15)

project(akv_provider C)

set(akv_provider_sources
    akv_provider.c
    akv_keymgmt.c
    akv_signature.c
    akv_cipher.c
    akv_logging.c
    base64.c
    curl.c
)

add_library(akv_provider SHARED ${akv_provider_sources})
set_target_properties(akv_provider PROPERTIES OUTPUT_NAME akv_provider)

target_include_directories(akv_provider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(CRYPTO_LIB NAMES crypto libcrypto REQUIRED)
find_library(SSL_LIB NAMES ssl libssl REQUIRED)
find_library(CURL_LIB NAMES curl libcurl REQUIRED)
find_library(JSONC_LIB NAMES json-c libjson-c REQUIRED)

if (WIN32)
    target_compile_definitions(akv_provider PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

target_link_libraries(akv_provider
    PRIVATE
    ${CRYPTO_LIB}
    ${SSL_LIB}
    ${CURL_LIB}
    ${JSONC_LIB}
)
