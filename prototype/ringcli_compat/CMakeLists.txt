cmake_minimum_required(VERSION 3.16)
project(ry02_ringcli_compat C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(ry02_ringcli_protocol STATIC
    src/ry02_ringcli_protocol.c
    bluex/ry02_bluex_adapter_contract.c
)

target_include_directories(ry02_ringcli_protocol PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bluex
)

target_compile_options(ry02_ringcli_protocol PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wpedantic
)

add_executable(test_ry02_ringcli_protocol
    tests/test_protocol.c
)

target_link_libraries(test_ry02_ringcli_protocol PRIVATE
    ry02_ringcli_protocol
)

target_compile_options(test_ry02_ringcli_protocol PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wpedantic
)

enable_testing()
add_test(NAME ry02_ringcli_protocol COMMAND test_ry02_ringcli_protocol)
