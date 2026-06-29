cmake_minimum_required(VERSION 3.20)
project(sedsprintf_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

find_path(ZSTD_INCLUDE_DIR zstd.h HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(ZSTD_LIBRARY zstd HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(_SEDSNET_TESTS_DEFAULT ON)
else()
  set(_SEDSNET_TESTS_DEFAULT OFF)
endif()
option(SEDSNET_ENABLE_TESTS "Build SEDSnet C++ tests" ${_SEDSNET_TESTS_DEFAULT})

set(SEDSNET_DIR_DEFAULT "${CMAKE_CURRENT_LIST_DIR}/")
set(SEDSNET_DIR "${SEDSNET_DIR_DEFAULT}" CACHE PATH "Path to sedsnet C++ port root")
set(SEDSNET_DEVICE_IDENTIFIER "" CACHE STRING "Device identifier override")
set(SEDSNET_MAX_STACK_PAYLOAD "" CACHE STRING "Maximum stack payload override")
set(SEDSNET_MAX_QUEUE_BUDGET "" CACHE STRING "Shared queue budget in bytes")
set(SEDSNET_MAX_QUEUE_SIZE "" CACHE STRING "Legacy alias for SEDSNET_MAX_QUEUE_BUDGET")
set(SEDSNET_MAX_RECENT_RX_IDS "" CACHE STRING "Maximum recent packet ID entries")
set(SEDSNET_SCHEMA_PATH "" CACHE STRING "Runtime telemetry schema seed path")
set(SEDSNET_IPC_SCHEMA_PATH "" CACHE STRING "Runtime IPC/link-local schema seed path")
option(SEDSNET_EMBEDDED_BUILD "Build sedsnet for embedded" OFF)
option(SEDSNET_PREFER_DYNAMIC "Prefer dynamic linking for host builds when supported" ON)
option(SEDSNET_FORCE_RELEASE "Build release profile even when parent CMake build is Debug" OFF)
option(SEDSNET_ENABLE_C_WRAPPER "Build the optional native C wrapper target sedsnet::c_wrapper" OFF)
option(SEDSNET_ENABLE_CPP_WRAPPER "Expose the optional C++ convenience target sedsnet::cpp_wrapper" OFF)
option(SEDSNET_ENABLE_EXAMPLES "Build SEDSnet example programs" OFF)
option(SEDSNET_ENABLE_CRYPTOGRAPHY "Enable cryptography provider APIs and define SEDS_ENABLE_CRYPTOGRAPHY" ON)
if(NOT SEDSNET_MAX_QUEUE_BUDGET AND SEDSNET_MAX_QUEUE_SIZE)
  set(SEDSNET_MAX_QUEUE_BUDGET "${SEDSNET_MAX_QUEUE_SIZE}")
endif()
if(SEDSNET_MAX_QUEUE_BUDGET)
  add_compile_definitions(SEDSPRINTF_MAX_QUEUE_BUDGET=${SEDSNET_MAX_QUEUE_BUDGET})
endif()
if(SEDSNET_MAX_RECENT_RX_IDS)
  add_compile_definitions(SEDSPRINTF_MAX_RECENT_RX_IDS=${SEDSNET_MAX_RECENT_RX_IDS})
endif()

set(SEDSPRINTF_SCHEMA_PATH "" CACHE STRING "Optional path to compile-time telemetry schema JSON")
set(SEDSPRINTF_IPC_SCHEMA_PATH "" CACHE STRING "Optional path to IPC overlay schema JSON")
set(SEDSNET_TEST_SCHEMA_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/default_test_schema.json" CACHE STRING "Schema fixture used by this repository's tests")
if(SEDSNET_SCHEMA_PATH)
  set(SEDSPRINTF_SCHEMA_PATH "${SEDSNET_SCHEMA_PATH}" CACHE STRING "Optional path to compile-time telemetry schema JSON" FORCE)
endif()
if(SEDSNET_IPC_SCHEMA_PATH)
  set(SEDSPRINTF_IPC_SCHEMA_PATH "${SEDSNET_IPC_SCHEMA_PATH}" CACHE STRING "Optional path to IPC overlay schema JSON" FORCE)
endif()
set(SEDSPRINTF_HEADER_BASE "${CMAKE_CURRENT_SOURCE_DIR}/sedsprintf.h")
set(SEDSPRINTF_ABI_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/sedsprintf.h" CACHE STRING "Header source used to extract ABI declarations and result enum")
option(SEDSPRINTF_ENABLE_TIMESYNC "Enable built-in time sync schema generation" ON)
option(SEDSPRINTF_ENABLE_DISCOVERY "Enable built-in discovery schema generation" ON)
set(SEDSPRINTF_C_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/C-Headers" CACHE PATH "Directory for the generated public C ABI header")
set(SEDSPRINTF_CPP_SOURCE_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Cpp-Headers")
set(SEDSPRINTF_CPP_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/Cpp-Headers" CACHE PATH "Directory for generated C++ metadata headers")
set(SEDSPRINTF_GENERATED_HEADER "${SEDSPRINTF_C_HEADER_DIR}/sedsprintf.h")
set(SEDSNET_GENERATED_HEADER "${SEDSPRINTF_C_HEADER_DIR}/sedsnet.h")
set(SEDSPRINTF_GENERATED_SCHEMA_HPP "${SEDSPRINTF_CPP_HEADER_DIR}/generated_schema.hpp")
set(SEDSPRINTF_EFFECTIVE_SCHEMA_PATH "${SEDSPRINTF_SCHEMA_PATH}")
if(NOT SEDSPRINTF_EFFECTIVE_SCHEMA_PATH AND SEDSNET_ENABLE_TESTS)
  set(SEDSPRINTF_EFFECTIVE_SCHEMA_PATH "${SEDSNET_TEST_SCHEMA_PATH}")
endif()

set(SEDSPRINTF_CODEGEN_ARGS
    --header-base "${SEDSPRINTF_HEADER_BASE}"
    --header-out "${SEDSPRINTF_GENERATED_HEADER}"
    --public-header-out "${SEDSNET_GENERATED_HEADER}"
    --schema-out "${SEDSPRINTF_GENERATED_SCHEMA_HPP}"
    --abi-source "${SEDSPRINTF_ABI_SOURCE}"
    --result-source "${SEDSPRINTF_ABI_SOURCE}"
    --enable-timesync "$<IF:$<BOOL:${SEDSPRINTF_ENABLE_TIMESYNC}>,1,0>"
    --enable-discovery "$<IF:$<BOOL:${SEDSPRINTF_ENABLE_DISCOVERY}>,1,0>"
)
set(SEDSPRINTF_CODEGEN_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_schema.py"
    "${SEDSPRINTF_HEADER_BASE}"
    "${SEDSPRINTF_ABI_SOURCE}"
)
if(SEDSPRINTF_EFFECTIVE_SCHEMA_PATH)
  list(APPEND SEDSPRINTF_CODEGEN_ARGS --schema "${SEDSPRINTF_EFFECTIVE_SCHEMA_PATH}")
  list(APPEND SEDSPRINTF_CODEGEN_DEPENDS "${SEDSPRINTF_EFFECTIVE_SCHEMA_PATH}")
endif()
if(SEDSPRINTF_IPC_SCHEMA_PATH)
  list(APPEND SEDSPRINTF_CODEGEN_ARGS --ipc-schema "${SEDSPRINTF_IPC_SCHEMA_PATH}")
  list(APPEND SEDSPRINTF_CODEGEN_DEPENDS "${SEDSPRINTF_IPC_SCHEMA_PATH}")
endif()

add_custom_command(
  OUTPUT "${SEDSPRINTF_GENERATED_HEADER}" "${SEDSNET_GENERATED_HEADER}" "${SEDSPRINTF_GENERATED_SCHEMA_HPP}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${SEDSPRINTF_C_HEADER_DIR}" "${SEDSPRINTF_CPP_HEADER_DIR}"
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_schema.py"
          ${SEDSPRINTF_CODEGEN_ARGS}
  DEPENDS
    ${SEDSPRINTF_CODEGEN_DEPENDS}
  VERBATIM
)
if(SEDSPRINTF_IPC_SCHEMA_PATH)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SEDSPRINTF_IPC_SCHEMA_PATH}")
endif()

add_custom_target(sedsprintf_codegen DEPENDS "${SEDSPRINTF_GENERATED_HEADER}" "${SEDSNET_GENERATED_HEADER}" "${SEDSPRINTF_GENERATED_SCHEMA_HPP}")

add_library(sedsprintf_cpp STATIC
  src/core.cpp
  src/discovery.cpp
  src/packet.cpp
  src/queue.cpp
  src/relay.cpp
  src/router.cpp
  src/serialize.cpp
  src/router_core.cpp
  src/packet_api.cpp
  src/router_api.cpp
  src/relay_api.cpp
  src/timesync.cpp
  src/upstream_api_compat.cpp
)
add_dependencies(sedsprintf_cpp sedsprintf_codegen)
target_include_directories(sedsprintf_cpp PUBLIC
  ${SEDSPRINTF_C_HEADER_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/c-wrapper
  ${SEDSPRINTF_CPP_HEADER_DIR}
  ${SEDSPRINTF_CPP_SOURCE_HEADER_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)
if(ZSTD_INCLUDE_DIR)
  target_include_directories(sedsprintf_cpp PRIVATE ${ZSTD_INCLUDE_DIR})
endif()
if(ZSTD_LIBRARY)
  target_link_libraries(sedsprintf_cpp PRIVATE ${ZSTD_LIBRARY})
  target_compile_definitions(sedsprintf_cpp PRIVATE SEDS_HAS_ZSTD=1)
endif()
if(SEDSNET_ENABLE_CRYPTOGRAPHY)
  target_compile_definitions(sedsprintf_cpp PUBLIC SEDS_ENABLE_CRYPTOGRAPHY=1)
endif()
add_library(sedsnet::sedsnet ALIAS sedsprintf_cpp)
add_library(sedsnet ALIAS sedsprintf_cpp)
set(SEDSNET_INCLUDE_DIR "${SEDSPRINTF_C_HEADER_DIR}")
set(SEDSNET_C_WRAPPER_INCLUDE_DIR "${SEDSPRINTF_C_HEADER_DIR}")

if(SEDSNET_ENABLE_C_WRAPPER)
  add_library(sedsnet_c_wrapper STATIC c-wrapper/sedsnet_c_wrapper.c)
  target_link_libraries(sedsnet_c_wrapper PUBLIC sedsprintf_cpp)
  target_include_directories(sedsnet_c_wrapper PUBLIC
    ${SEDSPRINTF_C_HEADER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/c-wrapper
  )
  if(SEDSNET_ENABLE_CRYPTOGRAPHY)
    target_compile_definitions(sedsnet_c_wrapper PUBLIC SEDS_ENABLE_CRYPTOGRAPHY=1)
  endif()
  add_library(sedsnet::c_wrapper ALIAS sedsnet_c_wrapper)
endif()

if(SEDSNET_ENABLE_CPP_WRAPPER)
  add_library(sedsnet_cpp_wrapper INTERFACE)
  target_link_libraries(sedsnet_cpp_wrapper INTERFACE sedsprintf_cpp)
  target_include_directories(sedsnet_cpp_wrapper INTERFACE
    ${SEDSPRINTF_C_HEADER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/c-wrapper
    ${SEDSPRINTF_CPP_SOURCE_HEADER_DIR}
  )
  add_library(sedsnet::cpp_wrapper ALIAS sedsnet_cpp_wrapper)
endif()

if(SEDSNET_ENABLE_EXAMPLES)
  add_executable(sedsnet_runtime_config_example examples/runtime_config_example.c)
  target_link_libraries(sedsnet_runtime_config_example PRIVATE sedsprintf_cpp)

  add_executable(sedsnet_timesync_example examples/timesync_example.c)
  target_link_libraries(sedsnet_timesync_example PRIVATE sedsprintf_cpp)

  add_executable(sedsnet_routing_example examples/routing_example.c)
  target_link_libraries(sedsnet_routing_example PRIVATE sedsprintf_cpp)

  if(NOT TARGET sedsnet_c_wrapper)
    add_library(sedsnet_c_wrapper STATIC c-wrapper/sedsnet_c_wrapper.c)
    target_link_libraries(sedsnet_c_wrapper PUBLIC sedsprintf_cpp)
    target_include_directories(sedsnet_c_wrapper PUBLIC
      ${SEDSPRINTF_C_HEADER_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/c-wrapper
    )
    if(SEDSNET_ENABLE_CRYPTOGRAPHY)
      target_compile_definitions(sedsnet_c_wrapper PUBLIC SEDS_ENABLE_CRYPTOGRAPHY=1)
    endif()
  endif()
  add_executable(sedsnet_managed_variables_e2e_example examples/managed_variables_e2e_example.c)
  target_link_libraries(sedsnet_managed_variables_e2e_example PRIVATE sedsnet_c_wrapper)
endif()

if(SEDSNET_ENABLE_TESTS)
find_package(GTest REQUIRED)
include(GoogleTest)
enable_testing()

add_executable(sedsprintf_cpp_tests tests/tests.cpp)
add_dependencies(sedsprintf_cpp_tests sedsprintf_codegen)
target_link_libraries(sedsprintf_cpp_tests PRIVATE sedsprintf_cpp GTest::gtest_main)
gtest_discover_tests(sedsprintf_cpp_tests)

add_executable(sedsprintf_cpp_wrapper_tests tests/test_cpp_wrappers.cpp)
add_dependencies(sedsprintf_cpp_wrapper_tests sedsprintf_codegen)
target_link_libraries(sedsprintf_cpp_wrapper_tests PRIVATE sedsprintf_cpp GTest::gtest_main)
gtest_discover_tests(sedsprintf_cpp_wrapper_tests)

set(SEDSPRINTF_OVERLAY_SCHEMA_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/ipc_link_local_overlay.json")
set(SEDSPRINTF_OVERLAY_C_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/C-Headers-overlay")
set(SEDSPRINTF_OVERLAY_CPP_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/Cpp-Headers-overlay")
set(SEDSPRINTF_OVERLAY_GENERATED_HEADER "${SEDSPRINTF_OVERLAY_C_HEADER_DIR}/sedsprintf.h")
set(SEDSNET_OVERLAY_GENERATED_HEADER "${SEDSPRINTF_OVERLAY_C_HEADER_DIR}/sedsnet.h")
set(SEDSPRINTF_OVERLAY_GENERATED_SCHEMA_HPP "${SEDSPRINTF_OVERLAY_CPP_HEADER_DIR}/generated_schema.hpp")
set(SEDSPRINTF_OVERLAY_CODEGEN_ARGS
    --ipc-schema "${SEDSPRINTF_OVERLAY_SCHEMA_PATH}"
    --header-base "${SEDSPRINTF_HEADER_BASE}"
    --header-out "${SEDSPRINTF_OVERLAY_GENERATED_HEADER}"
    --public-header-out "${SEDSNET_OVERLAY_GENERATED_HEADER}"
    --schema-out "${SEDSPRINTF_OVERLAY_GENERATED_SCHEMA_HPP}"
    --abi-source "${SEDSPRINTF_ABI_SOURCE}"
    --result-source "${SEDSPRINTF_ABI_SOURCE}"
    --enable-timesync "$<IF:$<BOOL:${SEDSPRINTF_ENABLE_TIMESYNC}>,1,0>"
    --enable-discovery "$<IF:$<BOOL:${SEDSPRINTF_ENABLE_DISCOVERY}>,1,0>"
)
set(SEDSPRINTF_OVERLAY_CODEGEN_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_schema.py"
    "${SEDSPRINTF_OVERLAY_SCHEMA_PATH}"
    "${SEDSPRINTF_HEADER_BASE}"
    "${SEDSPRINTF_ABI_SOURCE}"
)
if(SEDSPRINTF_EFFECTIVE_SCHEMA_PATH)
  list(APPEND SEDSPRINTF_OVERLAY_CODEGEN_ARGS --schema "${SEDSPRINTF_EFFECTIVE_SCHEMA_PATH}")
  list(APPEND SEDSPRINTF_OVERLAY_CODEGEN_DEPENDS "${SEDSPRINTF_EFFECTIVE_SCHEMA_PATH}")
endif()
add_custom_command(
  OUTPUT "${SEDSPRINTF_OVERLAY_GENERATED_HEADER}" "${SEDSNET_OVERLAY_GENERATED_HEADER}" "${SEDSPRINTF_OVERLAY_GENERATED_SCHEMA_HPP}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${SEDSPRINTF_OVERLAY_C_HEADER_DIR}" "${SEDSPRINTF_OVERLAY_CPP_HEADER_DIR}"
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_schema.py"
          ${SEDSPRINTF_OVERLAY_CODEGEN_ARGS}
  DEPENDS
    ${SEDSPRINTF_OVERLAY_CODEGEN_DEPENDS}
  VERBATIM
)
add_custom_target(sedsprintf_codegen_overlay DEPENDS "${SEDSPRINTF_OVERLAY_GENERATED_HEADER}" "${SEDSNET_OVERLAY_GENERATED_HEADER}" "${SEDSPRINTF_OVERLAY_GENERATED_SCHEMA_HPP}")

add_library(sedsprintf_cpp_overlay STATIC
  src/core.cpp
  src/discovery.cpp
  src/packet.cpp
  src/queue.cpp
  src/relay.cpp
  src/router.cpp
  src/serialize.cpp
  src/router_core.cpp
  src/packet_api.cpp
  src/router_api.cpp
  src/relay_api.cpp
  src/timesync.cpp
  src/upstream_api_compat.cpp
)
add_dependencies(sedsprintf_cpp_overlay sedsprintf_codegen_overlay)
target_include_directories(sedsprintf_cpp_overlay PUBLIC
  ${SEDSPRINTF_OVERLAY_C_HEADER_DIR}
  ${SEDSPRINTF_OVERLAY_CPP_HEADER_DIR}
  ${SEDSPRINTF_CPP_SOURCE_HEADER_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(sedsprintf_cpp_overlay PRIVATE SEDSPRINTF_USE_OVERLAY_SCHEMA=1)
if(ZSTD_INCLUDE_DIR)
  target_include_directories(sedsprintf_cpp_overlay PRIVATE ${ZSTD_INCLUDE_DIR})
endif()
if(ZSTD_LIBRARY)
  target_link_libraries(sedsprintf_cpp_overlay PRIVATE ${ZSTD_LIBRARY})
  target_compile_definitions(sedsprintf_cpp_overlay PRIVATE SEDS_HAS_ZSTD=1)
endif()
if(SEDSNET_ENABLE_CRYPTOGRAPHY)
  target_compile_definitions(sedsprintf_cpp_overlay PUBLIC SEDS_ENABLE_CRYPTOGRAPHY=1)
endif()

add_executable(sedsprintf_cpp_overlay_tests tests/test_link_local_overlay.cpp)
add_dependencies(sedsprintf_cpp_overlay_tests sedsprintf_codegen_overlay)
target_link_libraries(sedsprintf_cpp_overlay_tests PRIVATE sedsprintf_cpp_overlay GTest::gtest_main)
gtest_discover_tests(sedsprintf_cpp_overlay_tests)

add_executable(sedsprintf_c_interop_test tests/c_interop_test.c)
add_dependencies(sedsprintf_c_interop_test sedsprintf_codegen)
target_link_libraries(sedsprintf_c_interop_test PRIVATE sedsprintf_cpp)
add_test(NAME sedsprintf_c_interop_test COMMAND sedsprintf_c_interop_test)

add_executable(sedsprintf_c_system_test tests/c_system_test.c)
add_dependencies(sedsprintf_c_system_test sedsprintf_codegen)
target_link_libraries(sedsprintf_c_system_test PRIVATE sedsprintf_cpp)
add_test(NAME sedsprintf_c_system_test COMMAND sedsprintf_c_system_test)

add_executable(sedsprintf_upstream_api_parity_test tests/upstream_api_parity_test.c)
add_dependencies(sedsprintf_upstream_api_parity_test sedsprintf_codegen)
target_link_libraries(sedsprintf_upstream_api_parity_test PRIVATE sedsprintf_cpp)
add_test(NAME sedsprintf_upstream_api_parity_test COMMAND sedsprintf_upstream_api_parity_test)

if(SEDSNET_ENABLE_C_WRAPPER)
  add_executable(sedsnet_c_wrapper_api_test tests/c_wrapper_api_test.c)
  add_dependencies(sedsnet_c_wrapper_api_test sedsprintf_codegen)
  target_link_libraries(sedsnet_c_wrapper_api_test PRIVATE sedsnet_c_wrapper)
  add_test(NAME sedsnet_c_wrapper_api_test COMMAND sedsnet_c_wrapper_api_test)
endif()

add_executable(sedsprintf_runtime_env_schema_test tests/runtime_env_schema_test.c)
add_dependencies(sedsprintf_runtime_env_schema_test sedsprintf_codegen)
target_link_libraries(sedsprintf_runtime_env_schema_test PRIVATE sedsprintf_cpp)
add_test(NAME sedsprintf_runtime_env_schema_test COMMAND sedsprintf_runtime_env_schema_test)
set_tests_properties(sedsprintf_runtime_env_schema_test PROPERTIES
  ENVIRONMENT "SEDSNET_STATIC_SCHEMA_PATH=${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/runtime_env_base.json;SEDSNET_STATIC_IPC_SCHEMA_PATH=${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/runtime_env_ipc.json")

add_executable(sedsprintf_rust_interop_cpp_peer tests/rust_interop_cpp_peer.cpp)
add_dependencies(sedsprintf_rust_interop_cpp_peer sedsprintf_codegen)
target_link_libraries(sedsprintf_rust_interop_cpp_peer PRIVATE sedsprintf_cpp)
set(SEDSPRINTF_RS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../sedsnet" CACHE PATH "Path to sibling upstream SEDSnet Rust repo for interop test")
set(SEDSPRINTF_RS_REPOSITORY "https://github.com/Rylan-Meilutis/sedsnet.git" CACHE STRING "Git repository used when the Rust interop repo is not present")
set(SEDSPRINTF_RUST_INTEROP_ARGS
    --cpp-peer $<TARGET_FILE:sedsprintf_rust_interop_cpp_peer>
    --rust-root ${SEDSPRINTF_RS_ROOT}
    --rust-repo-url ${SEDSPRINTF_RS_REPOSITORY}
    --schema-path ${SEDSPRINTF_EFFECTIVE_SCHEMA_PATH}
    --work-dir ${CMAKE_CURRENT_BINARY_DIR}/rust_interop
)
if(SEDSPRINTF_IPC_SCHEMA_PATH)
  list(APPEND SEDSPRINTF_RUST_INTEROP_ARGS --ipc-schema-path ${SEDSPRINTF_IPC_SCHEMA_PATH})
endif()
add_test(
  NAME sedsprintf_rust_router_interop
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/rust_interop.py
          ${SEDSPRINTF_RUST_INTEROP_ARGS}
)

add_test(NAME sedsprintf_codegen_check
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_codegen.py)
endif()
