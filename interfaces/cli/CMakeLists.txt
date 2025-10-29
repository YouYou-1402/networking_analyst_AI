# interfaces/cli/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(PacketCaptureCLI)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)

# Try to find nlohmann_json
find_package(nlohmann_json QUIET)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/core/layer1
    ${PCAP_INCLUDE_DIRS}
)

# Source files
set(COMMON_SOURCES
    ../../src/common/logger.cpp
    ../../src/common/utils.cpp
    ../../src/common/packet_parser.cpp
    ../../src/common/network_utils.cpp
    ../../src/common/config_manager.cpp
    ../../src/common/flow_manager.cpp
)

set(LAYER1_SOURCES
    ../../src/core/layer1/packet_ingress.cpp
)

# Executable
add_executable(packet_capture_cli
    packet_capture_cli.cpp
    ${COMMON_SOURCES}
    ${LAYER1_SOURCES}
)

# Link libraries
target_link_libraries(packet_capture_cli
    ${PCAP_LIBRARIES}
    Threads::Threads
    ssl
    crypto
    z
)

# Link nlohmann_json if found
if(nlohmann_json_FOUND)
    target_link_libraries(packet_capture_cli nlohmann_json::nlohmann_json)
else()
    message(WARNING "nlohmann_json not found, some features may not work")
endif()

# Compiler flags
target_compile_options(packet_capture_cli PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
    -O2
)

# Install
install(TARGETS packet_capture_cli DESTINATION bin)
