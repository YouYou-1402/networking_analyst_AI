# tests/gui/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(NetworkSecurityGUI)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt6 settings
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Find packages
find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)
find_package(spdlog REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(CAP REQUIRED libcap)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/layer1
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common
    ${PCAP_INCLUDE_DIRS}
    ${CAP_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# GUI source files
set(GUI_SOURCES
    main.cpp
    main_window.cpp
    packet_index.cpp
    packet_detail_dialog.cpp
)

set(GUI_HEADERS
    main_window.hpp
    packet_index.hpp
)

# Core library sources
set(CORE_SOURCES
    ../../src/core/layer1/packet_ingress.cpp
    ../../src/core/layer1/packet_filter.cpp
    ../../src/core/storage/packet_storage.cpp
    ../../src/core/storage/pcap_writer.cpp
    ../../src/common/packet_parser.cpp
    ../../src/common/utils.cpp
)

# Check for logger files
file(GLOB LOGGER_SOURCES "../../src/common/logger*.cpp")
if(LOGGER_SOURCES)
    list(APPEND CORE_SOURCES ${LOGGER_SOURCES})
else()
    message(STATUS "No logger sources found, using spdlog directly")
endif()

# Executable
add_executable(${PROJECT_NAME}
    ${GUI_SOURCES}
    ${GUI_HEADERS}
    ${CORE_SOURCES}
)

# Link libraries
target_link_libraries(${PROJECT_NAME}
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    spdlog::spdlog
    ${PCAP_LIBRARIES}
    ${CAP_LIBRARIES}
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Create logs directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/logs)

# Install
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Print configuration
message(STATUS "=== Network Security GUI Configuration ===")
message(STATUS "Qt6 Version: ${Qt6_VERSION}")
message(STATUS "spdlog found: ${spdlog_FOUND}")
message(STATUS "libpcap version: ${PCAP_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "==========================================")
