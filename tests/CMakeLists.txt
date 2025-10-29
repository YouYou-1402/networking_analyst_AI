# tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)

# ============= Find Google Test =============
find_package(GTest REQUIRED)

# ============= Test Helpers Library =============
add_library(test_helpers STATIC
    unit/test_helpers.cpp
)

target_include_directories(test_helpers PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(test_helpers PUBLIC
    ${PCAP_LIBRARIES}
)

# ============= Unit Tests =============

# Test: Packet Ingress
add_executable(test_packet_ingress
    unit/test_packet_ingress.cpp
)

target_link_libraries(test_packet_ingress PRIVATE
    GTest::GTest
    GTest::Main
    test_helpers
    common_lib
    layer1_lib
)

add_test(NAME PacketIngressTest COMMAND test_packet_ingress)

# Test: Layer1 Components
add_executable(test_layer1
    unit/test_layer1.cpp
)

target_link_libraries(test_layer1 PRIVATE
    GTest::GTest
    GTest::Main
    test_helpers
    common_lib
    layer1_lib
)

add_test(NAME Layer1Test COMMAND test_layer1)

# Test: Layer2 Components
add_executable(test_layer2
    unit/test_layer2.cpp
)

target_link_libraries(test_layer2 PRIVATE
    GTest::GTest
    GTest::Main
    common_lib
    layer2_lib
)

add_test(NAME Layer2Test COMMAND test_layer2)

# Test: Analytics
add_executable(test_analytics
    unit/test_analytics.cpp
)

target_link_libraries(test_analytics PRIVATE
    GTest::GTest
    GTest::Main
    common_lib
    analytics_lib
    storage_lib
)

add_test(NAME AnalyticsTest COMMAND test_analytics)

# ============= Integration Tests =============

add_executable(test_full_pipeline
    integration/test_full_pipeline.cpp
)

target_link_libraries(test_full_pipeline PRIVATE
    GTest::GTest
    GTest::Main
    test_helpers
    common_lib
    layer1_lib
    layer2_lib
    storage_lib
    analytics_lib
)

add_test(NAME FullPipelineTest COMMAND test_full_pipeline)

# ============= Performance Tests =============

add_executable(test_performance
    integration/test_performance.cpp
)

target_link_libraries(test_performance PRIVATE
    GTest::GTest
    GTest::Main
    test_helpers
    common_lib
    layer1_lib
)

add_test(NAME PerformanceTest COMMAND test_performance)

# ============= Test Configuration =============

# Copy test data
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/data/
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test_data/)

# Set test properties
set_tests_properties(
    PacketIngressTest
    Layer1Test
    Layer2Test
    AnalyticsTest
    FullPipelineTest
    PROPERTIES
        TIMEOUT 300
        LABELS "unit"
)

set_tests_properties(
    PerformanceTest
    PROPERTIES
        TIMEOUT 600
        LABELS "performance"
)
