# Add test executable
add_executable(test_packet_capture
    test_packet_capture.cpp
)

target_link_libraries(test_packet_capture
    PRIVATE
        packet_ingress
        packet_parser
        utils
        pcap
        spdlog::spdlog
        pthread
        cap
)

# Install
install(TARGETS test_packet_capture
    RUNTIME DESTINATION bin
)
