// test_lib.cpp
#include "logger.hpp"
#include <iostream>

using namespace NetworkSecurity::Common;

int main() {
    std::cout << "=== Testing Logger Library ===" << std::endl;
    
    // Tạo logger
    Logger logger("Test");
    
    // Thêm console appender
    auto console = std::make_unique<ConsoleAppender>(true);
    logger.addAppender(std::move(console));
    
    // Set level
    logger.setLevel(LogLevel::DEBUG);
    
    // Test các level
    logger.debug("This is DEBUG");
    logger.info("This is INFO");
    logger.warn("This is WARN");
    logger.error("This is ERROR");
    
    std::cout << "\n=== Test Complete ===" << std::endl;
    
    return 0;
}
