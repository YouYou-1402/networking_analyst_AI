// tests/unit/test_common_logger.cpp
#include <gtest/gtest.h>
#include "../../src/common/logger.hpp"
#include <fstream>
#include <thread>
#include <chrono>
#include <filesystem>
#include <regex>

using namespace NetworkSecurity::Common;
namespace fs = std::filesystem;

// ==================== Test Fixtures ====================

class LoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Clean up any existing test files
        cleanupTestFiles();
        
        // Create test directory if not exists
        if (!fs::exists("test_logs"))
        {
            fs::create_directory("test_logs");
        }
    }

    void TearDown() override
    {
        // Clean up test files after each test
        cleanupTestFiles();
        
        // Shutdown logger manager
        LoggerManager::getInstance().shutdown();
    }

    void cleanupTestFiles()
    {
        if (fs::exists("test_logs"))
        {
            fs::remove_all("test_logs");
        }
    }

    std::string readFile(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            return "";
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    std::vector<std::string> readFileLines(const std::string &filename)
    {
        std::vector<std::string> lines;
        std::ifstream file(filename);
        if (!file.is_open())
        {
            return lines;
        }
        std::string line;
        while (std::getline(file, line))
        {
            if (!line.empty())
            {
                lines.push_back(line);
            }
        }
        return lines;
    }

    bool fileContains(const std::string &filename, const std::string &text)
    {
        std::string content = readFile(filename);
        return content.find(text) != std::string::npos;
    }
};

// ==================== LogLevel Tests ====================

TEST_F(LoggerTest, LogLevelToString)
{
    EXPECT_EQ(logLevelToString(LogLevel::TRACE), "TRACE");
    EXPECT_EQ(logLevelToString(LogLevel::DEBUG), "DEBUG");
    EXPECT_EQ(logLevelToString(LogLevel::INFO), "INFO");
    EXPECT_EQ(logLevelToString(LogLevel::WARN), "WARN");
    EXPECT_EQ(logLevelToString(LogLevel::ERROR), "ERROR");
    EXPECT_EQ(logLevelToString(LogLevel::FATAL), "FATAL");
    EXPECT_EQ(logLevelToString(LogLevel::OFF), "OFF");
}

TEST_F(LoggerTest, StringToLogLevel)
{
    EXPECT_EQ(stringToLogLevel("TRACE"), LogLevel::TRACE);
    EXPECT_EQ(stringToLogLevel("DEBUG"), LogLevel::DEBUG);
    EXPECT_EQ(stringToLogLevel("INFO"), LogLevel::INFO);
    EXPECT_EQ(stringToLogLevel("WARN"), LogLevel::WARN);
    EXPECT_EQ(stringToLogLevel("WARNING"), LogLevel::WARN);
    EXPECT_EQ(stringToLogLevel("ERROR"), LogLevel::ERROR);
    EXPECT_EQ(stringToLogLevel("FATAL"), LogLevel::FATAL);
    EXPECT_EQ(stringToLogLevel("CRITICAL"), LogLevel::FATAL);
    EXPECT_EQ(stringToLogLevel("OFF"), LogLevel::OFF);
    
    // Case insensitive
    EXPECT_EQ(stringToLogLevel("trace"), LogLevel::TRACE);
    EXPECT_EQ(stringToLogLevel("Debug"), LogLevel::DEBUG);
    EXPECT_EQ(stringToLogLevel("InFo"), LogLevel::INFO);
    
    // Default for unknown
    EXPECT_EQ(stringToLogLevel("UNKNOWN"), LogLevel::INFO);
    EXPECT_EQ(stringToLogLevel(""), LogLevel::INFO);
}

// ==================== LogEntry Tests ====================

TEST_F(LoggerTest, LogEntryCreation)
{
    LogEntry entry(LogLevel::INFO, "TestLogger", "Test message", "test.cpp", "testFunc", 42);
    
    EXPECT_EQ(entry.level, LogLevel::INFO);
    EXPECT_EQ(entry.logger_name, "TestLogger");
    EXPECT_EQ(entry.message, "Test message");
    EXPECT_EQ(entry.file, "test.cpp");
    EXPECT_EQ(entry.function, "testFunc");
    EXPECT_EQ(entry.line, 42);
    EXPECT_GT(entry.timestamp, 0);
}

TEST_F(LoggerTest, LogEntryDefaultConstructor)
{
    LogEntry entry;
    
    EXPECT_EQ(entry.level, LogLevel::INFO);
    EXPECT_EQ(entry.timestamp, 0);
    EXPECT_EQ(entry.line, 0);
}

// ==================== Formatter Tests ====================

TEST_F(LoggerTest, DefaultFormatterBasic)
{
    DefaultFormatter formatter("[{level}] {message}");
    LogEntry entry(LogLevel::INFO, "TestLogger", "Hello World");
    
    std::string formatted = formatter.format(entry);
    EXPECT_TRUE(formatted.find("[INFO]") != std::string::npos);
    EXPECT_TRUE(formatted.find("Hello World") != std::string::npos);
}

TEST_F(LoggerTest, DefaultFormatterAllFields)
{
    DefaultFormatter formatter("[{timestamp}] [{level}] [{logger}] {file}:{line} {function}() - {message}");
    LogEntry entry(LogLevel::ERROR, "MyLogger", "Error occurred", "main.cpp", "main", 100);
    
    std::string formatted = formatter.format(entry);
    EXPECT_TRUE(formatted.find("[ERROR]") != std::string::npos);
    EXPECT_TRUE(formatted.find("[MyLogger]") != std::string::npos);
    EXPECT_TRUE(formatted.find("Error occurred") != std::string::npos);
    EXPECT_TRUE(formatted.find("main.cpp") != std::string::npos);
    EXPECT_TRUE(formatted.find("100") != std::string::npos);
    EXPECT_TRUE(formatted.find("main()") != std::string::npos);
}

TEST_F(LoggerTest, DefaultFormatterClone)
{
    DefaultFormatter formatter("[{level}] {message}");
    auto cloned = formatter.clone();
    
    LogEntry entry(LogLevel::WARN, "TestLogger", "Warning message");
    std::string original = formatter.format(entry);
    std::string cloned_result = cloned->format(entry);
    
    EXPECT_EQ(original, cloned_result);
}

TEST_F(LoggerTest, JsonFormatterCompact)
{
    JsonFormatter formatter(false);
    LogEntry entry(LogLevel::DEBUG, "JsonLogger", "Debug info", "test.cpp", "testFunc", 50);
    
    std::string formatted = formatter.format(entry);
    
    EXPECT_TRUE(formatted.find("\"level\":\"DEBUG\"") != std::string::npos);
    EXPECT_TRUE(formatted.find("\"logger\":\"JsonLogger\"") != std::string::npos);
    EXPECT_TRUE(formatted.find("\"message\":\"Debug info\"") != std::string::npos);
    EXPECT_TRUE(formatted.find("\"file\":\"test.cpp\"") != std::string::npos);
    EXPECT_TRUE(formatted.find("\"line\":50") != std::string::npos);
    
    // Should not have newlines in compact mode
    EXPECT_EQ(formatted.find('\n'), std::string::npos);
}

TEST_F(LoggerTest, JsonFormatterPretty)
{
    JsonFormatter formatter(true);
    LogEntry entry(LogLevel::INFO, "JsonLogger", "Info message");
    
    std::string formatted = formatter.format(entry);
    
    // Should have newlines in pretty mode
    EXPECT_NE(formatted.find('\n'), std::string::npos);
    EXPECT_TRUE(formatted.find("\"level\": \"INFO\"") != std::string::npos);
}

// ==================== ConsoleAppender Tests ====================

TEST_F(LoggerTest, ConsoleAppenderCreation)
{
    ConsoleAppender appender(false); // No colors for testing
    EXPECT_EQ(appender.getLevel(), LogLevel::TRACE);
}

TEST_F(LoggerTest, ConsoleAppenderLevelFiltering)
{
    ConsoleAppender appender(false);
    appender.setLevel(LogLevel::WARN);
    
    LogEntry info_entry(LogLevel::INFO, "TestLogger", "Info message");
    LogEntry warn_entry(LogLevel::WARN, "TestLogger", "Warning message");
    LogEntry error_entry(LogLevel::ERROR, "TestLogger", "Error message");
    
    // INFO should be filtered out
    EXPECT_FALSE(appender.append(info_entry));
    
    // WARN and ERROR should pass
    EXPECT_TRUE(appender.append(warn_entry));
    EXPECT_TRUE(appender.append(error_entry));
}

TEST_F(LoggerTest, ConsoleAppenderClone)
{
    ConsoleAppender appender(true);
    appender.setLevel(LogLevel::ERROR);
    
    auto cloned = appender.clone();
    EXPECT_EQ(cloned->getLevel(), LogLevel::ERROR);
}

// ==================== FileAppender Tests ====================

TEST_F(LoggerTest, FileAppenderCreation)
{
    std::string filename = "test_logs/test.log";
    FileAppender appender(filename, false);
    
    LogEntry entry(LogLevel::INFO, "FileLogger", "Test message");
    EXPECT_TRUE(appender.append(entry));
    appender.flush();
    appender.close();
    
    EXPECT_TRUE(fs::exists(filename));
    EXPECT_TRUE(fileContains(filename, "Test message"));
}

TEST_F(LoggerTest, FileAppenderAppendMode)
{
    std::string filename = "test_logs/append_test.log";
    
    // Write first message
    {
        FileAppender appender(filename, false);
        LogEntry entry(LogLevel::INFO, "FileLogger", "First message");
        appender.append(entry);
    }
    
    // Append second message
    {
        FileAppender appender(filename, true);
        LogEntry entry(LogLevel::INFO, "FileLogger", "Second message");
        appender.append(entry);
    }
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("First message") != std::string::npos);
    EXPECT_TRUE(content.find("Second message") != std::string::npos);
}

TEST_F(LoggerTest, FileAppenderOverwriteMode)
{
    std::string filename = "test_logs/overwrite_test.log";
    
    // Write first message
    {
        FileAppender appender(filename, false);
        LogEntry entry(LogLevel::INFO, "FileLogger", "First message");
        appender.append(entry);
    }
    
    // Overwrite with second message
    {
        FileAppender appender(filename, false);
        LogEntry entry(LogLevel::INFO, "FileLogger", "Second message");
        appender.append(entry);
    }
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("First message") == std::string::npos);
    EXPECT_TRUE(content.find("Second message") != std::string::npos);
}

TEST_F(LoggerTest, FileAppenderLevelFiltering)
{
    std::string filename = "test_logs/level_filter.log";
    FileAppender appender(filename, false);
    appender.setLevel(LogLevel::WARN);
    
    LogEntry debug_entry(LogLevel::DEBUG, "FileLogger", "Debug message");
    LogEntry warn_entry(LogLevel::WARN, "FileLogger", "Warning message");
    
    appender.append(debug_entry);
    appender.append(warn_entry);
    appender.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("Debug message") == std::string::npos);
    EXPECT_TRUE(content.find("Warning message") != std::string::npos);
}

TEST_F(LoggerTest, FileAppenderRotation)
{
    std::string filename = "test_logs/rotation.log";
    FileAppender appender(filename, false);
    
    // Enable rotation: max 100 bytes, keep 3 files
    appender.setMaxFileSize(100);
    appender.setMaxFiles(3);
    appender.enableRotation(true);
    
    // Write multiple messages to trigger rotation
    for (int i = 0; i < 20; i++)
    {
        LogEntry entry(LogLevel::INFO, "FileLogger", "Message number " + std::to_string(i));
        appender.append(entry);
    }
    
    appender.close();
    
    // Check that rotation occurred
    EXPECT_TRUE(fs::exists(filename));
    // Rotated files should exist
    EXPECT_TRUE(fs::exists(filename + ".1") || fs::file_size(filename) < 100);
}

TEST_F(LoggerTest, RotatingFileAppenderCreation)
{
    std::string filename = "test_logs/rotating.log";
    RotatingFileAppender appender(filename, 200, 5);
    
    for (int i = 0; i < 30; i++)
    {
        LogEntry entry(LogLevel::INFO, "RotatingLogger", "Message " + std::to_string(i));
        appender.append(entry);
    }
    
    appender.close();
    EXPECT_TRUE(fs::exists(filename));
}

// ==================== CallbackAppender Tests ====================

TEST_F(LoggerTest, CallbackAppenderBasic)
{
    std::vector<LogEntry> captured_entries;
    
    CallbackAppender appender([&captured_entries](const LogEntry &entry) {
        captured_entries.push_back(entry);
    });
    
    LogEntry entry1(LogLevel::INFO, "CallbackLogger", "Message 1");
    LogEntry entry2(LogLevel::ERROR, "CallbackLogger", "Message 2");
    
    appender.append(entry1);
    appender.append(entry2);
    
    EXPECT_EQ(captured_entries.size(), 2);
    EXPECT_EQ(captured_entries[0].message, "Message 1");
    EXPECT_EQ(captured_entries[1].message, "Message 2");
}

TEST_F(LoggerTest, CallbackAppenderLevelFiltering)
{
    int callback_count = 0;
    
    CallbackAppender appender([&callback_count](const LogEntry &) {
        callback_count++;
    });
    appender.setLevel(LogLevel::ERROR);
    
    LogEntry info_entry(LogLevel::INFO, "CallbackLogger", "Info");
    LogEntry error_entry(LogLevel::ERROR, "CallbackLogger", "Error");
    
    appender.append(info_entry);
    appender.append(error_entry);
    
    EXPECT_EQ(callback_count, 1); // Only ERROR should trigger callback
}

// ==================== Logger Tests ====================

TEST_F(LoggerTest, LoggerCreation)
{
    Logger logger("TestLogger");
    EXPECT_EQ(logger.getName(), "TestLogger");
    EXPECT_EQ(logger.getLevel(), LogLevel::INFO);
}

TEST_F(LoggerTest, LoggerSetLevel)
{
    Logger logger("TestLogger");
    
    logger.setLevel(LogLevel::ERROR);
    EXPECT_EQ(logger.getLevel(), LogLevel::ERROR);
    
    logger.setLevel(LogLevel::DEBUG);
    EXPECT_EQ(logger.getLevel(), LogLevel::DEBUG);
}

TEST_F(LoggerTest, LoggerIsLevelEnabled)
{
    Logger logger("TestLogger");
    logger.setLevel(LogLevel::WARN);
    
    EXPECT_FALSE(logger.isLevelEnabled(LogLevel::TRACE));
    EXPECT_FALSE(logger.isLevelEnabled(LogLevel::DEBUG));
    EXPECT_FALSE(logger.isLevelEnabled(LogLevel::INFO));
    EXPECT_TRUE(logger.isLevelEnabled(LogLevel::WARN));
    EXPECT_TRUE(logger.isLevelEnabled(LogLevel::ERROR));
    EXPECT_TRUE(logger.isLevelEnabled(LogLevel::FATAL));
}

TEST_F(LoggerTest, LoggerBasicLogging)
{
    std::string filename = "test_logs/basic_logging.log";
    Logger logger("BasicLogger");
    logger.setLevel(LogLevel::TRACE);
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    logger.trace("Trace message");
    logger.debug("Debug message");
    logger.info("Info message");
    logger.warn("Warning message");
    logger.error("Error message");
    logger.fatal("Fatal message");
    
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("Trace message") != std::string::npos);
    EXPECT_TRUE(content.find("Debug message") != std::string::npos);
    EXPECT_TRUE(content.find("Info message") != std::string::npos);
    EXPECT_TRUE(content.find("Warning message") != std::string::npos);
    EXPECT_TRUE(content.find("Error message") != std::string::npos);
    EXPECT_TRUE(content.find("Fatal message") != std::string::npos);
}

TEST_F(LoggerTest, LoggerFormattedLogging)
{
    std::string filename = "test_logs/formatted_logging.log";
    Logger logger("FormattedLogger");
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    logger.info("User {} logged in from {}", "john", "192.168.1.1");
    logger.warn("Temperature is {} degrees", 75);
    logger.error("Failed to connect to {} on port {}", "server.com", 8080);
    
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("User john logged in from 192.168.1.1") != std::string::npos);
    EXPECT_TRUE(content.find("Temperature is 75 degrees") != std::string::npos);
    EXPECT_TRUE(content.find("Failed to connect to server.com on port 8080") != std::string::npos);
}

TEST_F(LoggerTest, LoggerMultipleAppenders)
{
    std::string filename1 = "test_logs/multi_appender1.log";
    std::string filename2 = "test_logs/multi_appender2.log";
    
    Logger logger("MultiAppenderLogger");
    
    auto file_appender1 = std::make_unique<FileAppender>(filename1, false);
    auto file_appender2 = std::make_unique<FileAppender>(filename2, false);
    
    logger.addAppender(std::move(file_appender1));
    logger.addAppender(std::move(file_appender2));
    
    EXPECT_EQ(logger.getAppenderCount(), 2);
    
    logger.info("Test message");
    logger.close();
    
    EXPECT_TRUE(fileContains(filename1, "Test message"));
    EXPECT_TRUE(fileContains(filename2, "Test message"));
}

TEST_F(LoggerTest, LoggerRemoveAllAppenders)
{
    Logger logger("TestLogger");
    
    auto appender1 = std::make_unique<ConsoleAppender>();
    auto appender2 = std::make_unique<ConsoleAppender>();
    
    logger.addAppender(std::move(appender1));
    logger.addAppender(std::move(appender2));
    
    EXPECT_EQ(logger.getAppenderCount(), 2);
    
    logger.removeAllAppenders();
    EXPECT_EQ(logger.getAppenderCount(), 0);
}

TEST_F(LoggerTest, LoggerAsyncLogging)
{
    std::string filename = "test_logs/async_logging.log";
    Logger logger("AsyncLogger");
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    logger.enableAsyncLogging(true);
    EXPECT_TRUE(logger.isAsyncLoggingEnabled());
    
    // Log many messages quickly
    for (int i = 0; i < 100; i++)
    {
        logger.info("Async message {}", i);
    }
    
    // Disable async to flush remaining messages
    logger.enableAsyncLogging(false);
    logger.close();
    
    auto lines = readFileLines(filename);
    EXPECT_GT(lines.size(), 0);
}

TEST_F(LoggerTest, LoggerThreadSafety)
{
    std::string filename = "test_logs/thread_safety.log";
    Logger logger("ThreadSafeLogger");
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    const int num_threads = 10;
    const int messages_per_thread = 100;
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; t++)
    {
        threads.emplace_back([&logger, t, messages_per_thread]() {
            for (int i = 0; i < messages_per_thread; i++)
            {
                logger.info("Thread {} message {}", t, i);
            }
        });
    }
    
    for (auto &thread : threads)
    {
        thread.join();
    }
    
    logger.close();
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_threads * messages_per_thread);
}

// ==================== LoggerManager Tests ====================

TEST_F(LoggerTest, LoggerManagerSingleton)
{
    auto &manager1 = LoggerManager::getInstance();
    auto &manager2 = LoggerManager::getInstance();
    
    EXPECT_EQ(&manager1, &manager2);
}

TEST_F(LoggerTest, LoggerManagerGetLogger)
{
    auto &manager = LoggerManager::getInstance();
    
    auto logger1 = manager.getLogger("TestLogger1");
    auto logger2 = manager.getLogger("TestLogger2");
    auto logger1_again = manager.getLogger("TestLogger1");
    
    EXPECT_NE(logger1, nullptr);
    EXPECT_NE(logger2, nullptr);
    EXPECT_EQ(logger1, logger1_again); // Should return same instance
    EXPECT_NE(logger1, logger2);
}

TEST_F(LoggerTest, LoggerManagerCreateLogger)
{
    auto &manager = LoggerManager::getInstance();
    
    auto logger = manager.createLogger("NewLogger");
    EXPECT_NE(logger, nullptr);
    EXPECT_EQ(logger->getName(), "NewLogger");
    
    // Creating again should return existing logger
    auto logger_again = manager.createLogger("NewLogger");
    EXPECT_EQ(logger, logger_again);
}

TEST_F(LoggerTest, LoggerManagerRemoveLogger)
{
    auto &manager = LoggerManager::getInstance();
    
    auto logger = manager.createLogger("RemovableLogger");
    EXPECT_NE(logger, nullptr);
    
    bool removed = manager.removeLogger("RemovableLogger");
    EXPECT_TRUE(removed);
    
    // Removing again should return false
    removed = manager.removeLogger("RemovableLogger");
    EXPECT_FALSE(removed);
}

TEST_F(LoggerTest, LoggerManagerGetAllLoggerNames)
{
    auto &manager = LoggerManager::getInstance();
    
    manager.createLogger("Logger1");
    manager.createLogger("Logger2");
    manager.createLogger("Logger3");
    
    auto names = manager.getAllLoggerNames();
    EXPECT_GE(names.size(), 3);
    
    bool found_logger1 = false, found_logger2 = false, found_logger3 = false;
    for (const auto &name : names)
    {
        if (name == "Logger1") found_logger1 = true;
        if (name == "Logger2") found_logger2 = true;
        if (name == "Logger3") found_logger3 = true;
    }
    
    EXPECT_TRUE(found_logger1);
    EXPECT_TRUE(found_logger2);
    EXPECT_TRUE(found_logger3);
}

TEST_F(LoggerTest, LoggerManagerSetGlobalLevel)
{
    auto &manager = LoggerManager::getInstance();
    
    auto logger1 = manager.createLogger("GlobalLevelLogger1");
    auto logger2 = manager.createLogger("GlobalLevelLogger2");
    
    manager.setGlobalLevel(LogLevel::ERROR);
    
    EXPECT_EQ(logger1->getLevel(), LogLevel::ERROR);
    EXPECT_EQ(logger2->getLevel(), LogLevel::ERROR);
}

TEST_F(LoggerTest, LoggerManagerFlushAll)
{
    auto &manager = LoggerManager::getInstance();
    
    std::string filename1 = "test_logs/flush_all1.log";
    std::string filename2 = "test_logs/flush_all2.log";
    
    auto logger1 = manager.createLogger("FlushLogger1");
    auto logger2 = manager.createLogger("FlushLogger2");
    
    logger1->removeAllAppenders();
    logger2->removeAllAppenders();
    
    logger1->addAppender(std::make_unique<FileAppender>(filename1, false));
    logger2->addAppender(std::make_unique<FileAppender>(filename2, false));
    
    logger1->info("Message 1");
    logger2->info("Message 2");
    
    manager.flushAll();
    
    EXPECT_TRUE(fileContains(filename1, "Message 1"));
    EXPECT_TRUE(fileContains(filename2, "Message 2"));
}

TEST_F(LoggerTest, LoggerManagerShutdown)
{
    auto &manager = LoggerManager::getInstance();
    
    manager.createLogger("ShutdownLogger1");
    manager.createLogger("ShutdownLogger2");
    
    auto names_before = manager.getAllLoggerNames();
    EXPECT_GE(names_before.size(), 2);
    
    manager.shutdown();
    
    auto names_after = manager.getAllLoggerNames();
    EXPECT_EQ(names_after.size(), 0);
}

TEST_F(LoggerTest, LoggerManagerGlobalAsyncLogging)
{
    auto &manager = LoggerManager::getInstance();
    
    auto logger1 = manager.createLogger("AsyncGlobalLogger1");
    auto logger2 = manager.createLogger("AsyncGlobalLogger2");
    
    manager.enableGlobalAsyncLogging(true);
    
    EXPECT_TRUE(logger1->isAsyncLoggingEnabled());
    EXPECT_TRUE(logger2->isAsyncLoggingEnabled());
    
    manager.enableGlobalAsyncLogging(false);
    
    EXPECT_FALSE(logger1->isAsyncLoggingEnabled());
    EXPECT_FALSE(logger2->isAsyncLoggingEnabled());
}

// ==================== Macro Tests ====================

TEST_F(LoggerTest, MacroGetLogger)
{
    auto logger = GET_LOGGER("MacroLogger");
    EXPECT_NE(logger, nullptr);
    EXPECT_EQ(logger->getName(), "MacroLogger");
}

TEST_F(LoggerTest, MacroLogManager)
{
    auto &manager1 = LOG_MANAGER;
    auto &manager2 = LoggerManager::getInstance();
    EXPECT_EQ(&manager1, &manager2);
}

TEST_F(LoggerTest, MacroLoggingWithFileInfo)
{
    std::string filename = "test_logs/macro_logging.log";
    auto logger = GET_LOGGER("MacroTestLogger");
    logger->removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    file_appender->setFormatter(std::make_unique<DefaultFormatter>(
        "[{level}] {file}:{line} {function}() - {message}"));
    logger->addAppender(std::move(file_appender));
    
    LOG_INFO(logger, "Test message with file info");
    logger->close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("test_common_logger.cpp") != std::string::npos);
    EXPECT_TRUE(content.find("TestBody()") != std::string::npos || 
                content.find("test_common_logger") != std::string::npos);
}

// ==================== Performance Tests ====================

TEST_F(LoggerTest, PerformanceSyncLogging)
{
    std::string filename = "test_logs/perf_sync.log";
    Logger logger("PerfSyncLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    const int num_messages = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_messages; i++)
    {
        logger.info("Performance test message {}", i);
    }
    
    logger.close();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Sync logging " << num_messages << " messages took " 
              << duration.count() << "ms" << std::endl;
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_messages);
}

TEST_F(LoggerTest, PerformanceAsyncLogging)
{
    std::string filename = "test_logs/perf_async.log";
    Logger logger("PerfAsyncLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    logger.enableAsyncLogging(true);
    
    const int num_messages = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_messages; i++)
    {
        logger.info("Performance test message {}", i);
    }
    
    logger.enableAsyncLogging(false); // Wait for all messages to be processed
    logger.close();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Async logging " << num_messages << " messages took " 
              << duration.count() << "ms" << std::endl;
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_messages);
}

TEST_F(LoggerTest, PerformanceMultiThreadedLogging)
{
    std::string filename = "test_logs/perf_multithread.log";
    Logger logger("PerfMultiThreadLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    const int num_threads = 4;
    const int messages_per_thread = 2500;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; t++)
    {
        threads.emplace_back([&logger, t, messages_per_thread]() {
            for (int i = 0; i < messages_per_thread; i++)
            {
                logger.info("Thread {} message {}", t, i);
            }
        });
    }
    
    for (auto &thread : threads)
    {
        thread.join();
    }
    
    logger.close();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Multi-threaded logging (" << num_threads << " threads, " 
              << messages_per_thread << " messages each) took " 
              << duration.count() << "ms" << std::endl;
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_threads * messages_per_thread);
}

// ==================== Edge Cases and Error Handling ====================

TEST_F(LoggerTest, EmptyLoggerName)
{
    Logger logger("");
    EXPECT_EQ(logger.getName(), "");
    
    logger.info("Test message");
    // Should not crash
}

TEST_F(LoggerTest, VeryLongMessage)
{
    std::string filename = "test_logs/long_message.log";
    Logger logger("LongMessageLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    std::string long_message(10000, 'A');
    logger.info(long_message);
    logger.close();
    
    EXPECT_TRUE(fileContains(filename, long_message));
}

TEST_F(LoggerTest, SpecialCharactersInMessage)
{
    std::string filename = "test_logs/special_chars.log";
    Logger logger("SpecialCharsLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    logger.info("Message with special chars: \n\t\r\\\"'");
    logger.info("Unicode: 你好世界 🌍");
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("special chars") != std::string::npos);
}

TEST_F(LoggerTest, NullPointerFormatting)
{
    std::string filename = "test_logs/null_pointer.log";
    Logger logger("NullPointerLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    void* null_ptr = nullptr;
    logger.info("Null pointer: {}", null_ptr);
    logger.close();
    
    EXPECT_TRUE(fs::exists(filename));
}

TEST_F(LoggerTest, FileAppenderInvalidPath)
{
    // Try to create file in non-existent directory without creating it first
    std::string invalid_path = "test_logs/non_existent_dir/subdir/test.log";
    
    // This should fail gracefully
    FileAppender appender(invalid_path, false);
    LogEntry entry(LogLevel::INFO, "TestLogger", "Test message");
    
    // append should return false for invalid file
    EXPECT_FALSE(appender.append(entry));
}

TEST_F(LoggerTest, AsyncLoggingQueueOverflow)
{
    std::string filename = "test_logs/queue_overflow.log";
    Logger logger("QueueOverflowLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    logger.enableAsyncLogging(true);
    logger.setAsyncQueueSize(10); // Very small queue
    
    // Try to overflow the queue
    for (int i = 0; i < 1000; i++)
    {
        logger.info("Message {}", i);
    }
    
    logger.enableAsyncLogging(false);
    logger.close();
    
    // Some messages might be dropped, but shouldn't crash
    EXPECT_TRUE(fs::exists(filename));
}

TEST_F(LoggerTest, MultipleFormattersOnSameAppender)
{
    std::string filename = "test_logs/multiple_formatters.log";
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    
    // Set default formatter
    file_appender->setFormatter(std::make_unique<DefaultFormatter>("[{level}] {message}"));
    
    Logger logger("FormatterLogger");
    logger.removeAllAppenders();
    logger.addAppender(std::move(file_appender));
    
    logger.info("First message");
    
    // Change formatter (note: need to access appender, which is not directly possible)
    // This test shows the formatter is set at appender creation
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("[INFO]") != std::string::npos);
}

TEST_F(LoggerTest, LogLevelBoundaries)
{
    Logger logger("BoundaryLogger");
    
    // Test minimum level
    logger.setLevel(LogLevel::TRACE);
    EXPECT_TRUE(logger.isLevelEnabled(LogLevel::TRACE));
    EXPECT_TRUE(logger.isLevelEnabled(LogLevel::FATAL));
    
    // Test maximum level
    logger.setLevel(LogLevel::OFF);
    EXPECT_FALSE(logger.isLevelEnabled(LogLevel::TRACE));
    EXPECT_FALSE(logger.isLevelEnabled(LogLevel::FATAL));
}

TEST_F(LoggerTest, ConcurrentLoggerCreation)
{
    auto &manager = LoggerManager::getInstance();
    
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<std::shared_ptr<Logger>> loggers(num_threads);
    
    for (int i = 0; i < num_threads; i++)
    {
        threads.emplace_back([&manager, &loggers, i]() {
            loggers[i] = manager.getLogger("ConcurrentLogger");
        });
    }
    
    for (auto &thread : threads)
    {
        thread.join();
    }
    
    // All threads should get the same logger instance
    for (int i = 1; i < num_threads; i++)
    {
        EXPECT_EQ(loggers[0], loggers[i]);
    }
}

// ==================== Integration Tests ====================

TEST_F(LoggerTest, CompleteLoggingWorkflow)
{
    std::string console_capture = "test_logs/console_capture.log";
    std::string file_log = "test_logs/workflow.log";
    
    // Create logger with multiple appenders
    auto logger = GET_LOGGER("WorkflowLogger");
    logger->removeAllAppenders();
    logger->setLevel(LogLevel::DEBUG);
    
    // Add file appender with custom formatter
    auto file_appender = std::make_unique<FileAppender>(file_log, false);
    file_appender->setFormatter(std::make_unique<DefaultFormatter>(
        "[{timestamp}] [{level}] {message}"));
    logger->addAppender(std::move(file_appender));
    
    // Add callback appender for counting
    int log_count = 0;
    auto callback_appender = std::make_unique<CallbackAppender>(
        [&log_count](const LogEntry &) { log_count++; });
    logger->addAppender(std::move(callback_appender));
    
    // Log various messages
    logger->debug("Starting application");
    logger->info("User {} logged in", "admin");
    logger->warn("Memory usage at {}%", 85);
    logger->error("Failed to connect to database");
    logger->info("Retrying connection...");
    logger->info("Connection successful");
    logger->debug("Shutting down");
    
    logger->flush();
    logger->close();
    
    // Verify file output
    auto lines = readFileLines(file_log);
    EXPECT_EQ(lines.size(), 7);
    
    // Verify callback count
    EXPECT_EQ(log_count, 7);
    
    // Verify content
    std::string content = readFile(file_log);
    EXPECT_TRUE(content.find("Starting application") != std::string::npos);
    EXPECT_TRUE(content.find("User admin logged in") != std::string::npos);
    EXPECT_TRUE(content.find("Memory usage at 85%") != std::string::npos);
}

TEST_F(LoggerTest, MultiLoggerScenario)
{
    std::string app_log = "test_logs/app.log";
    std::string security_log = "test_logs/security.log";
    std::string error_log = "test_logs/error.log";
    
    auto &manager = LOG_MANAGER;
    
    // Application logger - logs everything to app.log
    auto app_logger = manager.getLogger("Application");
    app_logger->removeAllAppenders();
    app_logger->setLevel(LogLevel::INFO);
    app_logger->addAppender(std::make_unique<FileAppender>(app_log, false));
    
    // Security logger - logs to security.log
    auto security_logger = manager.getLogger("Security");
    security_logger->removeAllAppenders();
    security_logger->setLevel(LogLevel::INFO);
    security_logger->addAppender(std::make_unique<FileAppender>(security_log, false));
    
    // Error logger - only errors to error.log
    auto error_logger = manager.getLogger("Error");
    error_logger->removeAllAppenders();
    error_logger->setLevel(LogLevel::ERROR);
    error_logger->addAppender(std::make_unique<FileAppender>(error_log, false));
    
    // Simulate application flow
    app_logger->info("Application started");
    security_logger->info("User login attempt from {}", "192.168.1.100");
    app_logger->info("Processing request");
    error_logger->error("Database connection failed");
    security_logger->warn("Multiple failed login attempts detected");
    app_logger->info("Application shutting down");
    
    manager.flushAll();
    
    // Verify each log file
    EXPECT_TRUE(fileContains(app_log, "Application started"));
    EXPECT_TRUE(fileContains(security_log, "User login attempt"));
    EXPECT_TRUE(fileContains(error_log, "Database connection failed"));
    
    // Security log should not contain application messages
    EXPECT_FALSE(fileContains(security_log, "Application started"));
}

TEST_F(LoggerTest, DynamicLogLevelChange)
{
    std::string filename = "test_logs/dynamic_level.log";
    Logger logger("DynamicLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    // Start with INFO level
    logger.setLevel(LogLevel::INFO);
    logger.debug("Debug 1 - should not appear");
    logger.info("Info 1 - should appear");
    
    // Change to DEBUG level
    logger.setLevel(LogLevel::DEBUG);
    logger.debug("Debug 2 - should appear");
    logger.info("Info 2 - should appear");
    
    // Change to ERROR level
    logger.setLevel(LogLevel::ERROR);
    logger.info("Info 3 - should not appear");
    logger.error("Error 1 - should appear");
    
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("Debug 1") == std::string::npos);
    EXPECT_TRUE(content.find("Info 1") != std::string::npos);
    EXPECT_TRUE(content.find("Debug 2") != std::string::npos);
    EXPECT_TRUE(content.find("Info 2") != std::string::npos);
    EXPECT_TRUE(content.find("Info 3") == std::string::npos);
    EXPECT_TRUE(content.find("Error 1") != std::string::npos);
}

TEST_F(LoggerTest, LoggerWithJsonFormatter)
{
    std::string filename = "test_logs/json_output.log";
    Logger logger("JsonLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    file_appender->setFormatter(std::make_unique<JsonFormatter>(true));
    logger.addAppender(std::move(file_appender));
    
    logger.info("Test JSON message");
    logger.error("Error in JSON format");
    logger.close();
    
    std::string content = readFile(filename);
    EXPECT_TRUE(content.find("\"level\": \"INFO\"") != std::string::npos);
    EXPECT_TRUE(content.find("\"message\": \"Test JSON message\"") != std::string::npos);
    EXPECT_TRUE(content.find("\"level\": \"ERROR\"") != std::string::npos);
}

// ==================== Stress Tests ====================

TEST_F(LoggerTest, StressTestRapidLogging)
{
    std::string filename = "test_logs/stress_rapid.log";
    Logger logger("StressLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    const int num_messages = 50000;
    
    for (int i = 0; i < num_messages; i++)
    {
        logger.info("Rapid message {}", i);
    }
    
    logger.close();
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_messages);
}

TEST_F(LoggerTest, StressTestManyLoggers)
{
    auto &manager = LOG_MANAGER;
    const int num_loggers = 100;
    
    std::vector<std::shared_ptr<Logger>> loggers;
    for (int i = 0; i < num_loggers; i++)
    {
        auto logger = manager.getLogger("StressLogger" + std::to_string(i));
        logger->removeAllAppenders();
        loggers.push_back(logger);
    }
    
    EXPECT_EQ(loggers.size(), num_loggers);
    
    // Log from all loggers
    for (int i = 0; i < num_loggers; i++)
    {
        loggers[i]->info("Message from logger {}", i);
    }
    
    // All should work without issues
    auto names = manager.getAllLoggerNames();
    EXPECT_GE(names.size(), num_loggers);
}

TEST_F(LoggerTest, StressTestLargeMessages)
{
    std::string filename = "test_logs/stress_large.log";
    Logger logger("LargeMessageLogger");
    logger.removeAllAppenders();
    
    auto file_appender = std::make_unique<FileAppender>(filename, false);
    logger.addAppender(std::move(file_appender));
    
    const int num_messages = 100;
    const int message_size = 10000;
    
    for (int i = 0; i < num_messages; i++)
    {
        std::string large_message(message_size, 'X');
        logger.info("Message {}: {}", i, large_message);
    }
    
    logger.close();
    
    auto lines = readFileLines(filename);
    EXPECT_EQ(lines.size(), num_messages);
}

// ==================== Real-world Scenarios ====================

TEST_F(LoggerTest, WebServerLoggingScenario)
{
    std::string access_log = "test_logs/access.log";
    std::string error_log = "test_logs/error.log";
    
    auto access_logger = GET_LOGGER("Access");
    access_logger->removeAllAppenders();
    access_logger->setLevel(LogLevel::INFO);
    access_logger->addAppender(std::make_unique<FileAppender>(access_log, false));
    
    auto error_logger = GET_LOGGER("Error");
    error_logger->removeAllAppenders();
    error_logger->setLevel(LogLevel::ERROR);
    error_logger->addAppender(std::make_unique<FileAppender>(error_log, false));
    
    // Simulate web requests
    access_logger->info("GET /index.html 200 {} ms", 45);
    access_logger->info("POST /api/login 200 {} ms", 120);
    access_logger->info("GET /api/users 200 {} ms", 67);
    error_logger->error("GET /api/data 500 - Database timeout");
    access_logger->info("GET /about.html 200 {} ms", 32);
    
    access_logger->close();
    error_logger->close();
    
    auto access_lines = readFileLines(access_log);
    auto error_lines = readFileLines(error_log);
    
    EXPECT_EQ(access_lines.size(), 4);
    EXPECT_EQ(error_lines.size(), 1);
}

TEST_F(LoggerTest, DatabaseOperationLogging)
{
    std::string db_log = "test_logs/database.log";
    
    auto db_logger = GET_LOGGER("Database");
    db_logger->removeAllAppenders();
    db_logger->setLevel(LogLevel::DEBUG);
    
    auto file_appender = std::make_unique<FileAppender>(db_log, false);
    file_appender->setFormatter(std::make_unique<DefaultFormatter>(
        "[{timestamp}] [{level}] {message}"));
    db_logger->addAppender(std::move(file_appender));
    
    // Simulate database operations
    db_logger->debug("Connecting to database server {}:{}", "localhost", 5432);
    db_logger->info("Connection established");
    db_logger->debug("Executing query: SELECT * FROM users");
    db_logger->info("Query returned {} rows", 150);
    db_logger->debug("Executing query: UPDATE users SET status='active'");
    db_logger->info("Updated {} rows", 25);
    db_logger->warn("Connection pool reaching capacity: {}/100", 95);
    db_logger->debug("Closing connection");
    
    db_logger->close();
    
    auto lines = readFileLines(db_log);
    EXPECT_EQ(lines.size(), 8);
}

// ==================== Main Function ====================

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
