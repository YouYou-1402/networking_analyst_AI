// tests/unit/test_common_utils.cpp
#include <gtest/gtest.h>
#include "../../src/common/utils.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace NetworkSecurity::Common;

class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Tạo thư mục test tạm thời
        test_dir = "/tmp/utils_test_" + std::to_string(Utils::getCurrentTimestampMs());
        Utils::createDirectory(test_dir);
    }

    void TearDown() override {
        // Dọn dẹp thư mục test
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    std::string test_dir;
};

// ==================== Time utilities tests ====================
TEST_F(UtilsTest, GetCurrentTimestamp) {
    std::string timestamp = Utils::getCurrentTimestamp();
    EXPECT_FALSE(timestamp.empty());
    EXPECT_GT(timestamp.length(), 19); // "YYYY-MM-DD HH:MM:SS" + milliseconds
    
    // Kiểm tra format cơ bản
    EXPECT_EQ(timestamp[4], '-');
    EXPECT_EQ(timestamp[7], '-');
    EXPECT_EQ(timestamp[10], ' ');
    EXPECT_EQ(timestamp[13], ':');
    EXPECT_EQ(timestamp[16], ':');
}

TEST_F(UtilsTest, GetCurrentTimestampMs) {
    uint64_t timestamp1 = Utils::getCurrentTimestampMs();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    uint64_t timestamp2 = Utils::getCurrentTimestampMs();
    
    EXPECT_GT(timestamp1, 0);
    EXPECT_GT(timestamp2, timestamp1);
    EXPECT_GE(timestamp2 - timestamp1, 10);
}

TEST_F(UtilsTest, GetCurrentTimestampUs) {
    uint64_t timestamp1 = Utils::getCurrentTimestampUs();
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    uint64_t timestamp2 = Utils::getCurrentTimestampUs();
    
    EXPECT_GT(timestamp1, 0);
    EXPECT_GT(timestamp2, timestamp1);
    EXPECT_GE(timestamp2 - timestamp1, 100);
}

TEST_F(UtilsTest, FormatTimestamp) {
    uint64_t timestamp = 1609459200000; // 2021-01-01 00:00:00 UTC
    std::string formatted = Utils::formatTimestamp(timestamp);
    EXPECT_FALSE(formatted.empty());
    EXPECT_GT(formatted.length(), 19);
}

TEST_F(UtilsTest, FormatTimestampWithFormat) {
    uint64_t timestamp = 1609459200000; // 2021-01-01 00:00:00 UTC
    std::string formatted = Utils::formatTimestamp(timestamp, "%Y-%m-%d");
    EXPECT_FALSE(formatted.empty());
    // Note: Kết quả có thể khác tùy theo timezone local
}

TEST_F(UtilsTest, TimeDifference) {
    uint64_t start = 1000;
    uint64_t end = 2500;
    
    EXPECT_EQ(Utils::timeDifference(start, end), 1500);
    EXPECT_EQ(Utils::timeDifference(end, start), 0); // end < start
    EXPECT_EQ(Utils::timeDifference(start, start), 0); // same time
}

// ==================== String utilities tests ====================
TEST_F(UtilsTest, SplitByChar) {
    std::string str = "hello,world,test";
    auto result = Utils::split(str, ',');
    
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "hello");
    EXPECT_EQ(result[1], "world");
    EXPECT_EQ(result[2], "test");
}

TEST_F(UtilsTest, SplitByString) {
    std::string str = "hello::world::test";
    auto result = Utils::split(str, "::");
    
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "hello");
    EXPECT_EQ(result[1], "world");
    EXPECT_EQ(result[2], "test");
}

TEST_F(UtilsTest, SplitEmptyString) {
    auto result = Utils::split("", ',');
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "");
}

TEST_F(UtilsTest, SplitNoDelimiter) {
    auto result = Utils::split("hello", ',');
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "hello");
}

TEST_F(UtilsTest, Trim) {
    EXPECT_EQ(Utils::trim("  hello  "), "hello");
    EXPECT_EQ(Utils::trim("\t\ntest\r\n"), "test");
    EXPECT_EQ(Utils::trim(""), "");
    EXPECT_EQ(Utils::trim("   "), "");
    EXPECT_EQ(Utils::trim("no_spaces"), "no_spaces");
}

TEST_F(UtilsTest, TrimWithChars) {
    EXPECT_EQ(Utils::trim("xxhelloxx", "x"), "hello");
    EXPECT_EQ(Utils::trim("abcdefcba", "abc"), "def");
    EXPECT_EQ(Utils::trim("", "x"), "");
    EXPECT_EQ(Utils::trim("xxx", "x"), "");
}

TEST_F(UtilsTest, ToLowerCase) {
    EXPECT_EQ(Utils::toLowerCase("HELLO"), "hello");
    EXPECT_EQ(Utils::toLowerCase("Hello World"), "hello world");
    EXPECT_EQ(Utils::toLowerCase("123ABC"), "123abc");
    EXPECT_EQ(Utils::toLowerCase(""), "");
}

TEST_F(UtilsTest, ToUpperCase) {
    EXPECT_EQ(Utils::toUpperCase("hello"), "HELLO");
    EXPECT_EQ(Utils::toUpperCase("Hello World"), "HELLO WORLD");
    EXPECT_EQ(Utils::toUpperCase("123abc"), "123ABC");
    EXPECT_EQ(Utils::toUpperCase(""), "");
}

TEST_F(UtilsTest, StartsWith) {
    EXPECT_TRUE(Utils::startsWith("hello world", "hello"));
    EXPECT_TRUE(Utils::startsWith("test", "test"));
    EXPECT_TRUE(Utils::startsWith("abc", ""));
    EXPECT_FALSE(Utils::startsWith("hello", "world"));
    EXPECT_FALSE(Utils::startsWith("", "test"));
    EXPECT_FALSE(Utils::startsWith("short", "longer_string"));
}

TEST_F(UtilsTest, EndsWith) {
    EXPECT_TRUE(Utils::endsWith("hello world", "world"));
    EXPECT_TRUE(Utils::endsWith("test", "test"));
    EXPECT_TRUE(Utils::endsWith("abc", ""));
    EXPECT_FALSE(Utils::endsWith("hello", "world"));
    EXPECT_FALSE(Utils::endsWith("", "test"));
    EXPECT_FALSE(Utils::endsWith("short", "longer_string"));
}

TEST_F(UtilsTest, ReplaceAll) {
    EXPECT_EQ(Utils::replaceAll("hello world hello", "hello", "hi"), "hi world hi");
    EXPECT_EQ(Utils::replaceAll("test", "test", "replaced"), "replaced");
    EXPECT_EQ(Utils::replaceAll("no_match", "xyz", "abc"), "no_match");
    EXPECT_EQ(Utils::replaceAll("", "a", "b"), "");
    EXPECT_EQ(Utils::replaceAll("test", "", "x"), "test"); // empty 'from'
}

TEST_F(UtilsTest, Join) {
    std::vector<std::string> strings = {"hello", "world", "test"};
    EXPECT_EQ(Utils::join(strings, ", "), "hello, world, test");
    EXPECT_EQ(Utils::join(strings, ""), "helloworldtest");
    
    std::vector<std::string> empty_vec;
    EXPECT_EQ(Utils::join(empty_vec, ","), "");
    
    std::vector<std::string> single = {"only"};
    EXPECT_EQ(Utils::join(single, ","), "only");
}

TEST_F(UtilsTest, ContainsIgnoreCase) {
    EXPECT_TRUE(Utils::containsIgnoreCase("Hello World", "hello"));
    EXPECT_TRUE(Utils::containsIgnoreCase("TEST", "est"));
    EXPECT_TRUE(Utils::containsIgnoreCase("abc", "ABC"));
    EXPECT_FALSE(Utils::containsIgnoreCase("hello", "xyz"));
    EXPECT_TRUE(Utils::containsIgnoreCase("anything", ""));
}

// ==================== Hash utilities tests ====================
TEST_F(UtilsTest, CalculateMD5String) {
    std::string result = Utils::calculateMD5("hello");
    EXPECT_EQ(result.length(), 32); // MD5 is 32 hex chars
    EXPECT_EQ(result, "5d41402abc4b2a76b9719d911017c592");
    
    // Test empty string
    std::string empty_result = Utils::calculateMD5("");
    EXPECT_EQ(empty_result.length(), 32);
}

TEST_F(UtilsTest, CalculateMD5Binary) {
    const char* data = "hello";
    std::string result = Utils::calculateMD5(data, 5);
    EXPECT_EQ(result.length(), 32);
    EXPECT_EQ(result, "5d41402abc4b2a76b9719d911017c592");
}

TEST_F(UtilsTest, CalculateSHA256String) {
    std::string result = Utils::calculateSHA256("hello");
    EXPECT_EQ(result.length(), 64); // SHA256 is 64 hex chars
    // Đúng SHA256 của "hello"
    EXPECT_EQ(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    
    // Test empty string
    std::string empty_result = Utils::calculateSHA256("");
    EXPECT_EQ(empty_result.length(), 64);
}

TEST_F(UtilsTest, CalculateSHA256Binary) {
    const char* data = "hello";
    std::string result = Utils::calculateSHA256(data, 5);
    EXPECT_EQ(result.length(), 64);
    // Should be same as string version
    EXPECT_EQ(result, Utils::calculateSHA256("hello"));
}

TEST_F(UtilsTest, CalculateCRC32) {
    const char* data = "hello";
    uint32_t result = Utils::calculateCRC32(data, 5);
    EXPECT_GT(result, 0);
    
    // Same data should give same CRC
    uint32_t result2 = Utils::calculateCRC32(data, 5);
    EXPECT_EQ(result, result2);
    
    // Different data should give different CRC (usually)
    uint32_t result3 = Utils::calculateCRC32("world", 5);
    EXPECT_NE(result, result3);
}

TEST_F(UtilsTest, HashString) {
    uint64_t hash1 = Utils::hashString("hello");
    uint64_t hash2 = Utils::hashString("hello");
    uint64_t hash3 = Utils::hashString("world");
    
    EXPECT_EQ(hash1, hash2); // Same string, same hash
    EXPECT_NE(hash1, hash3); // Different strings, different hash (usually)
    EXPECT_GT(hash1, 0);
}

// ==================== File utilities tests ====================
TEST_F(UtilsTest, FileExists) {
    std::string test_file = test_dir + "/test_file.txt";
    
    EXPECT_FALSE(Utils::fileExists(test_file));
    
    // Create file
    std::ofstream file(test_file);
    file << "test content";
    file.close();
    
    EXPECT_TRUE(Utils::fileExists(test_file));
    
    // Test with directory (should return false)
    EXPECT_FALSE(Utils::fileExists(test_dir));
}

TEST_F(UtilsTest, DirectoryExists) {
    EXPECT_TRUE(Utils::directoryExists(test_dir));
    EXPECT_FALSE(Utils::directoryExists(test_dir + "/nonexistent"));
    
    // Test with file (should return false)
    std::string test_file = test_dir + "/test_file.txt";
    std::ofstream file(test_file);
    file.close();
    EXPECT_FALSE(Utils::directoryExists(test_file));
}

TEST_F(UtilsTest, CreateDirectory) {
    std::string new_dir = test_dir + "/new_directory";
    EXPECT_FALSE(Utils::directoryExists(new_dir));
    
    EXPECT_TRUE(Utils::createDirectory(new_dir));
    EXPECT_TRUE(Utils::directoryExists(new_dir));
    
    // Test creating existing directory
    EXPECT_TRUE(Utils::createDirectory(new_dir));
    
    // Test creating nested directories
    std::string nested_dir = test_dir + "/level1/level2/level3";
    EXPECT_TRUE(Utils::createDirectory(nested_dir));
    EXPECT_TRUE(Utils::directoryExists(nested_dir));
}

TEST_F(UtilsTest, ReadWriteFileString) {
    std::string test_file = test_dir + "/test_string.txt";
    std::string content = "Hello, World!\nThis is a test file.";
    
    // Write file
    EXPECT_TRUE(Utils::writeStringToFile(test_file, content));
    EXPECT_TRUE(Utils::fileExists(test_file));
    
    // Read file
    std::string read_content = Utils::readFileToString(test_file);
    EXPECT_EQ(read_content, content);
    
    // Test append
    std::string append_content = "\nAppended line";
    EXPECT_TRUE(Utils::writeStringToFile(test_file, append_content, true));
    
    std::string final_content = Utils::readFileToString(test_file);
    EXPECT_EQ(final_content, content + append_content);
}

TEST_F(UtilsTest, ReadWriteFileBytes) {
    std::string test_file = test_dir + "/test_bytes.bin";
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0xFF, 0x00, 0xAB, 0xCD};
    
    // Write bytes
    EXPECT_TRUE(Utils::writeBytesToFile(test_file, data));
    EXPECT_TRUE(Utils::fileExists(test_file));
    
    // Read bytes
    std::vector<uint8_t> read_data = Utils::readFileToBytes(test_file);
    EXPECT_EQ(read_data, data);
    
    // Test append
    std::vector<uint8_t> append_data = {0xEF, 0x12};
    EXPECT_TRUE(Utils::writeBytesToFile(test_file, append_data, true));
    
    std::vector<uint8_t> final_data = Utils::readFileToBytes(test_file);
    std::vector<uint8_t> expected = data;
    expected.insert(expected.end(), append_data.begin(), append_data.end());
    EXPECT_EQ(final_data, expected);
}

TEST_F(UtilsTest, GetFileSize) {
    std::string test_file = test_dir + "/size_test.txt";
    std::string content = "1234567890"; // 10 bytes
    
    EXPECT_EQ(Utils::getFileSize(test_file), 0); // Non-existent file
    
    Utils::writeStringToFile(test_file, content);
    EXPECT_EQ(Utils::getFileSize(test_file), 10);
}

TEST_F(UtilsTest, GetFileModificationTime) {
    std::string test_file = test_dir + "/mod_time_test.txt";
    
    EXPECT_EQ(Utils::getFileModificationTime(test_file), 0); // Non-existent file
    
    uint64_t before = Utils::getCurrentTimestampMs();
    Utils::writeStringToFile(test_file, "test");
    uint64_t after = Utils::getCurrentTimestampMs();
    
    uint64_t mod_time = Utils::getFileModificationTime(test_file);
    EXPECT_GE(mod_time, before);
    EXPECT_LE(mod_time, after + 1000); // Allow some tolerance
}

TEST_F(UtilsTest, GetFileName) {
    EXPECT_EQ(Utils::getFileName("/path/to/file.txt"), "file.txt");
    EXPECT_EQ(Utils::getFileName("file.txt"), "file.txt");
    EXPECT_EQ(Utils::getFileName("/path/to/dir/"), "");
    EXPECT_EQ(Utils::getFileName(""), "");
}

TEST_F(UtilsTest, GetDirectoryName) {
    EXPECT_EQ(Utils::getDirectoryName("/path/to/file.txt"), "/path/to");
    EXPECT_EQ(Utils::getDirectoryName("file.txt"), ".");
    EXPECT_EQ(Utils::getDirectoryName("/file.txt"), "");
    EXPECT_EQ(Utils::getDirectoryName(""), ".");
}

TEST_F(UtilsTest, GetFileExtension) {
    EXPECT_EQ(Utils::getFileExtension("file.txt"), ".txt");
    EXPECT_EQ(Utils::getFileExtension("archive.tar.gz"), ".gz");
    EXPECT_EQ(Utils::getFileExtension("noextension"), "");
    EXPECT_EQ(Utils::getFileExtension(".hidden"), "");
    EXPECT_EQ(Utils::getFileExtension("/path/to/file.cpp"), ".cpp");
}

// ==================== Memory utilities tests ====================
TEST_F(UtilsTest, FormatBytes) {
    EXPECT_EQ(Utils::formatBytes(0), "0.00 B");
    EXPECT_EQ(Utils::formatBytes(512), "512.00 B");
    EXPECT_EQ(Utils::formatBytes(1024), "1.00 KB");
    EXPECT_EQ(Utils::formatBytes(1536), "1.50 KB"); // 1.5 KB
    EXPECT_EQ(Utils::formatBytes(1024 * 1024), "1.00 MB");
    EXPECT_EQ(Utils::formatBytes(1024ULL * 1024 * 1024), "1.00 GB");
}

TEST_F(UtilsTest, BytesToHex) {
    uint8_t data[] = {0x01, 0x23, 0xAB, 0xCD, 0xEF};
    std::string hex = Utils::bytesToHex(data, sizeof(data));
    EXPECT_EQ(hex, "0123abcdef");
    
    // Test empty data
    std::string empty_hex = Utils::bytesToHex(nullptr, 0);
    EXPECT_EQ(empty_hex, "");
}

TEST_F(UtilsTest, HexToBytes) {
    std::string hex = "0123abcdef";
    std::vector<uint8_t> bytes = Utils::hexToBytes(hex);
    
    std::vector<uint8_t> expected = {0x01, 0x23, 0xAB, 0xCD, 0xEF};
    EXPECT_EQ(bytes, expected);
    
    // Test empty hex
    std::vector<uint8_t> empty_bytes = Utils::hexToBytes("");
    EXPECT_TRUE(empty_bytes.empty());
    
    // Test odd length (should ignore last char)
    std::vector<uint8_t> odd_bytes = Utils::hexToBytes("123");
    EXPECT_EQ(odd_bytes.size(), 1);
    EXPECT_EQ(odd_bytes[0], 0x12);
}

TEST_F(UtilsTest, HexDump) {
    const char* data = "Hello";
    std::stringstream ss;
    
    Utils::hexDump(data, 5, ss);
    std::string output = ss.str();
    
    // Kiểm tra có chứa các byte hex (có thể có space)
    EXPECT_NE(output.find("48"), std::string::npos); // 'H'
    EXPECT_NE(output.find("65"), std::string::npos); // 'e'
    EXPECT_NE(output.find("6c"), std::string::npos); // 'l'
    EXPECT_NE(output.find("6f"), std::string::npos); // 'o'
    
    // Kiểm tra có chứa ASCII representation
    EXPECT_NE(output.find("Hello"), std::string::npos);
    
    // Kiểm tra có offset
    EXPECT_NE(output.find("00000000:"), std::string::npos);
}


TEST_F(UtilsTest, SecureMemoryCompare) {
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data2[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t data3[] = {0x01, 0x02, 0x03, 0x05};
    
    EXPECT_TRUE(Utils::secureMemoryCompare(data1, data2, 4));
    EXPECT_FALSE(Utils::secureMemoryCompare(data1, data3, 4));
    EXPECT_TRUE(Utils::secureMemoryCompare(data1, data3, 3)); // First 3 bytes are same
}

// ==================== System utilities tests ====================
TEST_F(UtilsTest, GetCPUCount) {
    int cpu_count = Utils::getCPUCount();
    EXPECT_GT(cpu_count, 0);
    EXPECT_LE(cpu_count, 1024); // Reasonable upper bound
}

TEST_F(UtilsTest, GetMemoryUsage) {
    size_t memory = Utils::getMemoryUsage();
    // Memory usage should be positive (this process is using some memory)
    EXPECT_GT(memory, 0);
}

TEST_F(UtilsTest, GetTotalSystemMemory) {
    size_t total_memory = Utils::getTotalSystemMemory();
    // Should be positive on Linux systems
    #ifdef __linux__
    EXPECT_GT(total_memory, 0);
    #endif
}

TEST_F(UtilsTest, GetAvailableSystemMemory) {
    size_t available_memory = Utils::getAvailableSystemMemory();
    // Should be positive on Linux systems
    #ifdef __linux__
    EXPECT_GT(available_memory, 0);
    #endif
}

// ==================== Edge cases and error handling ====================
TEST_F(UtilsTest, ReadNonExistentFile) {
    std::string content = Utils::readFileToString("/nonexistent/file.txt");
    EXPECT_EQ(content, "");
    
    std::vector<uint8_t> bytes = Utils::readFileToBytes("/nonexistent/file.txt");
    EXPECT_TRUE(bytes.empty());
}

TEST_F(UtilsTest, WriteToInvalidPath) {
    // Try to write to a path that doesn't exist and can't be created
    bool result = Utils::writeStringToFile("/root/invalid/path/file.txt", "test");
    EXPECT_FALSE(result);
}

TEST_F(UtilsTest, HashEmptyData) {
    std::string md5_empty = Utils::calculateMD5("");
    EXPECT_EQ(md5_empty.length(), 32);
    
    std::string sha256_empty = Utils::calculateSHA256("");
    EXPECT_EQ(sha256_empty.length(), 64);
    
    uint32_t crc32_empty = Utils::calculateCRC32("", 0);
    EXPECT_EQ(crc32_empty, 0);
}

TEST_F(UtilsTest, StringUtilsEdgeCases) {
    // Test with unicode/special characters
    std::string unicode = "Hello 世界 🌍";
    EXPECT_FALSE(Utils::toLowerCase(unicode).empty());
    EXPECT_FALSE(Utils::toUpperCase(unicode).empty());
    
    // Test split with consecutive delimiters
    auto result = Utils::split("a,,b", ',');
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[1], ""); // Empty string between delimiters
}

// Test main function
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
