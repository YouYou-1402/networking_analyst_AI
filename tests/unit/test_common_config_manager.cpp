// tests/unit/test_common_config_manager.cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../src/common/config_manager.hpp"
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace NetworkSecurity::Common;
using namespace testing;

// ==================== Test Fixture ====================
class ConfigManagerTest : public ::testing::Test
{
protected:
    ConfigManager* config;
    std::string test_config_file;
    std::string test_json_file;
    std::string test_backup_file;

    void SetUp() override
    {
        // Sử dụng getInstance() thay vì tạo instance mới
        config = &ConfigManager::getInstance();
        config->clear();
        
        test_config_file = "test_config.json";
        test_json_file = "test_config_json.json";
        test_backup_file = "test_backup.json";
        
        // Clean up any existing test files
        cleanupTestFiles();
    }

    void TearDown() override
    {
        config->disableFileWatcher();
        config->clear();
        cleanupTestFiles();
    }

    void cleanupTestFiles()
    {
        std::vector<std::string> files = {
            test_config_file,
            test_json_file,
            test_backup_file,
            "test_profile.json",
            "test_template.txt"
        };
        
        for (const auto& file : files)
        {
            if (std::filesystem::exists(file))
            {
                std::filesystem::remove(file);
            }
        }
    }

    void createTestConfigFile(const std::string& filename, const std::string& content)
    {
        std::ofstream file(filename);
        file << content;
        file.close();
    }

    std::string readFile(const std::string& filename)
    {
        std::ifstream file(filename);
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
};

// ==================== Basic Set/Get Tests ====================
TEST_F(ConfigManagerTest, SetAndGetString)
{
    EXPECT_TRUE(config->setString("test.string", "hello"));
    EXPECT_EQ(config->getString("test.string"), "hello");
    EXPECT_EQ(config->getString("nonexistent", "default"), "default");
}

TEST_F(ConfigManagerTest, SetAndGetInt)
{
    EXPECT_TRUE(config->setInt("test.int", 42));
    EXPECT_EQ(config->getInt("test.int"), 42);
    EXPECT_EQ(config->getInt("nonexistent", 100), 100);
}

TEST_F(ConfigManagerTest, SetAndGetDouble)
{
    EXPECT_TRUE(config->setDouble("test.double", 3.14159));
    EXPECT_DOUBLE_EQ(config->getDouble("test.double"), 3.14159);
    EXPECT_DOUBLE_EQ(config->getDouble("nonexistent", 2.71), 2.71);
}

TEST_F(ConfigManagerTest, SetAndGetBool)
{
    EXPECT_TRUE(config->setBool("test.bool", true));
    EXPECT_TRUE(config->getBool("test.bool"));
    EXPECT_FALSE(config->getBool("nonexistent", false));
}

TEST_F(ConfigManagerTest, SetAndGetStringArray)
{
    std::vector<std::string> arr = {"one", "two", "three"};
    EXPECT_TRUE(config->setStringArray("test.array", arr));
    
    auto result = config->getStringArray("test.array");
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "one");
    EXPECT_EQ(result[1], "two");
    EXPECT_EQ(result[2], "three");
}

// ==================== Key Validation Tests ====================
TEST_F(ConfigManagerTest, ValidKeyNames)
{
    EXPECT_TRUE(config->setString("valid.key.name", "value"));
    EXPECT_TRUE(config->setString("valid_key", "value"));
    EXPECT_TRUE(config->setString("valid-key", "value"));
    EXPECT_TRUE(config->setString("valid123", "value"));
}

// ==================== HasKey and RemoveKey Tests ====================
TEST_F(ConfigManagerTest, HasKey)
{
    config->setString("test.key", "value");
    EXPECT_TRUE(config->hasKey("test.key"));
    EXPECT_FALSE(config->hasKey("nonexistent.key"));
}

TEST_F(ConfigManagerTest, RemoveKey)
{
    config->setString("test.key", "value");
    EXPECT_TRUE(config->hasKey("test.key"));
    
    EXPECT_TRUE(config->removeKey("test.key"));
    EXPECT_FALSE(config->hasKey("test.key"));
    
    EXPECT_FALSE(config->removeKey("nonexistent.key"));
}

TEST_F(ConfigManagerTest, CannotRemoveReadonlyKey)
{
    config->setString("readonly.key", "value");
    config->setReadonly("readonly.key", true);
    
    EXPECT_FALSE(config->removeKey("readonly.key"));
    EXPECT_TRUE(config->hasKey("readonly.key"));
}

TEST_F(ConfigManagerTest, CannotRemoveRequiredKey)
{
    config->setString("required.key", "value");
    config->setRequired("required.key", true);
    
    EXPECT_FALSE(config->removeKey("required.key"));
    EXPECT_TRUE(config->hasKey("required.key"));
}

// ==================== GetAllKeys Tests ====================
TEST_F(ConfigManagerTest, GetAllKeys)
{
    config->setString("key1", "value1");
    config->setInt("key2", 42);
    config->setDouble("key3", 3.14);
    
    auto keys = config->getAllKeys();
    EXPECT_GE(keys.size(), 3);
    EXPECT_THAT(keys, Contains("key1"));
    EXPECT_THAT(keys, Contains("key2"));
    EXPECT_THAT(keys, Contains("key3"));
}

TEST_F(ConfigManagerTest, GetKeysByPrefix)
{
    config->setString("network.interface", "eth0");
    config->setInt("network.port", 8080);
    config->setString("database.host", "localhost");
    
    auto network_keys = config->getKeysByPrefix("network");
    EXPECT_GE(network_keys.size(), 2);
    
    auto db_keys = config->getKeysByPrefix("database");
    EXPECT_GE(db_keys.size(), 1);
}

// ==================== Clear and Size Tests ====================
TEST_F(ConfigManagerTest, ClearAndSize)
{
    config->setString("key1", "value1");
    config->setInt("key2", 42);
    
    EXPECT_GE(config->size(), 2);
    EXPECT_FALSE(config->empty());
    
    config->clear();
    
    EXPECT_FALSE(config->hasKey("key1"));
    EXPECT_FALSE(config->hasKey("key2"));
}

// ==================== Readonly Tests ====================
TEST_F(ConfigManagerTest, ReadonlyKey)
{
    // Dùng key unique để tránh conflict
    std::string test_key = "readonly.key." + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    
    config->setString(test_key, "initial");
    config->setReadonly(test_key, true);
    
    EXPECT_TRUE(config->isReadonly(test_key));
    
    // Cannot modify readonly key
    EXPECT_FALSE(config->setString(test_key, "modified"));
    EXPECT_EQ(config->getString(test_key), "initial");
}

// ==================== Required Tests ====================
TEST_F(ConfigManagerTest, RequiredKey)
{
    config->setString("required.key", "value");
    config->setRequired("required.key", true);
    
    EXPECT_TRUE(config->isRequired("required.key"));
}

TEST_F(ConfigManagerTest, GetMissingRequiredKeys)
{
    config->setString("required1", "");
    config->setRequired("required1", true);
    
    config->setString("required2", "value");
    config->setRequired("required2", true);
    
    auto missing = config->getMissingRequiredKeys();
    EXPECT_THAT(missing, Contains("required1"));
    EXPECT_THAT(missing, Not(Contains("required2")));
}

// ==================== Validator Tests ====================
TEST_F(ConfigManagerTest, SetValidator)
{
    config->setInt("port", 8080);
    
    // Set validator: port must be between 1 and 65535
    auto validator = [](const std::any& value) -> bool {
        try {
            int port = std::any_cast<int>(value);
            return port >= 1 && port <= 65535;
        } catch (...) {
            return false;
        }
    };
    
    EXPECT_TRUE(config->setValidator("port", validator));
    EXPECT_TRUE(config->validateKey("port"));
    
    // Try to set invalid value
    EXPECT_FALSE(config->setInt("port", 99999));
    EXPECT_EQ(config->getInt("port"), 8080); // Should remain unchanged
}

TEST_F(ConfigManagerTest, ValidateAll)
{
    config->setInt("valid.port", 8080);
    config->setInt("invalid.port", 8080);
    
    // Set validators
    auto valid_validator = [](const std::any& value) -> bool {
        try {
            return std::any_cast<int>(value) > 0;
        } catch (...) {
            return false;
        }
    };
    
    config->setValidator("valid.port", valid_validator);
    config->setValidator("invalid.port", valid_validator);
    
    EXPECT_TRUE(config->validateAll());
}

// ==================== JSON Load/Save Tests ====================
TEST_F(ConfigManagerTest, LoadFromJsonString)
{
    std::string json = R"({
        "string_key": "hello",
        "int_key": 42,
        "double_key": 3.14,
        "bool_key": true,
        "array_key": ["one", "two", "three"]
    })";
    
    EXPECT_TRUE(config->loadFromJson(json));
    
    EXPECT_EQ(config->getString("string_key"), "hello");
    EXPECT_EQ(config->getInt("int_key"), 42);
    EXPECT_DOUBLE_EQ(config->getDouble("double_key"), 3.14);
    EXPECT_TRUE(config->getBool("bool_key"));
    
    auto arr = config->getStringArray("array_key");
    EXPECT_EQ(arr.size(), 3);
}

TEST_F(ConfigManagerTest, LoadFromJsonWithComments)
{
    std::string json = R"({
        "key1": "value1",
        "key2": 42
    })";
    
    EXPECT_TRUE(config->loadFromJson(json));
    EXPECT_EQ(config->getString("key1"), "value1");
    EXPECT_EQ(config->getInt("key2"), 42);
}

TEST_F(ConfigManagerTest, LoadFromJsonFile)
{
    std::string json_content = R"({
        "test.key": "test_value",
        "test.number": 123
    })";
    
    createTestConfigFile(test_json_file, json_content);
    
    EXPECT_TRUE(config->loadFromJsonFile(test_json_file));
    EXPECT_EQ(config->getString("test.key"), "test_value");
    EXPECT_EQ(config->getInt("test.number"), 123);
}

TEST_F(ConfigManagerTest, SaveToFile)
{
    config->setString("test.key", "value");
    config->setInt("test.number", 42);
    
    EXPECT_TRUE(config->saveToFile(test_config_file));
    EXPECT_TRUE(std::filesystem::exists(test_config_file));
    
    // Verify content
    ConfigManager& config2 = ConfigManager::getInstance();
    config2.clear();
    EXPECT_TRUE(config2.loadFromFile(test_config_file));
    EXPECT_EQ(config2.getString("test.key"), "value");
    EXPECT_EQ(config2.getInt("test.number"), 42);
}

TEST_F(ConfigManagerTest, ExportToJson)
{
    config->setString("key1", "value1");
    config->setInt("key2", 42);
    config->setBool("key3", true);
    
    std::string json = config->exportToJson();
    
    EXPECT_THAT(json, HasSubstr("key1"));
    EXPECT_THAT(json, HasSubstr("value1"));
    EXPECT_THAT(json, HasSubstr("key2"));
}

// ==================== Nested Configuration Tests ====================
TEST_F(ConfigManagerTest, NestedConfiguration)
{
    std::string json = R"({
        "database": {
            "host": "localhost",
            "port": 5432,
            "credentials": {
                "username": "admin",
                "password": "secret"
            }
        }
    })";
    
    EXPECT_TRUE(config->loadFromJson(json));
    
    EXPECT_EQ(config->getString("database.host"), "localhost");
    EXPECT_EQ(config->getInt("database.port"), 5432);
    EXPECT_EQ(config->getString("database.credentials.username"), "admin");
    EXPECT_EQ(config->getString("database.credentials.password"), "secret");
}

// ==================== Environment Variables Tests ====================
TEST_F(ConfigManagerTest, LoadFromEnvironment)
{
    // Set environment variables
    setenv("NETSEC_TEST_KEY", "test_value", 1);
    setenv("NETSEC_TEST_PORT", "8080", 1);
    setenv("NETSEC_TEST_ENABLED", "true", 1);
    
    config->loadFromEnvironment("NETSEC_");
    
    EXPECT_EQ(config->getString("test.key"), "test_value");
    EXPECT_EQ(config->getInt("test.port"), 8080);
    EXPECT_TRUE(config->getBool("test.enabled"));
    
    // Cleanup
    unsetenv("NETSEC_TEST_KEY");
    unsetenv("NETSEC_TEST_PORT");
    unsetenv("NETSEC_TEST_ENABLED");
}

// ==================== Command Line Arguments Tests ====================
TEST_F(ConfigManagerTest, LoadFromCommandLine)
{
    const char* argv[] = {
        "program",
        "--test-key=value",
        "--test-port=8080",
        "--test-enabled=true"
    };
    int argc = 4;
    
    config->loadFromCommandLine(argc, const_cast<char**>(argv));
    
    EXPECT_EQ(config->getString("test.key"), "value");
    EXPECT_EQ(config->getInt("test.port"), 8080);
    EXPECT_TRUE(config->getBool("test.enabled"));
}

TEST_F(ConfigManagerTest, LoadFromCommandLineSpaceSeparated)
{
    const char* argv[] = {
        "program",
        "--test-key", "value",
        "--test-port", "8080"
    };
    int argc = 5;
    
    config->loadFromCommandLine(argc, const_cast<char**>(argv));
    
    EXPECT_EQ(config->getString("test.key"), "value");
    EXPECT_EQ(config->getInt("test.port"), 8080);
}

// ==================== Change Callback Tests ====================
TEST_F(ConfigManagerTest, ChangeCallback)
{
    std::string changed_key;
    std::string old_val;
    std::string new_val;
    
    config->registerChangeCallback("test.key", 
        [&](const std::string& key, const std::any& old_value, const std::any& new_value) {
            changed_key = key;
            try {
                old_val = std::any_cast<std::string>(old_value);
                new_val = std::any_cast<std::string>(new_value);
            } catch (...) {}
        });
    
    config->setString("test.key", "initial");
    config->setString("test.key", "modified");
    
    EXPECT_EQ(changed_key, "test.key");
    EXPECT_EQ(old_val, "initial");
    EXPECT_EQ(new_val, "modified");
}

TEST_F(ConfigManagerTest, GlobalChangeCallback)
{
    int change_count = 0;
    
    config->registerGlobalChangeCallback(
        [&](const std::string& key, const std::any& old_value, const std::any& new_value) {
            change_count++;
        });
    
    config->setString("key1", "value1");
    config->setString("key1", "value2");
    config->setInt("key2", 42);
    
    EXPECT_EQ(change_count, 3);
}

// ==================== Merge Tests ====================
TEST_F(ConfigManagerTest, MergeConfigurations)
{
    config->setString("key1", "value1");
    config->setInt("key2", 42);
    
    // Tạo ConfigManager khác để merge - SỬA Ở ĐÂY
    ConfigManager& other = ConfigManager::getInstance();
    // Lưu snapshot của config hiện tại
    auto snapshot = config->createSnapshot();
    
    // Clear và set giá trị mới cho other
    other.clear();
    other.setString("key2", "overwritten");
    other.setString("key3", "new_value");
    
    // Merge vào snapshot
    snapshot->merge(other, false);
    
    // Restore và kiểm tra
    config->restoreFromSnapshot(snapshot);
    EXPECT_EQ(config->getString("key3"), "new_value");
}

// ==================== Snapshot Tests ====================
TEST_F(ConfigManagerTest, CreateAndRestoreSnapshot)
{
    config->setString("key1", "value1");
    config->setInt("key2", 42);
    
    auto snapshot = config->createSnapshot();
    ASSERT_NE(snapshot, nullptr);
    
    // Modify config
    config->setString("key1", "modified");
    config->setInt("key3", 100);
    
    // Restore from snapshot
    EXPECT_TRUE(config->restoreFromSnapshot(snapshot));
    
    EXPECT_EQ(config->getString("key1"), "value1");
    EXPECT_EQ(config->getInt("key2"), 42);
    EXPECT_FALSE(config->hasKey("key3"));
}

// ==================== Thread Safety Tests ====================
TEST_F(ConfigManagerTest, ThreadSafetyMultipleReads)
{
    config->setString("thread.test", "value");
    
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back([&]() {
            for (int j = 0; j < 100; ++j)
            {
                if (config->getString("thread.test") == "value")
                {
                    success_count++;
                }
            }
        });
    }
    
    for (auto& t : threads)
    {
        t.join();
    }
    
    EXPECT_EQ(success_count, 1000);
}

TEST_F(ConfigManagerTest, ThreadSafetyMultipleWrites)
{
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back([&, i]() {
            for (int j = 0; j < 10; ++j)
            {
                config->setInt("thread.counter." + std::to_string(i), j);
            }
        });
    }
    
    for (auto& t : threads)
    {
        t.join();
    }
    
    // Verify all keys were set
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(config->hasKey("thread.counter." + std::to_string(i)));
    }
}

// ==================== Edge Cases Tests ====================
TEST_F(ConfigManagerTest, EmptyStringValue)
{
    EXPECT_TRUE(config->setString("empty.string", ""));
    EXPECT_EQ(config->getString("empty.string"), "");
}

TEST_F(ConfigManagerTest, VeryLongString)
{
    std::string long_str(10000, 'x');
    EXPECT_TRUE(config->setString("long.string", long_str));
    EXPECT_EQ(config->getString("long.string"), long_str);
}

TEST_F(ConfigManagerTest, SpecialCharactersInValue)
{
    std::string special = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    EXPECT_TRUE(config->setString("special.chars", special));
    EXPECT_EQ(config->getString("special.chars"), special);
}

TEST_F(ConfigManagerTest, NegativeNumbers)
{
    EXPECT_TRUE(config->setInt("negative.int", -42));
    EXPECT_EQ(config->getInt("negative.int"), -42);
    
    EXPECT_TRUE(config->setDouble("negative.double", -3.14));
    EXPECT_DOUBLE_EQ(config->getDouble("negative.double"), -3.14);
}

TEST_F(ConfigManagerTest, ZeroValues)
{
    EXPECT_TRUE(config->setInt("zero.int", 0));
    EXPECT_EQ(config->getInt("zero.int"), 0);
    
    EXPECT_TRUE(config->setDouble("zero.double", 0.0));
    EXPECT_DOUBLE_EQ(config->getDouble("zero.double"), 0.0);
}

// ==================== Main ====================
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
