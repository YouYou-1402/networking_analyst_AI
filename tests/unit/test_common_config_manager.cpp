// tests/test_config_manager.cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <future>
#include "/media/linhlinh/learn/nckh/NetworkSecurityAI/src/common/config_manager.cpp"

using namespace NetworkSecurity::Common;
using namespace testing;

class ConfigManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Clear any existing configuration
        ConfigManager::getInstance().clear();
        
        // Create test directory
        test_dir_ = "test_configs";
        std::filesystem::create_directories(test_dir_);
        
        test_config_file_ = test_dir_ + "/test_config.json";
        test_backup_file_ = test_dir_ + "/test_backup.json";
    }

    void TearDown() override
    {
        // Clean up test files
        std::filesystem::remove_all(test_dir_);
        
        // Clear configuration
        ConfigManager::getInstance().clear();
        ConfigManager::getInstance().disableFileWatcher();
    }

    void createTestConfigFile(const std::string& content)
    {
        std::ofstream file(test_config_file_);
        file << content;
        file.close();
    }

    std::string test_dir_;
    std::string test_config_file_;
    std::string test_backup_file_;
};

// ==================== Basic Functionality Tests ====================
TEST_F(ConfigManagerTest, SingletonPattern)
{
    auto& instance1 = ConfigManager::getInstance();
    auto& instance2 = ConfigManager::getInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(ConfigManagerTest, BasicSetAndGet)
{
    auto& config = ConfigManager::getInstance();
    
    // Test string
    EXPECT_TRUE(config.setString("test.string", "hello"));
    EXPECT_EQ(config.getString("test.string"), "hello");
    EXPECT_EQ(config.getString("nonexistent", "default"), "default");
    
    // Test integer
    EXPECT_TRUE(config.setInt("test.int", 42));
    EXPECT_EQ(config.getInt("test.int"), 42);
    EXPECT_EQ(config.getInt("nonexistent", 100), 100);
    
    // Test double
    EXPECT_TRUE(config.setDouble("test.double", 3.14));
    EXPECT_DOUBLE_EQ(config.getDouble("test.double"), 3.14);
    EXPECT_DOUBLE_EQ(config.getDouble("nonexistent", 2.71), 2.71);
    
    // Test boolean
    EXPECT_TRUE(config.setBool("test.bool", true));
    EXPECT_TRUE(config.getBool("test.bool"));
    EXPECT_FALSE(config.getBool("nonexistent", false));
    
    // Test string array
    std::vector<std::string> test_array = {"item1", "item2", "item3"};
    EXPECT_TRUE(config.setStringArray("test.array", test_array));
    EXPECT_EQ(config.getStringArray("test.array"), test_array);
}

TEST_F(ConfigManagerTest, KeyValidation)
{
    auto& config = ConfigManager::getInstance();
    
    // Valid keys
    EXPECT_TRUE(config.setString("valid.key", "value"));
    EXPECT_TRUE(config.setString("valid_key", "value"));
    EXPECT_TRUE(config.setString("valid-key", "value"));
    EXPECT_TRUE(config.setString("valid123", "value"));
    
    // Invalid keys
    EXPECT_FALSE(config.setString("", "value"));           // Empty key
    EXPECT_FALSE(config.setString(".invalid", "value"));   // Starts with dot
    EXPECT_FALSE(config.setString("invalid.", "value"));   // Ends with dot
    EXPECT_FALSE(config.setString("invalid..key", "value")); // Double dots
}

TEST_F(ConfigManagerTest, UtilityMethods)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("test1", "value1");
    config.setString("test2", "value2");
    config.setString("other.key", "value3");
    
    // Test hasKey
    EXPECT_TRUE(config.hasKey("test1"));
    EXPECT_FALSE(config.hasKey("nonexistent"));
    
    // Test size and empty
    EXPECT_FALSE(config.empty());
    EXPECT_GE(config.size(), 3);
    
    // Test getAllKeys
    auto all_keys = config.getAllKeys();
    EXPECT_THAT(all_keys, Contains("test1"));
    EXPECT_THAT(all_keys, Contains("test2"));
    EXPECT_THAT(all_keys, Contains("other.key"));
    
    // Test getKeysByPrefix
    auto test_keys = config.getKeysByPrefix("test");
    EXPECT_THAT(test_keys, Contains("test1"));
    EXPECT_THAT(test_keys, Contains("test2"));
    EXPECT_THAT(test_keys, Not(Contains("other.key")));
    
    // Test removeKey
    EXPECT_TRUE(config.removeKey("test1"));
    EXPECT_FALSE(config.hasKey("test1"));
    EXPECT_FALSE(config.removeKey("nonexistent"));
}

// ==================== JSON Operations Tests ====================
TEST_F(ConfigManagerTest, JSONLoadAndSave)
{
    auto& config = ConfigManager::getInstance();
    
    std::string json_content = R"({
        "database": {
            "host": "localhost",
            "port": 5432,
            "enabled": true
        },
        "timeout": 30.5,
        "tags": ["tag1", "tag2", "tag3"]
    })";
    
    EXPECT_TRUE(config.loadFromJson(json_content));
    
    // Verify loaded values
    EXPECT_EQ(config.getString("database.host"), "localhost");
    EXPECT_EQ(config.getInt("database.port"), 5432);
    EXPECT_TRUE(config.getBool("database.enabled"));
    EXPECT_DOUBLE_EQ(config.getDouble("timeout"), 30.5);
    
    auto tags = config.getStringArray("tags");
    EXPECT_EQ(tags.size(), 3);
    EXPECT_EQ(tags[0], "tag1");
    
    // Test export
    std::string exported = config.exportToJson();
    EXPECT_FALSE(exported.empty());
    
    // Test file operations
    createTestConfigFile(json_content);
    
    config.clear();
    EXPECT_TRUE(config.loadFromFile(test_config_file_));
    EXPECT_EQ(config.getString("database.host"), "localhost");
    
    EXPECT_TRUE(config.saveToFile(test_backup_file_));
    EXPECT_TRUE(std::filesystem::exists(test_backup_file_));
}

TEST_F(ConfigManagerTest, JSONWithComments)
{
    auto& config = ConfigManager::getInstance();
    
    std::string json_with_comments = R"({
        // This is a single line comment
        "host": "localhost",
        /* This is a 
           multi-line comment */
        "port": 8080,
        "debug": true // End of line comment
    })";
    
    EXPECT_TRUE(config.loadFromJson(json_with_comments));
    EXPECT_EQ(config.getString("host"), "localhost");
    EXPECT_EQ(config.getInt("port"), 8080);
    EXPECT_TRUE(config.getBool("debug"));
}

TEST_F(ConfigManagerTest, InvalidJSON)
{
    auto& config = ConfigManager::getInstance();
    
    std::string invalid_json = R"({
        "host": "localhost",
        "port": 8080,
        "invalid": 
    })";
    
    EXPECT_FALSE(config.loadFromJson(invalid_json));
}

// ==================== Environment Variables Tests ====================
TEST_F(ConfigManagerTest, EnvironmentVariables)
{
    auto& config = ConfigManager::getInstance();
    
    // Set some environment variables
    setenv("NETSEC_DATABASE_HOST", "env_host", 1);
    setenv("NETSEC_DATABASE_PORT", "9999", 1);
    setenv("NETSEC_DEBUG_ENABLED", "true", 1);
    setenv("NETSEC_TIMEOUT", "45.5", 1);
    
    config.loadFromEnvironment("NETSEC_");
    
    EXPECT_EQ(config.getString("database.host"), "env_host");
    EXPECT_EQ(config.getInt("database.port"), 9999);
    EXPECT_TRUE(config.getBool("debug.enabled"));
    EXPECT_DOUBLE_EQ(config.getDouble("timeout"), 45.5);
    
    // Clean up
    unsetenv("NETSEC_DATABASE_HOST");
    unsetenv("NETSEC_DATABASE_PORT");
    unsetenv("NETSEC_DEBUG_ENABLED");
    unsetenv("NETSEC_TIMEOUT");
}

// ==================== Command Line Arguments Tests ====================
TEST_F(ConfigManagerTest, CommandLineArguments)
{
    auto& config = ConfigManager::getInstance();
    
    const char* argv[] = {
        "program",
        "--database-host=cmd_host",
        "--database-port", "7777",
        "--debug-enabled=true",
        "--timeout=60.0"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    config.loadFromCommandLine(argc, const_cast<char**>(argv));
    
    EXPECT_EQ(config.getString("database.host"), "cmd_host");
    EXPECT_EQ(config.getInt("database.port"), 7777);
    EXPECT_TRUE(config.getBool("debug.enabled"));
    EXPECT_DOUBLE_EQ(config.getDouble("timeout"), 60.0);
}

// ==================== Validation Tests ====================
TEST_F(ConfigManagerTest, RequiredKeys)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("required.key", "value");
    config.setRequired("required.key", true);
    
    EXPECT_TRUE(config.isRequired("required.key"));
    EXPECT_FALSE(config.isRequired("optional.key"));
    
    // Cannot remove required key
    EXPECT_FALSE(config.removeKey("required.key"));
    
    // Test missing required keys
    config.setString("empty.required", "");
    config.setRequired("empty.required", true);
    
    auto missing = config.getMissingRequiredKeys();
    EXPECT_THAT(missing, Contains("empty.required"));
}

TEST_F(ConfigManagerTest, ReadonlyKeys)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("readonly.key", "original");
    config.setReadonly("readonly.key", true);
    
    EXPECT_TRUE(config.isReadonly("readonly.key"));
    
    // Cannot modify readonly key
    EXPECT_FALSE(config.setString("readonly.key", "modified"));
    EXPECT_EQ(config.getString("readonly.key"), "original");
    
    // Cannot remove readonly key
    EXPECT_FALSE(config.removeKey("readonly.key"));
}

TEST_F(ConfigManagerTest, CustomValidators)
{
    auto& config = ConfigManager::getInstance();
    
    config.setInt("port", 8080);
    
    // Set validator for port range
    EXPECT_TRUE(config.setValidator("port", [](const std::any& value) {
        try {
            int port = std::any_cast<int>(value);
            return port > 0 && port < 65536;
        } catch (...) {
            return false;
        }
    }));
    
    EXPECT_TRUE(config.validateKey("port"));
    
    // Try to set invalid value
    EXPECT_FALSE(config.setInt("port", 70000)); // Should fail validation
    EXPECT_EQ(config.getInt("port"), 8080); // Should remain unchanged
    
    EXPECT_TRUE(config.setInt("port", 9090)); // Should succeed
    EXPECT_EQ(config.getInt("port"), 9090);
}

// ==================== Change Notifications Tests ====================
TEST_F(ConfigManagerTest, ChangeCallbacks)
{
    auto& config = ConfigManager::getInstance();
    
    std::string changed_key;
    std::string old_value, new_value;
    
    // Register callback
    config.registerChangeCallback("test.key", [&](const std::string& key, const std::any& old_val, const std::any& new_val) {
        changed_key = key;
        try {
            old_value = std::any_cast<std::string>(old_val);
            new_value = std::any_cast<std::string>(new_val);
        } catch (...) {}
    });
    
    config.setString("test.key", "initial");
    config.setString("test.key", "updated");
    
    EXPECT_EQ(changed_key, "test.key");
    EXPECT_EQ(old_value, "initial");
    EXPECT_EQ(new_value, "updated");
    
    config.unregisterChangeCallback("test.key");
}

TEST_F(ConfigManagerTest, GlobalChangeCallback)
{
    auto& config = ConfigManager::getInstance();
    
    std::vector<std::string> changed_keys;
    
    config.registerGlobalChangeCallback([&](const std::string& key, const std::any& old_val, const std::any& new_val) {
        changed_keys.push_back(key);
    });
    
    config.setString("key1", "value1");
    config.setString("key1", "value1_updated");
    config.setString("key2", "value2");
    
    EXPECT_THAT(changed_keys, Contains("key1"));
    EXPECT_THAT(changed_keys, Contains("key2"));
    
    config.unregisterGlobalChangeCallback();
}

// ==================== Advanced Features Tests ====================
TEST_F(ConfigManagerTest, ConfigMerging)
{
    auto& config1 = ConfigManager::getInstance();
    auto config2 = config1.createSnapshot();
    
    config1.setString("key1", "value1");
    config1.setString("common", "config1_value");
    
    config2->setString("key2", "value2");
    config2->setString("common", "config2_value");
    
    // Merge without overwrite
    EXPECT_TRUE(config1.merge(*config2, false));
    EXPECT_EQ(config1.getString("key1"), "value1");
    EXPECT_EQ(config1.getString("key2"), "value2");
    EXPECT_EQ(config1.getString("common"), "config1_value"); // Should not be overwritten
    
    // Merge with overwrite
    EXPECT_TRUE(config1.merge(*config2, true));
    EXPECT_EQ(config1.getString("common"), "config2_value"); // Should be overwritten
}

TEST_F(ConfigManagerTest, SnapshotAndRestore)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("key1", "value1");
    config.setInt("key2", 42);
    
    auto snapshot = config.createSnapshot();
    EXPECT_NE(snapshot, nullptr);
    
    // Modify original config
    config.setString("key1", "modified");
    config.setString("key3", "new_value");
    
    // Restore from snapshot
    EXPECT_TRUE(config.restoreFromSnapshot(snapshot));
    EXPECT_EQ(config.getString("key1"), "value1");
    EXPECT_EQ(config.getInt("key2"), 42);
    EXPECT_FALSE(config.hasKey("key3"));
}

TEST_F(ConfigManagerTest, Profiles)
{
    auto& config = ConfigManager::getInstance();
    
    // Create and save profile
    config.setString("profile.key", "profile_value");
    config.setInt("profile.number", 123);
    
    EXPECT_TRUE(config.saveProfile("test_profile"));
    
    // Modify config
    config.setString("profile.key", "modified");
    config.setInt("profile.number", 456);
    
    // Load profile
    EXPECT_TRUE(config.loadProfile("test_profile"));
    EXPECT_EQ(config.getString("profile.key"), "profile_value");
    EXPECT_EQ(config.getInt("profile.number"), 123);
    
    // Test profile management
    auto profiles = config.getProfileNames();
    EXPECT_THAT(profiles, Contains("test_profile"));
    
    EXPECT_TRUE(config.deleteProfile("test_profile"));
    profiles = config.getProfileNames();
    EXPECT_THAT(profiles, Not(Contains("test_profile")));
}

// ==================== File Watcher Tests ====================
TEST_F(ConfigManagerTest, FileWatcher)
{
    auto& config = ConfigManager::getInstance();
    
    // Create initial config file
    std::string initial_content = R"({"initial": "value"})";
    createTestConfigFile(initial_content);
    
    EXPECT_TRUE(config.loadFromFile(test_config_file_));
    EXPECT_EQ(config.getString("initial"), "value");
    
    // Enable file watcher
    EXPECT_TRUE(config.enableFileWatcher(test_config_file_, 100)); // Check every 100ms
    
    // Wait a bit to ensure watcher is running
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    // Modify file
    std::string updated_content = R"({"initial": "updated", "new_key": "new_value"})";
    createTestConfigFile(updated_content);
    
    // Wait for file watcher to detect change
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    EXPECT_EQ(config.getString("initial"), "updated");
    EXPECT_EQ(config.getString("new_key"), "new_value");
    
    config.disableFileWatcher();
}

// ==================== Thread Safety Tests ====================
TEST_F(ConfigManagerTest, ThreadSafety)
{
    auto& config = ConfigManager::getInstance();
    
    const int num_threads = 10;
    const int operations_per_thread = 100;
    
    std::vector<std::future<void>> futures;
    
    // Launch multiple threads performing concurrent operations
    for (int t = 0; t < num_threads; ++t)
    {
        futures.push_back(std::async(std::launch::async, [&config, t, operations_per_thread]() {
            for (int i = 0; i < operations_per_thread; ++i)
            {
                std::string key = "thread_" + std::to_string(t) + "_key_" + std::to_string(i);
                std::string value = "value_" + std::to_string(i);
                
                config.setString(key, value);
                EXPECT_EQ(config.getString(key), value);
                
                if (i % 10 == 0)
                {
                    auto keys = config.getAllKeys();
                    EXPECT_FALSE(keys.empty());
                }
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures)
    {
        future.wait();
    }
    
    // Verify final state
    EXPECT_GE(config.size(), num_threads * operations_per_thread);
}

// ==================== Type Conversion Tests ====================
TEST_F(ConfigManagerTest, TypeConversions)
{
    auto& config = ConfigManager::getInstance();
    
    // Test automatic type conversions in getters
    config.setString("string_int", "42");
    config.setString("string_double", "3.14");
    config.setString("string_bool", "true");
    
    EXPECT_EQ(config.getInt("string_int"), 42);
    EXPECT_DOUBLE_EQ(config.getDouble("string_double"), 3.14);
    EXPECT_TRUE(config.getBool("string_bool"));
    
    // Test cross-type conversions
    config.setInt("int_value", 1);
    EXPECT_TRUE(config.getBool("int_value")); // 1 -> true
    EXPECT_DOUBLE_EQ(config.getDouble("int_value"), 1.0);
    
    config.setInt("zero_value", 0);
    EXPECT_FALSE(config.getBool("zero_value")); // 0 -> false
    
    // Test string array parsing
    config.setString("csv_string", "item1, item2, item3");
    auto array = config.getStringArray("csv_string");
    EXPECT_EQ(array.size(), 3);
    EXPECT_EQ(array[0], "item1");
    EXPECT_EQ(array[1], "item2");
    EXPECT_EQ(array[2], "item3");
}

// ==================== Statistics Tests ====================
TEST_F(ConfigManagerTest, Statistics)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("str_key", "value");
    config.setInt("int_key", 42);
    config.setDouble("double_key", 3.14);
    config.setBool("bool_key", true);
    config.setStringArray("array_key", {"item1", "item2"});
    
    config.setRequired("str_key", true);
    config.setReadonly("int_key", true);
    config.setValidator("double_key", [](const std::any&) { return true; });
    
    auto stats = config.getStatistics();
    
    EXPECT_EQ(stats.total_keys, 5);
    EXPECT_EQ(stats.string_keys, 1);
    EXPECT_EQ(stats.integer_keys, 1);
    EXPECT_EQ(stats.double_keys, 1);
    EXPECT_EQ(stats.boolean_keys, 1);
    EXPECT_EQ(stats.array_keys, 1);
    EXPECT_EQ(stats.required_keys, 1);
    EXPECT_EQ(stats.readonly_keys, 1);
    EXPECT_EQ(stats.keys_with_validators, 1);
}

// ==================== Nested Keys Tests ====================
TEST_F(ConfigManagerTest, NestedKeys)
{
    auto& config = ConfigManager::getInstance();
    
    EXPECT_TRUE(config.setNestedValue("level1.level2.level3", std::string("nested_value"), ConfigType::STRING));
    EXPECT_EQ(std::any_cast<std::string>(config.getNestedValue("level1.level2.level3")), "nested_value");
    EXPECT_TRUE(config.hasNestedKey("level1.level2.level3"));
    
    // Test with JSON loading
    std::string nested_json = R"({
        "database": {
            "connection": {
                "host": "localhost",
                "port": 5432,
                "ssl": {
                    "enabled": true,
                    "cert_path": "/path/to/cert"
                }
            }
        }
    })";
    
    EXPECT_TRUE(config.loadFromJson(nested_json));
    EXPECT_EQ(config.getString("database.connection.host"), "localhost");
    EXPECT_EQ(config.getInt("database.connection.port"), 5432);
    EXPECT_TRUE(config.getBool("database.connection.ssl.enabled"));
    EXPECT_EQ(config.getString("database.connection.ssl.cert_path"), "/path/to/cert");
}

// ==================== Utility Functions Tests ====================
TEST_F(ConfigManagerTest, UtilityFunctions)
{
    auto& config = ConfigManager::getInstance();
    
    config.setString("test.key", "value", "Test description");
    config.setInt("number.key", 42, "Number description");
    
    // Test descriptions
    EXPECT_EQ(config.getDescription("test.key"), "Test description");
    EXPECT_TRUE(config.setDescription("test.key", "Updated description"));
    EXPECT_EQ(config.getDescription("test.key"), "Updated description");
    
    // Test config entry retrieval
    const auto* entry = config.getConfigEntry("test.key");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->type, ConfigType::STRING);
    EXPECT_EQ(entry->description, "Updated description");
    
    // Test template generation
    std::string template_str = config.generateConfigTemplate();
    EXPECT_FALSE(template_str.empty());
    EXPECT_THAT(template_str, HasSubstr("test.key"));
    EXPECT_THAT(template_str, HasSubstr("Updated description"));
}

// ==================== Error Handling Tests ====================
TEST_F(ConfigManagerTest, ErrorHandling)
{
    auto& config = ConfigManager::getInstance();
    
    // Test loading non-existent file
    EXPECT_FALSE(config.loadFromFile("non_existent_file.json"));
    
    // Test saving to invalid path
    EXPECT_FALSE(config.saveToFile("/invalid/path/config.json"));
    
    // Test invalid JSON
    EXPECT_FALSE(config.loadFromJson("invalid json content"));
    
    // Test type mismatches
    config.setString("string_key", "not_a_number");
    EXPECT_EQ(config.getInt("string_key", 999), 999); // Should return default
    
    // Test null snapshot restore
    EXPECT_FALSE(config.restoreFromSnapshot(nullptr));
    
    // Test non-existent profile
    EXPECT_FALSE(config.loadProfile("non_existent_profile"));
    EXPECT_FALSE(config.deleteProfile("non_existent_profile"));
}

// ==================== Performance Tests ====================
TEST_F(ConfigManagerTest, PerformanceTest)
{
    auto& config = ConfigManager::getInstance();
    
    const int num_operations = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Perform many set operations
    for (int i = 0; i < num_operations; ++i)
    {
        config.setString("perf_key_" + std::to_string(i), "value_" + std::to_string(i));
    }
    
    // Perform many get operations
    for (int i = 0; i < num_operations; ++i)
    {
        std::string value = config.getString("perf_key_" + std::to_string(i));
        EXPECT_EQ(value, "value_" + std::to_string(i));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Performance test: " << num_operations * 2 << " operations in " 
              << duration.count() << "ms" << std::endl;
    
    // Should complete within reasonable time (adjust threshold as needed)
    EXPECT_LT(duration.count(), 5000); // Less than 5 seconds
}

// ==================== Integration Tests ====================
TEST_F(ConfigManagerTest, FullIntegrationTest)
{
    auto& config = ConfigManager::getInstance();
    
    // Test complete workflow
    std::string json_config = R"({
        "application": {
            "name": "NetworkSecurity",
            "version": "1.0.0",
            "debug": false
        },
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "netsec_db",
            "pool_size": 10
        },
        "network": {
            "interfaces": ["eth0", "eth1"],
            "timeout": 30.5,
            "buffer_size": 65536
        }
    })";
    
    // Load configuration
    EXPECT_TRUE(config.loadFromJson(json_config));
    
    // Set some keys as required and readonly
    config.setRequired("database.host", true);
    config.setReadonly("application.version", true);
    
    // Add validators
    config.setValidator("database.port", [](const std::any& value) {
        int port = std::any_cast<int>(value);
        return port > 0 && port < 65536;
    });
    
    // Test validation
    EXPECT_TRUE(config.validateAll());
    
    // Create snapshot
    auto snapshot = config.createSnapshot();
    
    // Modify configuration
    config.setString("database.host", "production.db.com");
    config.setInt("database.port", 3306);
    
    // Save to file
    EXPECT_TRUE(config.saveToFile(test_config_file_));
    
    // Clear and reload
    config.clear();
    EXPECT_TRUE(config.loadFromFile(test_config_file_));
    
    // Verify reloaded values
    EXPECT_EQ(config.getString("database.host"), "production.db.com");
    EXPECT_EQ(config.getInt("database.port"), 3306);
    
    // Restore from snapshot
    EXPECT_TRUE(config.restoreFromSnapshot(snapshot));
    EXPECT_EQ(config.getString("database.host"), "localhost");
    EXPECT_EQ(config.getInt("database.port"), 5432);
    
    // Test statistics
    auto stats = config.getStatistics();
    EXPECT_GT(stats.total_keys, 0);
    
    // Generate template
    std::string template_str = config.generateConfigTemplate();
    EXPECT_FALSE(template_str.empty());
}

// ==================== Main Function ====================
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
