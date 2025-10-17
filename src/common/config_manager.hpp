// src/common/config_manager.hpp
#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP

#include "utils.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <fstream>
#include <atomic>
#include <any>
#include <thread>
#include <shared_mutex>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Enum cho các loại cấu hình
         */
        enum class ConfigType
        {
            STRING,
            INTEGER,
            DOUBLE,
            BOOLEAN,
            ARRAY,
            OBJECT
        };

        /**
         * @brief Struct chứa thông tin một config entry
         */
        struct ConfigEntry
        {
            std::any value;
            ConfigType type;
            std::string description;
            bool is_required;
            bool is_readonly;
            std::function<bool(const std::any &)> validator;

            ConfigEntry() : type(ConfigType::STRING), is_required(false), is_readonly(false) {}

            ConfigEntry(const std::any &val, ConfigType t, const std::string &desc = "",
                        bool required = false, bool readonly = false)
                : value(val), type(t), description(desc), is_required(required), is_readonly(readonly) {}
        };

        /**
         * @brief Callback function cho config change events
         */
        using ConfigChangeCallback = std::function<void(const std::string &key, const std::any &old_value, const std::any &new_value)>;

        /**
         * @brief Thread-safe Configuration Manager
         */
        class ConfigManager : public Singleton<ConfigManager>
        {
            friend class Singleton<ConfigManager>;

        public:
            /**
             * @brief Load cấu hình từ file
             * @param config_file Đường dẫn file cấu hình
             * @return true nếu load thành công
             */
            bool loadFromFile(const std::string &config_file);

            /**
             * @brief Save cấu hình ra file
             * @param config_file Đường dẫn file cấu hình
             * @return true nếu save thành công
             */
            bool saveToFile(const std::string &config_file) const;

            /**
             * @brief Load cấu hình từ JSON string
             * @param json_content Nội dung JSON
             * @return true nếu load thành công
             */
            bool loadFromJson(const std::string &json_content);

            /**
             * @brief Export cấu hình thành JSON string
             * @return JSON string
             */
            std::string exportToJson() const;

            /**
             * @brief Load cấu hình từ environment variables
             * @param prefix Prefix cho env vars (VD: "NETSEC_")
             */
            void loadFromEnvironment(const std::string &prefix = "");

            /**
             * @brief Load cấu hình từ command line arguments
             * @param argc Số lượng arguments
             * @param argv Array arguments
             */
            void loadFromCommandLine(int argc, char *argv[]);

            // ==================== Set methods ====================
            /**
             * @brief Set giá trị string
             */
            bool setString(const std::string &key, const std::string &value, const std::string &description = "");

            /**
             * @brief Set giá trị integer
             */
            bool setInt(const std::string &key, int value, const std::string &description = "");

            /**
             * @brief Set giá trị double
             */
            bool setDouble(const std::string &key, double value, const std::string &description = "");

            /**
             * @brief Set giá trị boolean
             */
            bool setBool(const std::string &key, bool value, const std::string &description = "");

            /**
             * @brief Set array of strings
             */
            bool setStringArray(const std::string &key, const std::vector<std::string> &value, const std::string &description = "");

            /**
             * @brief Set generic value
             */
            bool setValue(const std::string &key, const std::any &value, ConfigType type, const std::string &description = "");

            // ==================== Get methods ====================
            /**
             * @brief Get giá trị string
             */
            std::string getString(const std::string &key, const std::string &default_value = "") const;

            /**
             * @brief Get giá trị integer
             */
            int getInt(const std::string &key, int default_value = 0) const;

            /**
             * @brief Get giá trị double
             */
            double getDouble(const std::string &key, double default_value = 0.0) const;

            /**
             * @brief Get giá trị boolean
             */
            bool getBool(const std::string &key, bool default_value = false) const;

            /**
             * @brief Get array of strings
             */
            std::vector<std::string> getStringArray(const std::string &key, const std::vector<std::string> &default_value = {}) const;

            /**
             * @brief Get generic value
             */
            std::any getValue(const std::string &key, const std::any &default_value = std::any{}) const;

            // ==================== Utility methods ====================
            /**
             * @brief Kiểm tra key có tồn tại không
             */
            bool hasKey(const std::string &key) const;

            /**
             * @brief Xóa một key
             */
            bool removeKey(const std::string &key);

            /**
             * @brief Lấy tất cả keys
             */
            std::vector<std::string> getAllKeys() const;

            /**
             * @brief Lấy keys theo prefix
             */
            std::vector<std::string> getKeysByPrefix(const std::string &prefix) const;

            /**
             * @brief Clear tất cả cấu hình
             */
            void clear();

            /**
             * @brief Lấy số lượng config entries
             */
            size_t size() const;

            /**
             * @brief Kiểm tra config manager có rỗng không
             */
            bool empty() const;

            // ==================== Validation ====================
            /**
             * @brief Set validator cho một key
             */
            bool setValidator(const std::string &key, std::function<bool(const std::any &)> validator);

            /**
             * @brief Validate tất cả config entries
             */
            bool validateAll() const;

            /**
             * @brief Validate một key cụ thể
             */
            bool validateKey(const std::string &key) const;

            /**
             * @brief Set key là required
             */
            bool setRequired(const std::string &key, bool required = true);

            /**
             * @brief Set key là readonly
             */
            bool setReadonly(const std::string &key, bool readonly = true);

            /**
             * @brief Kiểm tra key có required không
             */
            bool isRequired(const std::string &key) const;

            /**
             * @brief Kiểm tra key có readonly không
             */
            bool isReadonly(const std::string &key) const;

            /**
             * @brief Lấy tất cả required keys chưa được set
             */
            std::vector<std::string> getMissingRequiredKeys() const;

            // ==================== Change notifications ====================
            /**
             * @brief Đăng ký callback cho config changes
             */
            void registerChangeCallback(const std::string &key, ConfigChangeCallback callback);

            /**
             * @brief Đăng ký global callback cho tất cả changes
             */
            void registerGlobalChangeCallback(ConfigChangeCallback callback);

            /**
             * @brief Hủy đăng ký callback
             */
            void unregisterChangeCallback(const std::string &key);

            /**
             * @brief Hủy đăng ký global callback
             */
            void unregisterGlobalChangeCallback();

            // ==================== Advanced features ====================
            /**
             * @brief Merge cấu hình từ ConfigManager khác
             */
            bool merge(const ConfigManager &other, bool overwrite = false);

            /**
             * @brief Tạo snapshot của cấu hình hiện tại
             */
            std::shared_ptr<ConfigManager> createSnapshot() const;

            /**
             * @brief Restore từ snapshot
             */
            bool restoreFromSnapshot(const std::shared_ptr<ConfigManager> &snapshot);

            /**
             * @brief Watch file changes và auto reload
             */
            bool enableFileWatcher(const std::string &config_file, int check_interval_ms = 1000);

            /**
             * @brief Disable file watcher
             */
            void disableFileWatcher();

            /**
             * @brief Get config entry info
             */
            const ConfigEntry *getConfigEntry(const std::string &key) const;

            /**
             * @brief Set config entry description
             */
            bool setDescription(const std::string &key, const std::string &description);

            /**
             * @brief Get config entry description
             */
            std::string getDescription(const std::string &key) const;

            /**
             * @brief Print all configurations (for debugging)
             */
            void printAll() const;

            /**
             * @brief Generate config template/documentation
             */
            std::string generateConfigTemplate() const;

            // ==================== Nested configuration support ====================
            /**
             * @brief Get nested value using dot notation (e.g., "database.host")
             */
            std::any getNestedValue(const std::string &nested_key, const std::any &default_value = std::any{}) const;

            /**
             * @brief Set nested value using dot notation
             */
            bool setNestedValue(const std::string &nested_key, const std::any &value, ConfigType type);

            /**
             * @brief Check if nested key exists
             */
            bool hasNestedKey(const std::string &nested_key) const;

            // ==================== Type conversion helpers ====================
            /**
             * @brief Convert any value to string
             */
            static std::string anyToString(const std::any &value, ConfigType type);

            /**
             * @brief Convert string to any value
             */
            static std::any stringToAny(const std::string &str_value, ConfigType type);

            /**
             * @brief Get type name as string
             */
            static std::string getTypeName(ConfigType type);

            // ==================== Additional Features ====================
            
            /**
             * @brief Configuration statistics
             */
            struct ConfigStats
            {
                size_t total_keys = 0;
                size_t required_keys = 0;
                size_t readonly_keys = 0;
                size_t keys_with_validators = 0;
                size_t string_keys = 0;
                size_t integer_keys = 0;
                size_t double_keys = 0;
                size_t boolean_keys = 0;
                size_t array_keys = 0;
                size_t object_keys = 0;
            };

            /**
             * @brief Get configuration statistics
             */
            ConfigStats getStatistics() const;

            /**
             * @brief Load from JSON file
             */
            bool loadFromJsonFile(const std::string &json_file);

            /**
             * @brief Save/Load configuration profiles
             */
            bool saveProfile(const std::string &profile_name);
            bool loadProfile(const std::string &profile_name);
            std::vector<std::string> getProfileNames() const;
            bool deleteProfile(const std::string &profile_name);

            /**
             * @brief Backup/Restore configuration
             */
            bool backup(const std::string &backup_file);
            bool restore(const std::string &backup_file);
        protected:
            ConfigManager();
            virtual ~ConfigManager();

        private:
            // Additional private members
            std::unordered_map<std::string, std::shared_ptr<ConfigManager>> profiles_;
            
            // Enhanced JSON parsing methods
            bool parseJsonObjectAdvanced(const std::string &json_content);
            std::string removeJsonComments(const std::string &json_content);
            bool parseJsonRecursive(const std::string &json_str, const std::string &prefix);
            
            // Initialization
            void initializeDefaults();
            // Internal data
            mutable std::shared_mutex config_mutex_;
            std::unordered_map<std::string, ConfigEntry> config_map_;

            // Callbacks
            std::unordered_map<std::string, ConfigChangeCallback> change_callbacks_;
            ConfigChangeCallback global_change_callback_;
            mutable std::mutex callback_mutex_;

            // File watching
            std::atomic<bool> file_watcher_enabled_;
            std::string watched_file_;
            std::thread file_watcher_thread_;
            std::atomic<bool> file_watcher_stop_;
            uint64_t last_file_modification_time_;

            // Helper methods
            bool parseJsonObject(const std::string &json_content);
            std::string serializeToJson() const;
            void notifyChange(const std::string &key, const std::any &old_value, const std::any &new_value);
            void fileWatcherLoop(const std::string &file_path, int check_interval_ms);
            bool isValidKey(const std::string &key) const;
            std::vector<std::string> splitNestedKey(const std::string &nested_key) const;

            // Type validation
            bool isValidType(const std::any &value, ConfigType expected_type) const;
            ConfigType detectType(const std::any &value) const;
        };

// ==================== Utility macros ====================
#define CONFIG ConfigManager::getInstance()
#define CONFIG_GET_STRING(key, default_val) CONFIG.getString(key, default_val)
#define CONFIG_GET_INT(key, default_val) CONFIG.getInt(key, default_val)
#define CONFIG_GET_DOUBLE(key, default_val) CONFIG.getDouble(key, default_val)
#define CONFIG_GET_BOOL(key, default_val) CONFIG.getBool(key, default_val)
#define CONFIG_SET_STRING(key, val) CONFIG.setString(key, val)
#define CONFIG_SET_INT(key, val) CONFIG.setInt(key, val)
#define CONFIG_SET_DOUBLE(key, val) CONFIG.setDouble(key, val)
#define CONFIG_SET_BOOL(key, val) CONFIG.setBool(key, val)

        // ==================== Predefined config keys ====================
        namespace ConfigKeys
        {
            // System settings
            constexpr const char *SYSTEM_LOG_LEVEL = "system.log_level";
            constexpr const char *SYSTEM_LOG_FILE = "system.log_file";
            constexpr const char *SYSTEM_MAX_LOG_SIZE = "system.max_log_size";
            constexpr const char *SYSTEM_THREAD_POOL_SIZE = "system.thread_pool_size";
            constexpr const char *SYSTEM_ENABLE_DEBUG = "system.enable_debug";

            // Network settings
            constexpr const char *NETWORK_INTERFACE = "network.interface";
            constexpr const char *NETWORK_CAPTURE_BUFFER_SIZE = "network.capture_buffer_size";
            constexpr const char *NETWORK_PACKET_TIMEOUT = "network.packet_timeout";
            constexpr const char *NETWORK_MAX_PACKET_SIZE = "network.max_packet_size";
            constexpr const char *NETWORK_PROMISCUOUS_MODE = "network.promiscuous_mode";

            // Detection settings
            constexpr const char *DETECTION_ENABLE_DPI = "detection.enable_dpi";
            constexpr const char *DETECTION_SIGNATURE_FILE = "detection.signature_file";
            constexpr const char *DETECTION_ANOMALY_THRESHOLD = "detection.anomaly_threshold";
            constexpr const char *DETECTION_MAX_FLOWS = "detection.max_flows";
            constexpr const char *DETECTION_FLOW_TIMEOUT = "detection.flow_timeout";

            // AI/ML settings
            constexpr const char *AI_MODEL_PATH = "ai.model_path";
            constexpr const char *AI_ENABLE_GPU = "ai.enable_gpu";
            constexpr const char *AI_BATCH_SIZE = "ai.batch_size";
            constexpr const char *AI_CONFIDENCE_THRESHOLD = "ai.confidence_threshold";
            constexpr const char *AI_UPDATE_INTERVAL = "ai.update_interval";

            // Database settings
            constexpr const char *DB_HOST = "database.host";
            constexpr const char *DB_PORT = "database.port";
            constexpr const char *DB_NAME = "database.name";
            constexpr const char *DB_USERNAME = "database.username";
            constexpr const char *DB_PASSWORD = "database.password";
            constexpr const char *DB_MAX_CONNECTIONS = "database.max_connections";
            constexpr const char *DB_CONNECTION_TIMEOUT = "database.connection_timeout";

            // Alert settings
            constexpr const char *ALERT_ENABLE_EMAIL = "alert.enable_email";
            constexpr const char *ALERT_EMAIL_SMTP_HOST = "alert.email.smtp_host";
            constexpr const char *ALERT_EMAIL_SMTP_PORT = "alert.email.smtp_port";
            constexpr const char *ALERT_EMAIL_USERNAME = "alert.email.username";
            constexpr const char *ALERT_EMAIL_PASSWORD = "alert.email.password";
            constexpr const char *ALERT_EMAIL_RECIPIENTS = "alert.email.recipients";
            constexpr const char *ALERT_WEBHOOK_URL = "alert.webhook_url";
            constexpr const char *ALERT_SEVERITY_THRESHOLD = "alert.severity_threshold";

            // Performance settings
            constexpr const char *PERF_ENABLE_PROFILING = "performance.enable_profiling";
            constexpr const char *PERF_STATS_INTERVAL = "performance.stats_interval";
            constexpr const char *PERF_MAX_MEMORY_USAGE = "performance.max_memory_usage";
            constexpr const char *PERF_MAX_CPU_USAGE = "performance.max_cpu_usage";
        }

    } // namespace Common
} // namespace NetworkSecurity

#endif // CONFIG_MANAGER_HPP
