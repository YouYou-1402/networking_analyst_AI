// src/common/config_manager.cpp
#include "config_manager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <chrono>
#include <cstdlib>
#include <typeinfo>

// JSON parsing library - assuming we use nlohmann/json
#include <nlohmann/json.hpp>

extern char** environ;

namespace NetworkSecurity {
namespace Common {
    // Định nghĩa biến enviro
    char** environ = ::environ;
}
}

using json = nlohmann::json;

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== Constructor/Destructor ====================
        ConfigManager::ConfigManager()
            : file_watcher_enabled_(false), file_watcher_stop_(false), last_file_modification_time_(0)
        {
            initializeDefaults();
        }

        ConfigManager::~ConfigManager()
        {
            disableFileWatcher();
        }

        // ==================== Initialization ====================
        void ConfigManager::initializeDefaults()
        {
            // Set default system configurations
            setString(ConfigKeys::SYSTEM_LOG_LEVEL, "INFO", "System log level (DEBUG, INFO, WARN, ERROR)");
            setString(ConfigKeys::SYSTEM_LOG_FILE, "netsec.log", "System log file path");
            setInt(ConfigKeys::SYSTEM_MAX_LOG_SIZE, 100 * 1024 * 1024, "Maximum log file size in bytes"); // 100MB
            setInt(ConfigKeys::SYSTEM_THREAD_POOL_SIZE, std::thread::hardware_concurrency(), "Thread pool size");
            setBool(ConfigKeys::SYSTEM_ENABLE_DEBUG, false, "Enable debug mode");

            // Network defaults
            setString(ConfigKeys::NETWORK_INTERFACE, "eth0", "Network interface for packet capture");
            setInt(ConfigKeys::NETWORK_CAPTURE_BUFFER_SIZE, 64 * 1024 * 1024, "Capture buffer size in bytes"); // 64MB
            setInt(ConfigKeys::NETWORK_PACKET_TIMEOUT, 1000, "Packet capture timeout in milliseconds");
            setInt(ConfigKeys::NETWORK_MAX_PACKET_SIZE, 65535, "Maximum packet size");
            setBool(ConfigKeys::NETWORK_PROMISCUOUS_MODE, true, "Enable promiscuous mode");

            // Detection defaults
            setBool(ConfigKeys::DETECTION_ENABLE_DPI, true, "Enable Deep Packet Inspection");
            setString(ConfigKeys::DETECTION_SIGNATURE_FILE, "signatures.yaml", "Signature file path");
            setDouble(ConfigKeys::DETECTION_ANOMALY_THRESHOLD, 0.8, "Anomaly detection threshold");
            setInt(ConfigKeys::DETECTION_MAX_FLOWS, 100000, "Maximum concurrent flows");
            setInt(ConfigKeys::DETECTION_FLOW_TIMEOUT, 300, "Flow timeout in seconds");

            // AI/ML defaults
            setString(ConfigKeys::AI_MODEL_PATH, "models/", "AI model directory path");
            setBool(ConfigKeys::AI_ENABLE_GPU, false, "Enable GPU acceleration");
            setInt(ConfigKeys::AI_BATCH_SIZE, 32, "AI processing batch size");
            setDouble(ConfigKeys::AI_CONFIDENCE_THRESHOLD, 0.7, "AI confidence threshold");
            setInt(ConfigKeys::AI_UPDATE_INTERVAL, 3600, "Model update interval in seconds");

            // Database defaults
            setString(ConfigKeys::DB_HOST, "localhost", "Database host");
            setInt(ConfigKeys::DB_PORT, 5432, "Database port");
            setString(ConfigKeys::DB_NAME, "netsec", "Database name");
            setString(ConfigKeys::DB_USERNAME, "netsec_user", "Database username");
            setString(ConfigKeys::DB_PASSWORD, "", "Database password");
            setInt(ConfigKeys::DB_MAX_CONNECTIONS, 10, "Maximum database connections");
            setInt(ConfigKeys::DB_CONNECTION_TIMEOUT, 30, "Database connection timeout in seconds");

            // Alert defaults
            setBool(ConfigKeys::ALERT_ENABLE_EMAIL, false, "Enable email alerts");
            setString(ConfigKeys::ALERT_EMAIL_SMTP_HOST, "smtp.gmail.com", "SMTP server host");
            setInt(ConfigKeys::ALERT_EMAIL_SMTP_PORT, 587, "SMTP server port");
            setString(ConfigKeys::ALERT_EMAIL_USERNAME, "", "SMTP username");
            setString(ConfigKeys::ALERT_EMAIL_PASSWORD, "", "SMTP password");
            setStringArray(ConfigKeys::ALERT_EMAIL_RECIPIENTS, {}, "Email recipients list");
            setString(ConfigKeys::ALERT_WEBHOOK_URL, "", "Webhook URL for alerts");
            setString(ConfigKeys::ALERT_SEVERITY_THRESHOLD, "MEDIUM", "Minimum alert severity");

            // Performance defaults
            setBool(ConfigKeys::PERF_ENABLE_PROFILING, false, "Enable performance profiling");
            setInt(ConfigKeys::PERF_STATS_INTERVAL, 60, "Statistics collection interval in seconds");
            setInt(ConfigKeys::PERF_MAX_MEMORY_USAGE, 80, "Maximum memory usage percentage");
            setInt(ConfigKeys::PERF_MAX_CPU_USAGE, 80, "Maximum CPU usage percentage");

            // Set some keys as required
            setRequired(ConfigKeys::NETWORK_INTERFACE, true);
            setRequired(ConfigKeys::DB_HOST, true);
            setRequired(ConfigKeys::DB_NAME, true);

            // Set some keys as readonly
            setReadonly(ConfigKeys::SYSTEM_THREAD_POOL_SIZE, true);
        }

        // ==================== File I/O ====================
        bool ConfigManager::loadFromFile(const std::string &config_file)
        {
            try
            {
                std::ifstream file(config_file);
                if (!file.is_open())
                {
                    std::cerr << "Cannot open config file: " << config_file << std::endl;
                    return false;
                }

                std::stringstream buffer;
                buffer << file.rdbuf();
                file.close();

                return loadFromJson(buffer.str());
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error loading config file: " << e.what() << std::endl;
                return false;
            }
        }

        bool ConfigManager::saveToFile(const std::string &config_file) const
        {
            try
            {
                std::ofstream file(config_file);
                if (!file.is_open())
                {
                    std::cerr << "Cannot create config file: " << config_file << std::endl;
                    return false;
                }

                file << exportToJson();
                file.close();
                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error saving config file: " << e.what() << std::endl;
                return false;
            }
        }

        bool ConfigManager::loadFromJsonFile(const std::string &json_file)
        {
            return loadFromFile(json_file);
        }

        // ==================== JSON Operations ====================
        bool ConfigManager::loadFromJson(const std::string &json_content)
        {
            try
            {
                // Remove comments first
                std::string clean_json = removeJsonComments(json_content);
                
                json j = json::parse(clean_json);
                
                // KHÔNG lock ở đây, để parseJsonRecursive tự lock
                // std::unique_lock<std::shared_mutex> lock(config_mutex_);  ← XÓA DÒNG NÀY
                
                // Parse JSON recursively
                return parseJsonRecursive(j.dump(), "");
            }
            catch (const json::parse_error &e)
            {
                std::cerr << "JSON parse error: " << e.what() << std::endl;
                return false;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error loading JSON: " << e.what() << std::endl;
                return false;
            }
        }
        std::string ConfigManager::exportToJson() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            json j;
            
            for (const auto &[key, entry] : config_map_)
            {
                try
                {
                    switch (entry.type)
                    {
                    case ConfigType::STRING:
                        j[key] = std::any_cast<std::string>(entry.value);
                        break;
                    case ConfigType::INTEGER:
                        j[key] = std::any_cast<int>(entry.value);
                        break;
                    case ConfigType::DOUBLE:
                        j[key] = std::any_cast<double>(entry.value);
                        break;
                    case ConfigType::BOOLEAN:
                        j[key] = std::any_cast<bool>(entry.value);
                        break;
                    case ConfigType::ARRAY:
                        j[key] = std::any_cast<std::vector<std::string>>(entry.value);
                        break;
                    default:
                        j[key] = anyToString(entry.value, entry.type);
                        break;
                    }
                }
                catch (const std::bad_any_cast &e)
                {
                    std::cerr << "Bad any_cast for key: " << key << std::endl;
                }
            }
            
            return j.dump(4); // Pretty print with 4 spaces
        }

        std::string ConfigManager::removeJsonComments(const std::string& json_content) {
            std::string result;
            std::istringstream iss(json_content);
            std::string line;
            bool in_multiline_comment = false;

            while (std::getline(iss, line)) {
                // Xóa comment đơn dòng (//)
                size_t comment_pos = line.find("//");
                if (comment_pos != std::string::npos && !in_multiline_comment) {
                    line = line.substr(0, comment_pos);
                }

                // Xử lý comment đa dòng (/* */)
                if (!in_multiline_comment) {
                    size_t start_pos = line.find("/*");
                    if (start_pos != std::string::npos) {
                        in_multiline_comment = true;
                        line = line.substr(0, start_pos);
                    }
                }
                if (in_multiline_comment) {
                    size_t end_pos = line.find("*/");
                    if (end_pos != std::string::npos) {
                        in_multiline_comment = false;
                        line = line.substr(end_pos + 2);
                    } else {
                        line.clear(); // Bỏ toàn bộ dòng nếu đang trong comment đa dòng
                    }
                }

                // Trim whitespace
                line.erase(0, line.find_first_not_of(" \t"));
                line.erase(line.find_last_not_of(" \t") + 1);

                if (!line.empty()) {
                    result += line + "\n";
                }
            }

            return result;
        }

        bool ConfigManager::parseJsonRecursive(const std::string &json_str, const std::string &prefix)
        {
            try
            {
                json j = json::parse(json_str);
                
                // KHÔNG lock ở đây vì setString/setInt/... đã tự lock
                for (auto it = j.begin(); it != j.end(); ++it)
                {
                    std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
                    
                    if (it.value().is_object())
                    {
                        // Recursive call for nested objects
                        parseJsonRecursive(it.value().dump(), key);
                    }
                    else if (it.value().is_string())
                    {
                        setString(key, it.value().get<std::string>());
                    }
                    else if (it.value().is_number_integer())
                    {
                        setInt(key, it.value().get<int>());
                    }
                    else if (it.value().is_number_float())
                    {
                        setDouble(key, it.value().get<double>());
                    }
                    else if (it.value().is_boolean())
                    {
                        setBool(key, it.value().get<bool>());
                    }
                    else if (it.value().is_array())
                    {
                        std::vector<std::string> arr;
                        for (const auto &item : it.value())
                        {
                            if (item.is_string())
                            {
                                arr.push_back(item.get<std::string>());
                            }
                            else
                            {
                                arr.push_back(item.dump());
                            }
                        }
                        setStringArray(key, arr);
                    }
                }
                
                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error parsing JSON recursively: " << e.what() << std::endl;
                return false;
            }
        }

        // ==================== Environment Variables ====================
        void ConfigManager::loadFromEnvironment(const std::string &prefix)
        {
            // Lấy environment variables
            extern char **environ;
            
            if (environ == nullptr)
            {
                std::cerr << "Environment variables not available" << std::endl;
                return;
            }
            
            for (char **env = environ; *env != nullptr; ++env)
            {
                std::string env_var(*env);
                size_t eq_pos = env_var.find('=');
                if (eq_pos == std::string::npos) continue;
                
                std::string key = env_var.substr(0, eq_pos);
                std::string value = env_var.substr(eq_pos + 1);
                
                // Check prefix
                if (!prefix.empty())
                {
                    if (key.length() < prefix.length() || 
                        key.substr(0, prefix.length()) != prefix)
                    {
                        continue;
                    }
                    key = key.substr(prefix.length());
                }
                
                // Convert to lowercase and replace underscores with dots
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                std::replace(key.begin(), key.end(), '_', '.');
                
                // Try to detect type and set value
                if (value == "true" || value == "false")
                {
                    setBool(key, value == "true");
                }
                else if (std::regex_match(value, std::regex(R"(^-?\d+$)")))
                {
                    setInt(key, std::stoi(value));
                }
                else if (std::regex_match(value, std::regex(R"(^-?\d+\.\d+$)")))
                {
                    setDouble(key, std::stod(value));
                }
                else
                {
                    setString(key, value);
                }
            }
        }



        // ==================== Command Line Arguments ====================
        void ConfigManager::loadFromCommandLine(int argc, char *argv[])
        {
            for (int i = 1; i < argc; ++i)
            {
                std::string arg(argv[i]);
                
                // Handle --key=value format
                if (arg.substr(0, 2) == "--" && arg.find('=') != std::string::npos)
                {
                    size_t eq_pos = arg.find('=');
                    std::string key = arg.substr(2, eq_pos - 2);
                    std::string value = arg.substr(eq_pos + 1);
                    
                    // Replace hyphens with dots
                    std::replace(key.begin(), key.end(), '-', '.');
                    
                    // Auto-detect type and set
                    if (value == "true" || value == "false")
                    {
                        setBool(key, value == "true");
                    }
                    else if (std::regex_match(value, std::regex(R"(^-?\d+$)")))
                    {
                        setInt(key, std::stoi(value));
                    }
                    else if (std::regex_match(value, std::regex(R"(^-?\d+\.\d+$)")))
                    {
                        setDouble(key, std::stod(value));
                    }
                    else
                    {
                        setString(key, value);
                    }
                }
                // Handle --key value format
                else if (arg.substr(0, 2) == "--" && i + 1 < argc)  // ← SỬA: thêm điều kiện i+1 < argc
                {
                    std::string key = arg.substr(2);
                    std::string value = argv[i + 1];  // ← SỬA: lấy giá trị từ argv[i+1]
                    i++;  // ← SỬA: tăng i để skip value
                    
                    std::replace(key.begin(), key.end(), '-', '.');
                    
                    // Auto-detect type and set
                    if (value == "true" || value == "false")
                    {
                        setBool(key, value == "true");
                    }
                    else if (std::regex_match(value, std::regex(R"(^-?\d+$)")))
                    {
                        setInt(key, std::stoi(value));
                    }
                    else if (std::regex_match(value, std::regex(R"(^-?\d+\.\d+$)")))
                    {
                        setDouble(key, std::stod(value));
                    }
                    else
                    {
                        setString(key, value);
                    }
                }
            }
        }


        // ==================== Set Methods ====================
        bool ConfigManager::setString(const std::string &key, const std::string &value, const std::string &description)
        {
            return setValue(key, value, ConfigType::STRING, description);
        }

        bool ConfigManager::setInt(const std::string &key, int value, const std::string &description)
        {
            return setValue(key, value, ConfigType::INTEGER, description);
        }


        bool ConfigManager::setDouble(const std::string &key, double value, const std::string &description)
        {
            return setValue(key, value, ConfigType::DOUBLE, description);
        }

        bool ConfigManager::setBool(const std::string &key, bool value, const std::string &description)
        {
            return setValue(key, value, ConfigType::BOOLEAN, description);
        }

        bool ConfigManager::setStringArray(const std::string &key, const std::vector<std::string> &value, const std::string &description)
        {
            return setValue(key, value, ConfigType::ARRAY, description);
        }

        bool ConfigManager::setValue(const std::string &key, const std::any &value, ConfigType type, const std::string &description)
        {
            if (!isValidKey(key))
            {
                std::cerr << "Invalid key: " << key << std::endl;
                return false;
            }

            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            // Check if key is readonly
            auto it = config_map_.find(key);
            if (it != config_map_.end() && it->second.is_readonly)
            {
                std::cerr << "Cannot modify readonly key: " << key << std::endl;
                return false;
            }

            // Validate type
            if (!isValidType(value, type))
            {
                std::cerr << "Invalid type for key: " << key << std::endl;
                return false;
            }

            std::any old_value;
            bool key_existed = (it != config_map_.end());
            if (key_existed)
            {
                old_value = it->second.value;
            }

            // Create or update config entry
            ConfigEntry entry(value, type, description);
            if (key_existed)
            {
                // Preserve existing settings
                entry.is_required = it->second.is_required;
                entry.is_readonly = it->second.is_readonly;  // ← QUAN TRỌNG: giữ readonly flag
                entry.validator = it->second.validator;
            }

            // Validate with custom validator if exists
            if (entry.validator && !entry.validator(value))
            {
                std::cerr << "Validation failed for key: " << key << std::endl;
                return false;
            }

            config_map_[key] = entry;
            
            lock.unlock();

            // Notify change
            notifyChange(key, key_existed ? old_value : std::any{}, value);

            return true;
        }


        // ==================== Get Methods ====================
        std::string ConfigManager::getString(const std::string &key, const std::string &default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            try
            {
                if (it->second.type == ConfigType::STRING)
                {
                    return std::any_cast<std::string>(it->second.value);
                }
                else
                {
                    return anyToString(it->second.value, it->second.type);
                }
            }
            catch (const std::bad_any_cast &e)
            {
                std::cerr << "Bad any_cast for string key: " << key << std::endl;
                return default_value;
            }
        }

        int ConfigManager::getInt(const std::string &key, int default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            try
            {
                if (it->second.type == ConfigType::INTEGER)
                {
                    return std::any_cast<int>(it->second.value);
                }
                else if (it->second.type == ConfigType::STRING)
                {
                    return std::stoi(std::any_cast<std::string>(it->second.value));
                }
                else if (it->second.type == ConfigType::DOUBLE)
                {
                    return static_cast<int>(std::any_cast<double>(it->second.value));
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error converting to int for key: " << key << " - " << e.what() << std::endl;
            }
            
            return default_value;
        }

        double ConfigManager::getDouble(const std::string &key, double default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            try
            {
                if (it->second.type == ConfigType::DOUBLE)
                {
                    return std::any_cast<double>(it->second.value);
                }
                else if (it->second.type == ConfigType::INTEGER)
                {
                    return static_cast<double>(std::any_cast<int>(it->second.value));
                }
                else if (it->second.type == ConfigType::STRING)
                {
                    return std::stod(std::any_cast<std::string>(it->second.value));
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error converting to double for key: " << key << " - " << e.what() << std::endl;
            }
            
            return default_value;
        }

        bool ConfigManager::getBool(const std::string &key, bool default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            try
            {
                if (it->second.type == ConfigType::BOOLEAN)
                {
                    return std::any_cast<bool>(it->second.value);
                }
                else if (it->second.type == ConfigType::STRING)
                {
                    std::string str_val = std::any_cast<std::string>(it->second.value);
                    std::transform(str_val.begin(), str_val.end(), str_val.begin(), ::tolower);
                    return (str_val == "true" || str_val == "1" || str_val == "yes" || str_val == "on");
                }
                else if (it->second.type == ConfigType::INTEGER)
                {
                    return std::any_cast<int>(it->second.value) != 0;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error converting to bool for key: " << key << " - " << e.what() << std::endl;
            }
            
            return default_value;
        }

        std::vector<std::string> ConfigManager::getStringArray(const std::string &key, const std::vector<std::string> &default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            try
            {
                if (it->second.type == ConfigType::ARRAY)
                {
                    return std::any_cast<std::vector<std::string>>(it->second.value);
                }
                else if (it->second.type == ConfigType::STRING)
                {
                    // Try to parse comma-separated string
                    std::string str_val = std::any_cast<std::string>(it->second.value);
                    std::vector<std::string> result;
                    std::stringstream ss(str_val);
                    std::string item;
                    
                    while (std::getline(ss, item, ','))
                    {
                        // Trim whitespace
                        item.erase(0, item.find_first_not_of(" \t"));
                        item.erase(item.find_last_not_of(" \t") + 1);
                        if (!item.empty())
                        {
                            result.push_back(item);
                        }
                    }
                    return result;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error converting to string array for key: " << key << " - " << e.what() << std::endl;
            }
            
            return default_value;
        }

        std::any ConfigManager::getValue(const std::string &key, const std::any &default_value) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return default_value;
            }

            return it->second.value;
        }

        // ==================== Utility Methods ====================
        bool ConfigManager::hasKey(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            return config_map_.find(key) != config_map_.end();
        }

        bool ConfigManager::removeKey(const std::string &key)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            if (it->second.is_readonly)
            {
                std::cerr << "Cannot remove readonly key: " << key << std::endl;
                return false;
            }

            if (it->second.is_required)
            {
                std::cerr << "Cannot remove required key: " << key << std::endl;
                return false;
            }

            config_map_.erase(it);
            return true;
        }

        std::vector<std::string> ConfigManager::getAllKeys() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::vector<std::string> keys;
            keys.reserve(config_map_.size());
            
            for (const auto &[key, entry] : config_map_)
            {
                keys.push_back(key);
            }
            
            std::sort(keys.begin(), keys.end());
            return keys;
        }

        std::vector<std::string> ConfigManager::getKeysByPrefix(const std::string &prefix) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::vector<std::string> keys;
            
            for (const auto &[key, entry] : config_map_)
            {
                if (key.substr(0, prefix.length()) == prefix)
                {
                    keys.push_back(key);
                }
            }
            
            std::sort(keys.begin(), keys.end());
            return keys;
        }

        void ConfigManager::clear()
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            // Only clear non-readonly keys
            auto it = config_map_.begin();
            while (it != config_map_.end())
            {
                if (it->second.is_readonly)
                {
                    ++it;
                }
                else
                {
                    it = config_map_.erase(it);
                }
            }
        }

        size_t ConfigManager::size() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            return config_map_.size();
        }

        bool ConfigManager::empty() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            return config_map_.empty();
        }

        // ==================== Validation ====================
        bool ConfigManager::setValidator(const std::string &key, std::function<bool(const std::any &)> validator)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            it->second.validator = validator;
            return true;
        }

        bool ConfigManager::validateAll() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            for (const auto &[key, entry] : config_map_)
            {
                if (entry.validator && !entry.validator(entry.value))
                {
                    std::cerr << "Validation failed for key: " << key << std::endl;
                    return false;
                }
            }
            
            return true;
        }

        bool ConfigManager::validateKey(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            if (it->second.validator)
            {
                return it->second.validator(it->second.value);
            }

            return true;
        }

        bool ConfigManager::setRequired(const std::string &key, bool required)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            it->second.is_required = required;
            return true;
        }

        bool ConfigManager::setReadonly(const std::string &key, bool readonly)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            it->second.is_readonly = readonly;
            return true;
        }

        bool ConfigManager::isRequired(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            return it->second.is_required;
        }

        bool ConfigManager::isReadonly(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            return it->second.is_readonly;
        }

        std::vector<std::string> ConfigManager::getMissingRequiredKeys() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::vector<std::string> missing_keys;
            
            for (const auto &[key, entry] : config_map_)
            {
                if (entry.is_required)
                {
                    // Check if value is empty/default
                    try
                    {
                        switch (entry.type)
                        {
                        case ConfigType::STRING:
                            if (std::any_cast<std::string>(entry.value).empty())
                            {
                                missing_keys.push_back(key);
                            }
                            break;
                        case ConfigType::ARRAY:
                            if (std::any_cast<std::vector<std::string>>(entry.value).empty())
                            {
                                missing_keys.push_back(key);
                            }
                            break;
                        default:
                            // For other types, we assume they have valid values if they exist
                            break;
                        }
                    }
                    catch (const std::bad_any_cast &e)
                    {
                        missing_keys.push_back(key);
                    }
                }
            }
            
            return missing_keys;
        }

        // ==================== Change Notifications ====================
        void ConfigManager::registerChangeCallback(const std::string &key, ConfigChangeCallback callback)
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            change_callbacks_[key] = callback;
        }

        void ConfigManager::registerGlobalChangeCallback(ConfigChangeCallback callback)
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            global_change_callback_ = callback;
        }

        void ConfigManager::unregisterChangeCallback(const std::string &key)
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            change_callbacks_.erase(key);
        }

        void ConfigManager::unregisterGlobalChangeCallback()
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            global_change_callback_ = nullptr;
        }

        void ConfigManager::notifyChange(const std::string &key, const std::any &old_value, const std::any &new_value)
        {
            // Copy callbacks to avoid deadlock
            ConfigChangeCallback key_callback;
            ConfigChangeCallback global_callback;
            
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                
                auto it = change_callbacks_.find(key);
                if (it != change_callbacks_.end())
                {
                    key_callback = it->second;
                }
                
                global_callback = global_change_callback_;
            }
            
            // Call callbacks outside lock
            if (key_callback)
            {
                try {
                    key_callback(key, old_value, new_value);
                } catch (const std::exception& e) {
                    std::cerr << "Exception in key callback: " << e.what() << std::endl;
                }
            }
            
            if (global_callback)
            {
                try {
                    global_callback(key, old_value, new_value);
                } catch (const std::exception& e) {
                    std::cerr << "Exception in global callback: " << e.what() << std::endl;
                }
            }
        }


        // ==================== Advanced Features ====================
        bool ConfigManager::merge(const ConfigManager &other, bool overwrite)
        {
            std::unique_lock<std::shared_mutex> this_lock(config_mutex_);
            std::shared_lock<std::shared_mutex> other_lock(other.config_mutex_);
            
            for (const auto &[key, entry] : other.config_map_)
            {
                auto it = config_map_.find(key);
                
                // Skip if key exists and overwrite is false
                if (it != config_map_.end() && !overwrite)
                {
                    continue;
                }

                // Skip if key is readonly in this config
                if (it != config_map_.end() && it->second.is_readonly)
                {
                    continue;
                }

                config_map_[key] = entry;
            }

            return true;
        }

        std::shared_ptr<ConfigManager> ConfigManager::createSnapshot() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
        auto snapshot = std::shared_ptr<ConfigManager>(new ConfigManager(), 
            [](ConfigManager* ptr) { 
                // Custom deleter - không cần delete vì Singleton tự quản lý
                // hoặc có thể để trống nếu snapshot chỉ là copy
            });
            
            std::unique_lock<std::shared_mutex> snapshot_lock(snapshot->config_mutex_);
            snapshot->config_map_ = config_map_;
            
            return snapshot;
        }

        bool ConfigManager::restoreFromSnapshot(const std::shared_ptr<ConfigManager> &snapshot)
        {
            if (!snapshot)
            {
                return false;
            }

            std::unique_lock<std::shared_mutex> this_lock(config_mutex_);
            std::shared_lock<std::shared_mutex> snapshot_lock(snapshot->config_mutex_);
            
            // Clear current config (except readonly)
            auto it = config_map_.begin();
            while (it != config_map_.end())
            {
                if (it->second.is_readonly)
                {
                    ++it;
                }
                else
                {
                    it = config_map_.erase(it);
                }
            }

            // Copy from snapshot (skip readonly keys)
            for (const auto &[key, entry] : snapshot->config_map_)
            {
                auto existing_it = config_map_.find(key);
                if (existing_it != config_map_.end() && existing_it->second.is_readonly)
                {
                    continue;
                }
                
                config_map_[key] = entry;
            }

            return true;
        }

        // ==================== File Watcher ====================
        bool ConfigManager::enableFileWatcher(const std::string &config_file, int check_interval_ms)
        {
            if (file_watcher_enabled_.load())
            {
                disableFileWatcher();
            }

            watched_file_ = config_file;
            file_watcher_stop_.store(false);
            file_watcher_enabled_.store(true);

            // Get initial modification time
            try
            {
                auto ftime = std::filesystem::last_write_time(config_file);
                last_file_modification_time_ = std::chrono::duration_cast<std::chrono::seconds>(
                    ftime.time_since_epoch()).count();
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                std::cerr << "Cannot get file modification time: " << e.what() << std::endl;
                return false;
            }

            // Start watcher thread
            file_watcher_thread_ = std::thread(&ConfigManager::fileWatcherLoop, this, config_file, check_interval_ms);

            return true;
        }

        void ConfigManager::disableFileWatcher()
        {
            if (file_watcher_enabled_.load())
            {
                file_watcher_stop_.store(true);
                file_watcher_enabled_.store(false);
                
                if (file_watcher_thread_.joinable())
                {
                    file_watcher_thread_.join();
                }
            }
        }

        void ConfigManager::fileWatcherLoop(const std::string &file_path, int check_interval_ms)
        {
            while (!file_watcher_stop_.load())
            {
                try
                {
                    if (std::filesystem::exists(file_path))
                    {
                        auto ftime = std::filesystem::last_write_time(file_path);
                        uint64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
                            ftime.time_since_epoch()).count();

                        if (current_time > last_file_modification_time_)
                        {
                            std::cout << "Config file changed, reloading..." << std::endl;
                            
                            if (loadFromFile(file_path))
                            {
                                last_file_modification_time_ = current_time;
                                std::cout << "Config reloaded successfully" << std::endl;
                            }
                            else
                            {
                                std::cerr << "Failed to reload config file" << std::endl;
                            }
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error in file watcher: " << e.what() << std::endl;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms));
            }
        }

        // ==================== Config Entry Info ====================
        const ConfigEntry *ConfigManager::getConfigEntry(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return nullptr;
            }

            return &it->second;
        }

        bool ConfigManager::setDescription(const std::string &key, const std::string &description)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return false;
            }

            it->second.description = description;
            return true;
        }

        std::string ConfigManager::getDescription(const std::string &key) const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = config_map_.find(key);
            if (it == config_map_.end())
            {
                return "";
            }

            return it->second.description;
        }

        void ConfigManager::printAll() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::cout << "\n==================== Configuration Manager ====================" << std::endl;
            std::cout << "Total entries: " << config_map_.size() << std::endl;
            std::cout << "=============================================================" << std::endl;

            for (const auto &[key, entry] : config_map_)
            {
                std::cout << "Key: " << key << std::endl;
                std::cout << "  Type: " << getTypeName(entry.type) << std::endl;
                std::cout << "  Value: " << anyToString(entry.value, entry.type) << std::endl;
                
                if (!entry.description.empty())
                {
                    std::cout << "  Description: " << entry.description << std::endl;
                }
                
                std::vector<std::string> flags;
                if (entry.is_required) flags.push_back("REQUIRED");
                if (entry.is_readonly) flags.push_back("READONLY");
                if (entry.validator) flags.push_back("HAS_VALIDATOR");
                
                if (!flags.empty())
                {
                    std::cout << "  Flags: ";
                    for (size_t i = 0; i < flags.size(); ++i)
                    {
                        if (i > 0) std::cout << ", ";
                        std::cout << flags[i];
                    }
                    std::cout << std::endl;
                }
                
                std::cout << std::endl;
            }
        }

        std::string ConfigManager::generateConfigTemplate() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::stringstream ss;
            ss << "# Configuration Template\n";
            ss << "# Generated at: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n\n";

            // Group by category (prefix before first dot)
            std::map<std::string, std::vector<std::string>> categories;
            
            for (const auto &[key, entry] : config_map_)
            {
                size_t dot_pos = key.find('.');
                std::string category = (dot_pos != std::string::npos) ? key.substr(0, dot_pos) : "general";
                categories[category].push_back(key);
            }

            for (const auto &[category, keys] : categories)
            {
                ss << "# " << category << " settings\n";
                
                for (const std::string &key : keys)
                {
                    const auto &entry = config_map_.at(key);
                    
                    if (!entry.description.empty())
                    {
                        ss << "# " << entry.description << "\n";
                    }
                    
                    ss << "# Type: " << getTypeName(entry.type);
                    if (entry.is_required) ss << " (REQUIRED)";
                    if (entry.is_readonly) ss << " (READONLY)";
                    ss << "\n";
                    
                    ss << key << " = " << anyToString(entry.value, entry.type) << "\n\n";
                }
            }

            return ss.str();
        }

        // ==================== Nested Configuration Support ====================
        std::any ConfigManager::getNestedValue(const std::string &nested_key, const std::any &default_value) const
        {
            return getValue(nested_key, default_value);
        }

        bool ConfigManager::setNestedValue(const std::string &nested_key, const std::any &value, ConfigType type)
        {
            return setValue(nested_key, value, type);
        }

        bool ConfigManager::hasNestedKey(const std::string &nested_key) const
        {
            return hasKey(nested_key);
        }

        std::vector<std::string> ConfigManager::splitNestedKey(const std::string &nested_key) const
        {
            std::vector<std::string> parts;
            std::stringstream ss(nested_key);
            std::string part;
            
            while (std::getline(ss, part, '.'))
            {
                if (!part.empty())
                {
                    parts.push_back(part);
                }
            }
            
            return parts;
        }

        // ==================== Type Conversion Helpers ====================
        std::string ConfigManager::anyToString(const std::any &value, ConfigType type)
        {
            try
            {
                switch (type)
                {
                case ConfigType::STRING:
                    return std::any_cast<std::string>(value);
                    
                case ConfigType::INTEGER:
                    return std::to_string(std::any_cast<int>(value));
                    
                case ConfigType::DOUBLE:
                    return std::to_string(std::any_cast<double>(value));
                    
                case ConfigType::BOOLEAN:
                    return std::any_cast<bool>(value) ? "true" : "false";
                    
                case ConfigType::ARRAY:
                    {
                        const auto &arr = std::any_cast<std::vector<std::string>>(value);
                        std::stringstream ss;
                        ss << "[";
                        for (size_t i = 0; i < arr.size(); ++i)
                        {
                            if (i > 0) ss << ", ";
                            ss << "\"" << arr[i] << "\"";
                        }
                        ss << "]";
                        return ss.str();
                    }
                    
                case ConfigType::OBJECT:
                default:
                    return "<object>";
                }
            }
            catch (const std::bad_any_cast &e)
            {
                return "<invalid>";
            }
        }

        std::any ConfigManager::stringToAny(const std::string &str_value, ConfigType type)
        {
            try
            {
                switch (type)
                {
                case ConfigType::STRING:
                    return str_value;
                    
                case ConfigType::INTEGER:
                    return std::stoi(str_value);
                    
                case ConfigType::DOUBLE:
                    return std::stod(str_value);
                    
                case ConfigType::BOOLEAN:
                    {
                        std::string lower_val = str_value;
                        std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(), ::tolower);
                        return (lower_val == "true" || lower_val == "1" || lower_val == "yes" || lower_val == "on");
                    }
                    
                case ConfigType::ARRAY:
                    {
                        std::vector<std::string> result;
                        std::stringstream ss(str_value);
                        std::string item;
                        
                        while (std::getline(ss, item, ','))
                        {
                            // Trim whitespace
                            item.erase(0, item.find_first_not_of(" \t"));
                            item.erase(item.find_last_not_of(" \t") + 1);
                            if (!item.empty())
                            {
                                result.push_back(item);
                            }
                        }
                        return result;
                    }
                    
                case ConfigType::OBJECT:
                default:
                    return str_value;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error converting string to type: " << e.what() << std::endl;
                return std::any{};
            }
        }

        std::string ConfigManager::getTypeName(ConfigType type)
        {
            switch (type)
            {
            case ConfigType::STRING: return "STRING";
            case ConfigType::INTEGER: return "INTEGER";
            case ConfigType::DOUBLE: return "DOUBLE";
            case ConfigType::BOOLEAN: return "BOOLEAN";
            case ConfigType::ARRAY: return "ARRAY";
            case ConfigType::OBJECT: return "OBJECT";
            default: return "UNKNOWN";
            }
        }

        // ==================== Statistics ====================
        ConfigManager::ConfigStats ConfigManager::getStatistics() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            ConfigStats stats;
            stats.total_keys = config_map_.size();
            
            for (const auto &[key, entry] : config_map_)
            {
                if (entry.is_required) stats.required_keys++;
                if (entry.is_readonly) stats.readonly_keys++;
                if (entry.validator) stats.keys_with_validators++;
                
                switch (entry.type)
                {
                case ConfigType::STRING: stats.string_keys++; break;
                case ConfigType::INTEGER: stats.integer_keys++; break;
                case ConfigType::DOUBLE: stats.double_keys++; break;
                case ConfigType::BOOLEAN: stats.boolean_keys++; break;
                case ConfigType::ARRAY: stats.array_keys++; break;
                case ConfigType::OBJECT: stats.object_keys++; break;
                }
            }
            
            return stats;
        }

        // ==================== Profiles ====================
        bool ConfigManager::saveProfile(const std::string &profile_name)
        {
            auto snapshot = createSnapshot();
            if (!snapshot)
            {
                return false;
            }

            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            profiles_[profile_name] = snapshot;
            return true;
        }

        bool ConfigManager::loadProfile(const std::string &profile_name)
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = profiles_.find(profile_name);
            if (it == profiles_.end())
            {
                return false;
            }

            lock.unlock();
            return restoreFromSnapshot(it->second);
        }

        std::vector<std::string> ConfigManager::getProfileNames() const
        {
            std::shared_lock<std::shared_mutex> lock(config_mutex_);
            
            std::vector<std::string> names;
            names.reserve(profiles_.size());
            
            for (const auto &[name, profile] : profiles_)
            {
                names.push_back(name);
            }
            
            std::sort(names.begin(), names.end());
            return names;
        }

        bool ConfigManager::deleteProfile(const std::string &profile_name)
        {
            std::unique_lock<std::shared_mutex> lock(config_mutex_);
            
            auto it = profiles_.find(profile_name);
            if (it == profiles_.end())
            {
                return false;
            }

            profiles_.erase(it);
            return true;
        }

        // ==================== Backup/Restore ====================
        bool ConfigManager::backup(const std::string &backup_file)
        {
            return saveToFile(backup_file);
        }

        bool ConfigManager::restore(const std::string &backup_file)
        {
            return loadFromFile(backup_file);
        }

        // ==================== Helper Methods ====================
        bool ConfigManager::isValidKey(const std::string &key) const
        {
            if (key.empty())
            {
                return false;
            }

            // Key should not start or end with dot
            if (key.front() == '.' || key.back() == '.')
            {
                return false;
            }

            // Key should not contain consecutive dots
            if (key.find("..") != std::string::npos)
            {
                return false;
            }

            // Key should only contain alphanumeric characters, dots, underscores, and hyphens
            return std::regex_match(key, std::regex(R"(^[a-zA-Z0-9._-]+$)"));
        }

        bool ConfigManager::isValidType(const std::any &value, ConfigType expected_type) const
        {
            try
            {
                switch (expected_type)
                {
                case ConfigType::STRING:
                    std::any_cast<std::string>(value);
                    return true;
                case ConfigType::INTEGER:
                    std::any_cast<int>(value);
                    return true;
                case ConfigType::DOUBLE:
                    std::any_cast<double>(value);
                    return true;
                case ConfigType::BOOLEAN:
                    std::any_cast<bool>(value);
                    return true;
                case ConfigType::ARRAY:
                    std::any_cast<std::vector<std::string>>(value);
                    return true;
                case ConfigType::OBJECT:
                    return true; // Accept any type for objects
                default:
                    return false;
                }
            }
            catch (const std::bad_any_cast &)
            {
                return false;
            }
        }

        ConfigType ConfigManager::detectType(const std::any &value) const
        {
            const std::type_info &type = value.type();
            
            if (type == typeid(std::string))
            {
                return ConfigType::STRING;
            }
            else if (type == typeid(int))
            {
                return ConfigType::INTEGER;
            }
            else if (type == typeid(double))
            {
                return ConfigType::DOUBLE;
            }
            else if (type == typeid(bool))
            {
                return ConfigType::BOOLEAN;
            }
            else if (type == typeid(std::vector<std::string>))
            {
                return ConfigType::ARRAY;
            }
            else
            {
                return ConfigType::OBJECT;
            }
        }

    } // namespace Common
} // namespace NetworkSecurity
