// src/common/utils.cpp
#include "utils.hpp"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <random>
#include <regex>
#include <iomanip>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <thread>
#include <climits>
#include <cstring>

// OpenSSL headers
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// System headers
#ifdef __linux__
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#endif

// zlib for CRC32
#include <zlib.h>

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== Time utilities ====================
        std::string Utils::getCurrentTimestamp()
        {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch()) %
                      1000;

            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
            return ss.str();
        }

        uint64_t Utils::getCurrentTimestampMs()
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        uint64_t Utils::getCurrentTimestampUs()
        {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        std::string Utils::formatTimestamp(uint64_t timestamp)
        {
            auto time_point = std::chrono::system_clock::from_time_t(timestamp / 1000);
            auto time_t = std::chrono::system_clock::to_time_t(time_point);
            auto ms = timestamp % 1000;

            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            ss << '.' << std::setfill('0') << std::setw(3) << ms;
            return ss.str();
        }

        std::string Utils::formatTimestamp(uint64_t timestamp, const std::string &format)
        {
            auto time_point = std::chrono::system_clock::from_time_t(timestamp / 1000);
            auto time_t = std::chrono::system_clock::to_time_t(time_point);

            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), format.c_str());
            return ss.str();
        }

        uint64_t Utils::timeDifference(uint64_t start_time, uint64_t end_time)
        {
            return (end_time > start_time) ? (end_time - start_time) : 0;
        }

        // ==================== String utilities ====================
        std::vector<std::string> Utils::split(const std::string &str, char delimiter)
        {
            std::vector<std::string> tokens;
            std::stringstream ss(str);
            std::string token;

            while (std::getline(ss, token, delimiter))
            {
                tokens.push_back(token);
            }
            return tokens;
        }

        std::vector<std::string> Utils::split(const std::string &str, const std::string &delimiter)
        {
            std::vector<std::string> tokens;
            size_t start = 0;
            size_t end = str.find(delimiter);

            while (end != std::string::npos)
            {
                tokens.push_back(str.substr(start, end - start));
                start = end + delimiter.length();
                end = str.find(delimiter, start);
            }
            tokens.push_back(str.substr(start));
            return tokens;
        }

        std::string Utils::trim(const std::string &str)
        {
            return trim(str, " \t\n\r\f\v");
        }

        std::string Utils::trim(const std::string &str, const std::string &chars)
        {
            size_t start = str.find_first_not_of(chars);
            if (start == std::string::npos)
                return "";

            size_t end = str.find_last_not_of(chars);
            return str.substr(start, end - start + 1);
        }

        std::string Utils::toLowerCase(const std::string &str)
        {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), ::tolower);
            return result;
        }

        std::string Utils::toUpperCase(const std::string &str)
        {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), ::toupper);
            return result;
        }

        bool Utils::startsWith(const std::string &str, const std::string &prefix)
        {
            return str.length() >= prefix.length() &&
                   str.compare(0, prefix.length(), prefix) == 0;
        }

        bool Utils::endsWith(const std::string &str, const std::string &suffix)
        {
            return str.length() >= suffix.length() &&
                   str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
        }

        std::string Utils::replaceAll(const std::string &str, const std::string &from, const std::string &to)
        {
            if (from.empty())
                return str;

            std::string result = str;
            size_t pos = 0;
            while ((pos = result.find(from, pos)) != std::string::npos)
            {
                result.replace(pos, from.length(), to);
                pos += to.length();
            }
            return result;
        }

        std::string Utils::join(const std::vector<std::string> &strings, const std::string &delimiter)
        {
            if (strings.empty())
                return "";

            std::stringstream ss;
            for (size_t i = 0; i < strings.size(); ++i)
            {
                if (i > 0)
                    ss << delimiter;
                ss << strings[i];
            }
            return ss.str();
        }

        bool Utils::containsIgnoreCase(const std::string &str, const std::string &substring)
        {
            std::string str_lower = toLowerCase(str);
            std::string sub_lower = toLowerCase(substring);
            return str_lower.find(sub_lower) != std::string::npos;
        }

        // ==================== Hash utilities - UPDATED ====================
        std::string Utils::calculateMD5(const std::string &data)
        {
            return calculateMD5(data.c_str(), data.length());
        }

        std::string Utils::calculateMD5(const void *data, size_t length)
        {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) {
                return "";
            }

            // Initialize MD5 digest
            if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Update with data
            if (EVP_DigestUpdate(ctx, data, length) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Finalize and get hash
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len;
            if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            EVP_MD_CTX_free(ctx);

            // Convert to hex string
            std::stringstream ss;
            for (unsigned int i = 0; i < hash_len; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string Utils::calculateSHA256(const std::string &data)
        {
            return calculateSHA256(data.c_str(), data.length());
        }

        std::string Utils::calculateSHA256(const void *data, size_t length)
        {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) {
                return "";
            }

            // Initialize SHA256 digest
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Update with data
            if (EVP_DigestUpdate(ctx, data, length) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Finalize and get hash
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len;
            if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            EVP_MD_CTX_free(ctx);

            // Convert to hex string
            std::stringstream ss;
            for (unsigned int i = 0; i < hash_len; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        uint32_t Utils::calculateCRC32(const void *data, size_t length)
        {
            return crc32(0L, static_cast<const Bytef *>(data), length);
        }

        uint64_t Utils::hashString(const std::string &str)
        {
            // FNV-1a hash algorithm
            const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
            const uint64_t FNV_PRIME = 1099511628211ULL;

            uint64_t hash = FNV_OFFSET_BASIS;
            for (char c : str)
            {
                hash ^= static_cast<uint64_t>(c);
                hash *= FNV_PRIME;
            }
            return hash;
        }
        // ==================== File utilities ====================
        bool Utils::fileExists(const std::string &filepath)
        {
            struct stat buffer;
            return (stat(filepath.c_str(), &buffer) == 0) && S_ISREG(buffer.st_mode);
        }

        bool Utils::directoryExists(const std::string &dirpath)
        {
            struct stat buffer;
            return (stat(dirpath.c_str(), &buffer) == 0) && S_ISDIR(buffer.st_mode);
        }

        bool Utils::createDirectory(const std::string &dirpath)
        {
            if (directoryExists(dirpath))
                return true;

            // Create parent directories recursively
            size_t pos = dirpath.find_last_of('/');
            if (pos != std::string::npos)
            {
                std::string parent = dirpath.substr(0, pos);
                if (!createDirectory(parent))
                    return false;
            }

            return mkdir(dirpath.c_str(), 0755) == 0;
        }

        std::string Utils::readFileToString(const std::string &filepath)
        {
            std::ifstream file(filepath, std::ios::binary);
            if (!file.is_open())
                return "";

            file.seekg(0, std::ios::end);
            size_t size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::string content(size, '\0');
            file.read(&content[0], size);
            return content;
        }

        std::vector<uint8_t> Utils::readFileToBytes(const std::string &filepath)
        {
            std::ifstream file(filepath, std::ios::binary);
            if (!file.is_open())
                return {};

            file.seekg(0, std::ios::end);
            size_t size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> data(size);
            file.read(reinterpret_cast<char *>(data.data()), size);
            return data;
        }

        bool Utils::writeStringToFile(const std::string &filepath, const std::string &content, bool append)
        {
            std::ios::openmode mode = std::ios::binary;
            if (append)
                mode |= std::ios::app;
            else
                mode |= std::ios::trunc;

            std::ofstream file(filepath, mode);
            if (!file.is_open())
                return false;

            file.write(content.c_str(), content.length());
            return file.good();
        }

        bool Utils::writeBytesToFile(const std::string &filepath, const std::vector<uint8_t> &data, bool append)
        {
            std::ios::openmode mode = std::ios::binary;
            if (append)
                mode |= std::ios::app;
            else
                mode |= std::ios::trunc;

            std::ofstream file(filepath, mode);
            if (!file.is_open())
                return false;

            file.write(reinterpret_cast<const char *>(data.data()), data.size());
            return file.good();
        }

        size_t Utils::getFileSize(const std::string &filepath)
        {
            struct stat buffer;
            if (stat(filepath.c_str(), &buffer) != 0)
                return 0;
            return buffer.st_size;
        }

        uint64_t Utils::getFileModificationTime(const std::string &filepath)
        {
            struct stat buffer;
            if (stat(filepath.c_str(), &buffer) != 0)
                return 0;
            return static_cast<uint64_t>(buffer.st_mtime) * 1000; // Convert to milliseconds
        }

        std::string Utils::getFileName(const std::string &filepath)
        {
            size_t pos = filepath.find_last_of('/');
            if (pos == std::string::npos)
                return filepath;
            return filepath.substr(pos + 1);
        }

        std::string Utils::getDirectoryName(const std::string &filepath)
        {
            size_t pos = filepath.find_last_of('/');
            if (pos == std::string::npos)
                return ".";
            return filepath.substr(0, pos);
        }

        std::string Utils::getFileExtension(const std::string &filepath)
        {
            std::string filename = getFileName(filepath);
            size_t pos = filename.find_last_of('.');
            if (pos == std::string::npos)
                return "";
            return filename.substr(pos);
        }

        // ==================== Memory utilities ====================
        std::string Utils::formatBytes(size_t bytes)
        {
            const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
            const size_t num_units = sizeof(units) / sizeof(units[0]);

            double size = static_cast<double>(bytes);
            size_t unit_index = 0;

            while (size >= 1024.0 && unit_index < num_units - 1)
            {
                size /= 1024.0;
                unit_index++;
            }

            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
            return ss.str();
        }

        void Utils::hexDump(const void *data, size_t length, std::ostream &os, size_t bytes_per_line)
        {
            const uint8_t *bytes = static_cast<const uint8_t *>(data);

            for (size_t i = 0; i < length; i += bytes_per_line)
            {
                // Print offset
                os << std::hex << std::setw(8) << std::setfill('0') << i << ": ";

                // Print hex bytes
                for (size_t j = 0; j < bytes_per_line; ++j)
                {
                    if (i + j < length)
                    {
                        os << std::hex << std::setw(2) << std::setfill('0')
                           << static_cast<int>(bytes[i + j]) << " ";
                    }
                    else
                    {
                        os << "   ";
                    }
                }

                os << " ";

                // Print ASCII representation
                for (size_t j = 0; j < bytes_per_line && i + j < length; ++j)
                {
                    char c = bytes[i + j];
                    os << (std::isprint(c) ? c : '.');
                }

                os << std::endl;
            }
        }

        std::string Utils::bytesToHex(const void *data, size_t length)
        {
            const uint8_t *bytes = static_cast<const uint8_t *>(data);
            std::stringstream ss;

            for (size_t i = 0; i < length; ++i)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            }
            return ss.str();
        }

        std::vector<uint8_t> Utils::hexToBytes(const std::string &hex_str)
        {
            std::vector<uint8_t> bytes;

            for (size_t i = 0; i < hex_str.length(); i += 2)
            {
                if (i + 1 < hex_str.length())
                {
                    std::string byte_str = hex_str.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                    bytes.push_back(byte);
                }
            }
            return bytes;
        }

        bool Utils::secureMemoryCompare(const void *ptr1, const void *ptr2, size_t length)
        {
            const uint8_t *a = static_cast<const uint8_t *>(ptr1);
            const uint8_t *b = static_cast<const uint8_t *>(ptr2);
            uint8_t result = 0;

            for (size_t i = 0; i < length; ++i)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        // ==================== System utilities ====================
        int Utils::getCPUCount()
        {
            return std::thread::hardware_concurrency();
        }

        size_t Utils::getMemoryUsage()
        {
#ifdef __linux__
            std::ifstream file("/proc/self/status");
            std::string line;

            while (std::getline(file, line))
            {
                if (startsWith(line, "VmRSS:"))
                {
                    std::stringstream ss(line);
                    std::string key, value, unit;
                    ss >> key >> value >> unit;

                    size_t memory_kb = stringToInt(value);
                    return memory_kb * 1024; // Convert to bytes
                }
            }
#endif
            return 0;
        }

        size_t Utils::getTotalSystemMemory()
        {
#ifdef __linux__
            struct sysinfo info;
            if (sysinfo(&info) == 0)
            {
                return info.totalram * info.mem_unit;
            }
#endif
            return 0;
        }

        size_t Utils::getAvailableSystemMemory()
        {
#ifdef __linux__
            struct sysinfo info;
            if (sysinfo(&info) == 0)
            {
                return info.freeram * info.mem_unit;
            }
#endif
            return 0;
        }

        std::string Utils::getHostname()
        {
            char hostname[HOST_NAME_MAX];
            if (gethostname(hostname, sizeof(hostname)) == 0)
            {
                return std::string(hostname);
            }
            return "unknown";
        }

        std::string Utils::getProcessName()
        {
            std::string cmdline = readFileToString("/proc/self/cmdline");
            if (!cmdline.empty())
            {
                size_t pos = cmdline.find('\0');
                if (pos != std::string::npos)
                {
                    cmdline = cmdline.substr(0, pos);
                }
                return getFileName(cmdline);
            }
            return "unknown";
        }

        int Utils::getProcessId()
        {
            return getpid();
        }

        int Utils::getUserId()
        {
            return getuid();
        }

        double Utils::getCPUUsage()
        {
#ifdef __linux__
            static uint64_t prev_idle = 0, prev_total = 0;

            std::ifstream file("/proc/stat");
            std::string line;

            if (std::getline(file, line) && startsWith(line, "cpu "))
            {
                std::stringstream ss(line);
                std::string cpu;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal;

                ss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

                uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
                uint64_t total_diff = total - prev_total;
                uint64_t idle_diff = idle - prev_idle;

                double usage = 0.0;
                if (total_diff > 0)
                {
                    usage = 100.0 * (total_diff - idle_diff) / total_diff;
                }

                prev_total = total;
                prev_idle = idle;

                return usage;
            }
#endif
            return 0.0;
        }

        // ==================== Random utilities ====================
        int Utils::randomInt(int min, int max)
        {
            static thread_local std::random_device rd;
            static thread_local std::mt19937 gen(rd());
            std::uniform_int_distribution<int> dis(min, max);
            return dis(gen);
        }

        double Utils::randomDouble(double min, double max)
        {
            static thread_local std::random_device rd;
            static thread_local std::mt19937 gen(rd());
            std::uniform_real_distribution<double> dis(min, max);
            return dis(gen);
        }

        std::string Utils::randomString(size_t length, const std::string &charset)
        {
            std::string result;
            result.reserve(length);

            for (size_t i = 0; i < length; ++i)
            {
                result += charset[randomInt(0, charset.length() - 1)];
            }
            return result;
        }

        std::string Utils::generateUUID()
        {
            static thread_local std::random_device rd;
            static thread_local std::mt19937 gen(rd());
            std::uniform_int_distribution<int> dis(0, 15);
            std::uniform_int_distribution<int> dis2(8, 11);

            std::stringstream ss;
            ss << std::hex;

            for (int i = 0; i < 8; i++)
                ss << dis(gen);
            ss << "-";
            for (int i = 0; i < 4; i++)
                ss << dis(gen);
            ss << "-4";
            for (int i = 0; i < 3; i++)
                ss << dis(gen);
            ss << "-";
            ss << dis2(gen);
            for (int i = 0; i < 3; i++)
                ss << dis(gen);
            ss << "-";
            for (int i = 0; i < 12; i++)
                ss << dis(gen);

            return ss.str();
        }

        // ==================== Validation utilities ====================
        bool Utils::isNumeric(const std::string &str)
        {
            if (str.empty())
                return false;

            size_t start = 0;
            if (str[0] == '+' || str[0] == '-')
                start = 1;

            bool has_digit = false;
            bool has_dot = false;

            for (size_t i = start; i < str.length(); ++i)
            {
                if (std::isdigit(str[i]))
                {
                    has_digit = true;
                }
                else if (str[i] == '.' && !has_dot)
                {
                    has_dot = true;
                }
                else
                {
                    return false;
                }
            }
            return has_digit;
        }

        bool Utils::isInteger(const std::string &str)
        {
            if (str.empty())
                return false;

            size_t start = 0;
            if (str[0] == '+' || str[0] == '-')
                start = 1;

            for (size_t i = start; i < str.length(); ++i)
            {
                if (!std::isdigit(str[i]))
                    return false;
            }
            return start < str.length();
        }

        bool Utils::isFloat(const std::string &str)
        {
            return isNumeric(str) && str.find('.') != std::string::npos;
        }

        bool Utils::isValidEmail(const std::string &email)
        {
            const std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
            return std::regex_match(email, email_regex);
        }

        // ==================== Conversion utilities ====================
        int Utils::stringToInt(const std::string &str, int default_value)
        {
            try
            {
                return std::stoi(str);
            }
            catch (const std::exception &)
            {
                return default_value;
            }
        }

        double Utils::stringToDouble(const std::string &str, double default_value)
        {
            try
            {
                return std::stod(str);
            }
            catch (const std::exception &)
            {
                return default_value;
            }
        }

        bool Utils::stringToBool(const std::string &str, bool default_value)
        {
            std::string lower_str = toLowerCase(trim(str));

            if (lower_str == "true" || lower_str == "1" || lower_str == "yes" || lower_str == "on")
                return true;
            else if (lower_str == "false" || lower_str == "0" || lower_str == "no" || lower_str == "off")
                return false;
            else
                return default_value;
        }

        // ==================== Timer implementation ====================
        Timer::Timer() : Timer("Timer")
        {
        }

        Timer::Timer(const std::string &name)
            : name_(name), is_running_(false), auto_print_(false)
        {
            start();
        }

        Timer::~Timer()
        {
            if (is_running_ && auto_print_)
            {
                stop();
                // Could log the elapsed time here if logger is available
            }
        }

        void Timer::start()
        {
            start_time_ = std::chrono::high_resolution_clock::now();
            is_running_ = true;
        }

        void Timer::stop()
        {
            if (is_running_)
            {
                end_time_ = std::chrono::high_resolution_clock::now();
                is_running_ = false;
            }
        }

        double Timer::getElapsedMs() const
        {
            auto end_time = is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
            return duration.count() / 1000.0;
        }

        double Timer::getElapsedUs() const
        {
            auto end_time = is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
            return static_cast<double>(duration.count());
        }

        void Timer::reset()
        {
            start_time_ = std::chrono::high_resolution_clock::now();
            is_running_ = true;
        }

        const std::string &Timer::getName() const
        {
            return name_;
        }

        // ==================== ScopeGuard implementation ====================
        ScopeGuard::ScopeGuard(std::function<void()> cleanup_func)
            : cleanup_func_(std::move(cleanup_func)), dismissed_(false)
        {
        }

        ScopeGuard::~ScopeGuard()
        {
            if (!dismissed_ && cleanup_func_)
            {
                try
                {
                    cleanup_func_();
                }
                catch (...)
                {
                    // Swallow exceptions in destructor
                }
            }
        }

        void ScopeGuard::dismiss()
        {
            dismissed_ = true;
        }

    } // namespace Common
} // namespace NetworkSecurity
