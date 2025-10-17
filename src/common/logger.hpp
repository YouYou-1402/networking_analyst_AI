// src/common/logger.hpp
#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "utils.hpp"
#include <string>
#include <memory>
#include <fstream>
#include <mutex>
#include <atomic>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <unordered_map>
#include <array>
#include <sstream>
#include <iostream>
#include <shared_mutex>
#include <type_traits>
#include <vector>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Enum cho các mức độ log
         */
        enum class LogLevel : int
        {
            TRACE = 0,
            DEBUG = 1,
            INFO = 2,
            WARN = 3,
            ERROR = 4,
            FATAL = 5,
            OFF = 6
        };

        /**
         * @brief Enum cho các loại output
         */
        enum class LogOutput
        {
            CONSOLE,
            FILE,
            SYSLOG,
            NETWORK,
            CALLBACK
        };

        /**
         * @brief Struct chứa thông tin một log entry
         */
        struct LogEntry
        {
            uint64_t timestamp;
            LogLevel level;
            std::string logger_name;
            std::string message;
            std::string file;
            std::string function;
            int line;
            std::thread::id thread_id;
            std::string formatted_message;

            LogEntry() : timestamp(0), level(LogLevel::INFO), line(0) {}

            LogEntry(LogLevel lvl, const std::string &name, const std::string &msg,
                     const std::string &f = "", const std::string &func = "", int l = 0)
                : timestamp(Utils::getCurrentTimestampUs()), 
                  level(lvl), 
                  logger_name(name), 
                  message(msg), 
                  file(f), 
                  function(func), 
                  line(l), 
                  thread_id(std::this_thread::get_id())
            {
            }
        };

        /**
         * @brief Interface cho log formatters
         */
        class LogFormatter
        {
        public:
            virtual ~LogFormatter() = default;
            virtual std::string format(const LogEntry &entry) = 0;
            virtual std::unique_ptr<LogFormatter> clone() const = 0;
        };

        /**
         * @brief Default formatter
         */
        class DefaultFormatter : public LogFormatter
        {
        public:
            DefaultFormatter(const std::string &pattern = "[{timestamp}] [{level}] [{logger}] {message}");
            std::string format(const LogEntry &entry) override;
            std::unique_ptr<LogFormatter> clone() const override;

        private:
            std::string pattern_;
        };

        /**
         * @brief JSON formatter
         */
        class JsonFormatter : public LogFormatter
        {
        public:
            JsonFormatter(bool pretty_print = false);
            std::string format(const LogEntry &entry) override;
            std::unique_ptr<LogFormatter> clone() const override;

        private:
            bool pretty_print_;
        };

        /**
         * @brief Interface cho log appenders
         */
        class LogAppender
        {
        public:
            virtual ~LogAppender() = default;
            virtual bool append(const LogEntry &entry) = 0;
            virtual void flush() = 0;
            virtual void close() = 0;
            virtual std::unique_ptr<LogAppender> clone() const = 0;

            void setFormatter(std::unique_ptr<LogFormatter> formatter);
            void setLevel(LogLevel level);
            LogLevel getLevel() const;

        protected:
            std::unique_ptr<LogFormatter> formatter_;
            LogLevel level_ = LogLevel::TRACE;
        };

        /**
         * @brief Console appender
         */
        class ConsoleAppender : public LogAppender
        {
        public:
            ConsoleAppender(bool use_colors = true);
            bool append(const LogEntry &entry) override;
            void flush() override;
            void close() override;
            std::unique_ptr<LogAppender> clone() const override;

        private:
            bool use_colors_;
            mutable std::mutex console_mutex_;
            std::string getColorCode(LogLevel level) const;
            std::string getResetCode() const;
        };

        /**
         * @brief File appender
         */
        class FileAppender : public LogAppender
        {
        public:
            FileAppender(const std::string &filename, bool append_mode = true);
            ~FileAppender();
            bool append(const LogEntry &entry) override;
            void flush() override;
            void close() override;
            std::unique_ptr<LogAppender> clone() const override;

            void setMaxFileSize(size_t max_size);
            void setMaxFiles(int max_files);
            void enableRotation(bool enable);

        private:
            std::string filename_;
            std::ofstream file_stream_;
            mutable std::mutex file_mutex_;
            size_t max_file_size_;
            int max_files_;
            bool rotation_enabled_;
            size_t current_file_size_;

            void rotateFile();
            std::string getRotatedFilename(int index) const;
        };

        /**
         * @brief Rotating file appender
         */
        class RotatingFileAppender : public FileAppender
        {
        public:
            RotatingFileAppender(const std::string &filename, 
                               size_t max_size = 10 * 1024 * 1024, 
                               int max_files = 5);
        };

        /**
         * @brief Syslog appender (Linux/Unix only)
         */
        class SyslogAppender : public LogAppender
        {
        public:
            SyslogAppender(const std::string &ident = "NetworkSecurity", 
                          int facility = 16); // LOG_LOCAL0
            ~SyslogAppender();
            bool append(const LogEntry &entry) override;
            void flush() override;
            void close() override;
            std::unique_ptr<LogAppender> clone() const override;

        private:
            std::string ident_;
            int facility_;
            bool opened_;
            int getSyslogPriority(LogLevel level) const;
        };

        /**
         * @brief Network appender (UDP)
         */
        class NetworkAppender : public LogAppender
        {
        public:
            NetworkAppender(const std::string &host, int port);
            ~NetworkAppender();
            bool append(const LogEntry &entry) override;
            void flush() override;
            void close() override;
            std::unique_ptr<LogAppender> clone() const override;

        private:
            std::string host_;
            int port_;
            int socket_fd_;
            mutable std::mutex network_mutex_;
            bool initSocket();
        };

        /**
         * @brief Callback appender
         */
        class CallbackAppender : public LogAppender
        {
        public:
            using LogCallback = std::function<void(const LogEntry &)>;

            CallbackAppender(LogCallback callback);
            bool append(const LogEntry &entry) override;
            void flush() override;
            void close() override;
            std::unique_ptr<LogAppender> clone() const override;

        private:
            LogCallback callback_;
        };

        /**
         * @brief Main Logger class
         */
        class Logger
        {
        public:
            explicit Logger(const std::string &name);
            ~Logger();

            // ==================== Basic logging methods ====================
            void trace(const std::string &message, 
                      const std::string &file = "", 
                      const std::string &function = "", 
                      int line = 0);
            
            void debug(const std::string &message, 
                      const std::string &file = "", 
                      const std::string &function = "", 
                      int line = 0);
            
            void info(const std::string &message, 
                     const std::string &file = "", 
                     const std::string &function = "", 
                     int line = 0);
            
            void warn(const std::string &message, 
                     const std::string &file = "", 
                     const std::string &function = "", 
                     int line = 0);
            
            void error(const std::string &message, 
                      const std::string &file = "", 
                      const std::string &function = "", 
                      int line = 0);
            
            void fatal(const std::string &message, 
                      const std::string &file = "", 
                      const std::string &function = "", 
                      int line = 0);

            // ==================== Formatted logging methods ====================
            template <typename... Args>
            void trace(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::TRACE))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    trace(message, "", "", 0);
                }
            }

            template <typename... Args>
            void debug(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::DEBUG))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    debug(message, "", "", 0);
                }
            }

            template <typename... Args>
            void info(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::INFO))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    info(message, "", "", 0);
                }
            }

            template <typename... Args>
            void warn(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::WARN))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    warn(message, "", "", 0);
                }
            }

            template <typename... Args>
            void error(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::ERROR))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    error(message, "", "", 0);
                }
            }

            template <typename... Args>
            void fatal(const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(LogLevel::FATAL))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    fatal(message, "", "", 0);
                }
            }

            // ==================== Generic log method ====================
            void log(LogLevel level, 
                    const std::string &message, 
                    const std::string &file = "", 
                    const std::string &function = "", 
                    int line = 0);

            template <typename... Args>
            void log(LogLevel level, const std::string &format, Args &&...args)
            {
                if (isLevelEnabled(level))
                {
                    std::string message = formatMessage(format, std::forward<Args>(args)...);
                    log(level, message, "", "", 0);
                }
            }

            // ==================== Level control ====================
            void setLevel(LogLevel level);
            LogLevel getLevel() const;
            bool isLevelEnabled(LogLevel level) const;

            // ==================== Appender management ====================
            void addAppender(std::unique_ptr<LogAppender> appender);
            void removeAllAppenders();
            size_t getAppenderCount() const;

            // ==================== Utility methods ====================
            const std::string &getName() const;
            void flush();
            void close();

            // ==================== Async logging control ====================
            void enableAsyncLogging(bool enable = true);
            bool isAsyncLoggingEnabled() const;
            void setAsyncQueueSize(size_t size);

        private:
            std::string name_;
            std::atomic<LogLevel> level_;
            std::vector<std::unique_ptr<LogAppender>> appenders_;
            mutable std::shared_mutex appenders_mutex_;

            // Async logging
            std::atomic<bool> async_enabled_;
            std::queue<LogEntry> async_queue_;
            std::mutex async_mutex_;
            std::condition_variable async_cv_;
            std::thread async_thread_;
            std::atomic<bool> async_stop_;
            size_t max_queue_size_;

            void processEntry(const LogEntry &entry);
            void asyncWorker();

            // ==================== Helper to convert value to string ====================
            template<typename T>
            std::string valueToString(T&& value) const
            {
                using DecayT = typename std::decay<T>::type;
                
                // Check if it's a string type (const char*, char*, std::string)
                if constexpr (std::is_same_v<DecayT, std::string>)
                {
                    return std::forward<T>(value);
                }
                else if constexpr (std::is_same_v<DecayT, const char*> || 
                                  std::is_same_v<DecayT, char*>)
                {
                    return std::string(value);
                }
                else if constexpr (std::is_array_v<DecayT> && 
                                  std::is_same_v<typename std::remove_extent<DecayT>::type, char>)
                {
                    // Handle char arrays
                    return std::string(value);
                }
                // Check if it's a numeric type
                else if constexpr (std::is_arithmetic_v<DecayT>)
                {
                    return std::to_string(value);
                }
                // Check if it's a pointer (except char*)
                else if constexpr (std::is_pointer_v<DecayT>)
                {
                    std::ostringstream oss;
                    oss << static_cast<const void*>(value);
                    return oss.str();
                }
                // For other types, use stringstream
                else
                {
                    std::ostringstream oss;
                    oss << value;
                    return oss.str();
                }
            }

            // ==================== Format message methods ====================
            /**
             * @brief Format message with multiple arguments
             * Supports {} placeholders for arguments
             * 
             * Example:
             *   formatMessage("User {} logged in from {}", "john", "192.168.1.1")
             *   => "User john logged in from 192.168.1.1"
             */
            template <typename T, typename... Args>
            std::string formatMessage(const std::string &format, T &&value, Args &&...args) const
            {
                size_t pos = format.find("{}");
                if (pos != std::string::npos)
                {
                    // Replace first {} with value and continue with remaining args
                    std::string partial = format.substr(0, pos) + 
                                         valueToString(std::forward<T>(value)) + 
                                         format.substr(pos + 2);
                    return formatMessage(partial, std::forward<Args>(args)...);
                }
                else
                {
                    // No {} found, append value at the end and continue
                    return formatMessage(format + " " + valueToString(std::forward<T>(value)), 
                                       std::forward<Args>(args)...);
                }
            }

            /**
             * @brief Base case - no more arguments
             */
            template <typename T>
            std::string formatMessage(const std::string &format, T &&value) const
            {
                size_t pos = format.find("{}");
                if (pos != std::string::npos)
                {
                    // Replace first {} with value
                    return format.substr(0, pos) + 
                           valueToString(std::forward<T>(value)) + 
                           format.substr(pos + 2);
                }
                else
                {
                    // No {} found, append value at the end
                    return format + " " + valueToString(std::forward<T>(value));
                }
            }

            /**
             * @brief Base case - no arguments
             */
            std::string formatMessage(const std::string &format) const
            {
                return format;
            }
        };

        /**
         * @brief Logger Manager - Singleton quản lý tất cả loggers
         */
        class LoggerManager : public Singleton<LoggerManager>
        {
            friend class Singleton<LoggerManager>;

        public:
            /**
             * @brief Lấy logger theo tên
             */
            std::shared_ptr<Logger> getLogger(const std::string &name);

            /**
             * @brief Tạo logger mới
             */
            std::shared_ptr<Logger> createLogger(const std::string &name);

            /**
             * @brief Xóa logger
             */
            bool removeLogger(const std::string &name);

            /**
             * @brief Lấy tất cả logger names
             */
            std::vector<std::string> getAllLoggerNames() const;

            /**
             * @brief Set global log level cho tất cả loggers
             */
            void setGlobalLevel(LogLevel level);

            /**
             * @brief Load cấu hình từ file
             */
            bool loadConfiguration(const std::string &config_file);

            /**
             * @brief Load cấu hình từ JSON string
             */
            bool loadConfigurationFromJson(const std::string &json_config);

            /**
             * @brief Shutdown tất cả loggers
             */
            void shutdown();

            /**
             * @brief Flush tất cả loggers
             */
            void flushAll();

            /**
             * @brief Set default formatter cho new loggers
             */
            void setDefaultFormatter(std::unique_ptr<LogFormatter> formatter);

            /**
             * @brief Add default appender cho new loggers
             */
            void addDefaultAppender(std::unique_ptr<LogAppender> appender);

            /**
             * @brief Enable/disable async logging globally
             */
            void enableGlobalAsyncLogging(bool enable = true);

        protected:
            LoggerManager();
            virtual ~LoggerManager();

        private:
            mutable std::shared_mutex loggers_mutex_;
            std::unordered_map<std::string, std::shared_ptr<Logger>> loggers_;
            std::unique_ptr<LogFormatter> default_formatter_;
            std::vector<std::unique_ptr<LogAppender>> default_appenders_;
            std::atomic<bool> global_async_enabled_;
            LogLevel global_level_;

            /**
             * @brief Apply default configuration to a logger
             */
            void applyDefaultConfiguration(std::shared_ptr<Logger> logger);
        };

        // ==================== Helper functions ====================
        
        /**
         * @brief Convert LogLevel to string
         */
        std::string logLevelToString(LogLevel level);

        /**
         * @brief Convert string to LogLevel
         */
        LogLevel stringToLogLevel(const std::string &level_str);

        /**
         * @brief Get color code for log level
         */
        std::string getLogLevelColor(LogLevel level);

    } // namespace Common
} // namespace NetworkSecurity

// ==================== Convenience macros ====================

// Get logger instance
#define GET_LOGGER(name) NetworkSecurity::Common::LoggerManager::getInstance().getLogger(name)

// Logger Manager instance
#define LOG_MANAGER NetworkSecurity::Common::LoggerManager::getInstance()

// Logging macros with file/line info
#define LOG_TRACE(logger, msg) logger->trace(msg, __FILE__, __FUNCTION__, __LINE__)
#define LOG_DEBUG(logger, msg) logger->debug(msg, __FILE__, __FUNCTION__, __LINE__)
#define LOG_INFO(logger, msg) logger->info(msg, __FILE__, __FUNCTION__, __LINE__)
#define LOG_WARN(logger, msg) logger->warn(msg, __FILE__, __FUNCTION__, __LINE__)
#define LOG_ERROR(logger, msg) logger->error(msg, __FILE__, __FUNCTION__, __LINE__)
#define LOG_FATAL(logger, msg) logger->fatal(msg, __FILE__, __FUNCTION__, __LINE__)

// Formatted logging macros
#define LOG_TRACE_FMT(logger, fmt, ...) logger->trace(fmt, __VA_ARGS__)
#define LOG_DEBUG_FMT(logger, fmt, ...) logger->debug(fmt, __VA_ARGS__)
#define LOG_INFO_FMT(logger, fmt, ...) logger->info(fmt, __VA_ARGS__)
#define LOG_WARN_FMT(logger, fmt, ...) logger->warn(fmt, __VA_ARGS__)
#define LOG_ERROR_FMT(logger, fmt, ...) logger->error(fmt, __VA_ARGS__)
#define LOG_FATAL_FMT(logger, fmt, ...) logger->fatal(fmt, __VA_ARGS__)

#endif // LOGGER_HPP
