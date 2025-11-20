// src/common/logger.cpp
#include "logger.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <string.h>
#ifdef __linux__
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <ctime>

namespace {
    std::string formatTimestampCorrectly(uint64_t timestamp_us) {
        time_t seconds = static_cast<time_t>(timestamp_us / 1000000);
        uint64_t microseconds = timestamp_us % 1000000;
        
        struct tm timeinfo;
        #ifdef _WIN32
            localtime_s(&timeinfo, &seconds);
        #else
            localtime_r(&seconds, &timeinfo);
        #endif
        
        char buffer[64];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
        snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), 
                 ".%03lu", static_cast<unsigned long>(microseconds / 1000));
        
        return std::string(buffer);
    }
}

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== DefaultFormatter Implementation ====================
        DefaultFormatter::DefaultFormatter(const std::string &pattern)
            : pattern_(pattern)
        {
        }

        std::string DefaultFormatter::format(const LogEntry &entry)
        {
            std::string result = pattern_;
            
            // Replace {timestamp}
            size_t pos = result.find("{timestamp}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 11, formatTimestampCorrectly(entry.timestamp));
            }
            
            // Replace {level}
            pos = result.find("{level}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 7, logLevelToString(entry.level));
            }
            
            // Replace {logger}
            pos = result.find("{logger}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 8, entry.logger_name);
            }
            
            // Replace {message}
            pos = result.find("{message}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 9, entry.message);
            }
            
            // Replace {file}
            pos = result.find("{file}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 6, entry.file);
            }
            
            // Replace {function}
            pos = result.find("{function}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 10, entry.function);
            }
            
            // Replace {line}
            pos = result.find("{line}");
            if (pos != std::string::npos)
            {
                result.replace(pos, 6, std::to_string(entry.line));
            }
            
            // Replace {thread}
            pos = result.find("{thread}");
            if (pos != std::string::npos)
            {
                std::ostringstream oss;
                oss << entry.thread_id;
                result.replace(pos, 8, oss.str());
            }
            
            return result;
        }

        std::unique_ptr<LogFormatter> DefaultFormatter::clone() const
        {
            return std::make_unique<DefaultFormatter>(pattern_);
        }

        // ==================== JsonFormatter Implementation ====================
        JsonFormatter::JsonFormatter(bool pretty_print)
            : pretty_print_(pretty_print)
        {
        }

        std::string JsonFormatter::format(const LogEntry &entry)
        {
            std::ostringstream oss;
            
            if (pretty_print_)
            {
                oss << "{\n";
                oss << "  \"timestamp\": " << entry.timestamp << ",\n";
                oss << "  \"level\": \"" << logLevelToString(entry.level) << "\",\n";
                oss << "  \"logger\": \"" << entry.logger_name << "\",\n";
                oss << "  \"message\": \"" << entry.message << "\",\n";
                oss << "  \"file\": \"" << entry.file << "\",\n";
                oss << "  \"function\": \"" << entry.function << "\",\n";
                oss << "  \"line\": " << entry.line << ",\n";
                oss << "  \"thread_id\": \"" << entry.thread_id << "\"\n";
                oss << "}";
            }
            else
            {
                oss << "{";
                oss << "\"timestamp\":" << entry.timestamp << ",";
                oss << "\"level\":\"" << logLevelToString(entry.level) << "\",";
                oss << "\"logger\":\"" << entry.logger_name << "\",";
                oss << "\"message\":\"" << entry.message << "\",";
                oss << "\"file\":\"" << entry.file << "\",";
                oss << "\"function\":\"" << entry.function << "\",";
                oss << "\"line\":" << entry.line << ",";
                oss << "\"thread_id\":\"" << entry.thread_id << "\"";
                oss << "}";
            }
            
            return oss.str();
        }

        std::unique_ptr<LogFormatter> JsonFormatter::clone() const
        {
            return std::make_unique<JsonFormatter>(pretty_print_);
        }

        // ==================== LogAppender Implementation ====================
        void LogAppender::setFormatter(std::unique_ptr<LogFormatter> formatter)
        {
            formatter_ = std::move(formatter);
        }

        void LogAppender::setLevel(LogLevel level)
        {
            level_ = level;
        }

        LogLevel LogAppender::getLevel() const
        {
            return level_;
        }

        // ==================== ConsoleAppender Implementation ====================
        ConsoleAppender::ConsoleAppender(bool use_colors)
            : use_colors_(use_colors)
        {
            if (!formatter_)
            {
                formatter_ = std::make_unique<DefaultFormatter>();
            }
        }

        bool ConsoleAppender::append(const LogEntry &entry)
        {
            if (entry.level < level_)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(console_mutex_);
            
            std::string formatted = formatter_->format(entry);
            
            if (use_colors_)
            {
                std::cout << getColorCode(entry.level) << formatted << getResetCode() << std::endl;
            }
            else
            {
                std::cout << formatted << std::endl;
            }
            
            return true;
        }

        void ConsoleAppender::flush()
        {
            std::lock_guard<std::mutex> lock(console_mutex_);
            std::cout.flush();
        }

        void ConsoleAppender::close()
        {
            flush();
        }

        std::unique_ptr<LogAppender> ConsoleAppender::clone() const
        {
            auto cloned = std::make_unique<ConsoleAppender>(use_colors_);
            if (formatter_)
            {
                cloned->setFormatter(formatter_->clone());
            }
            cloned->setLevel(level_);
            return cloned;
        }

        std::string ConsoleAppender::getColorCode(LogLevel level) const
        {
            switch (level)
            {
                case LogLevel::TRACE:   return "\033[37m";  // White
                case LogLevel::DEBUG:   return "\033[36m";  // Cyan
                case LogLevel::INFO:    return "\033[32m";  // Green
                case LogLevel::WARN:    return "\033[33m";  // Yellow
                case LogLevel::ERROR:   return "\033[31m";  // Red
                case LogLevel::FATAL:   return "\033[35m";  // Magenta
                default:                return "\033[0m";   // Reset
            }
        }

        std::string ConsoleAppender::getResetCode() const
        {
            return "\033[0m";
        }

        // ==================== FileAppender Implementation ====================
        FileAppender::FileAppender(const std::string &filename, bool append_mode)
            : filename_(filename),
              max_file_size_(0),
              max_files_(0),
              rotation_enabled_(false),
              current_file_size_(0)
        {
            if (!formatter_)
            {
                formatter_ = std::make_unique<DefaultFormatter>();
            }

            std::ios_base::openmode mode = std::ios::out;
            if (append_mode)
            {
                mode |= std::ios::app;
            }

            file_stream_.open(filename_, mode);
            
            if (file_stream_.is_open() && append_mode)
            {
                file_stream_.seekp(0, std::ios::end);
                current_file_size_ = file_stream_.tellp();
            }
        }

        FileAppender::~FileAppender()
        {
            close();
        }

        bool FileAppender::append(const LogEntry &entry)
        {
            if (entry.level < level_)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(file_mutex_);
            
            if (!file_stream_.is_open())
            {
                return false;
            }

            std::string formatted = formatter_->format(entry);
            file_stream_ << formatted << std::endl;
            
            current_file_size_ += formatted.length() + 1;

            // Check rotation
            if (rotation_enabled_ && max_file_size_ > 0 && current_file_size_ >= max_file_size_)
            {
                rotateFile();
            }

            return true;
        }

        void FileAppender::flush()
        {
            std::lock_guard<std::mutex> lock(file_mutex_);
            if (file_stream_.is_open())
            {
                file_stream_.flush();
            }
        }

        void FileAppender::close()
        {
            std::lock_guard<std::mutex> lock(file_mutex_);
            if (file_stream_.is_open())
            {
                file_stream_.close();
            }
        }

        std::unique_ptr<LogAppender> FileAppender::clone() const
        {
            auto cloned = std::make_unique<FileAppender>(filename_, true);
            if (formatter_)
            {
                cloned->setFormatter(formatter_->clone());
            }
            cloned->setLevel(level_);
            cloned->setMaxFileSize(max_file_size_);
            cloned->setMaxFiles(max_files_);
            cloned->enableRotation(rotation_enabled_);
            return cloned;
        }

        void FileAppender::setMaxFileSize(size_t max_size)
        {
            max_file_size_ = max_size;
        }

        void FileAppender::setMaxFiles(int max_files)
        {
            max_files_ = max_files;
        }

        void FileAppender::enableRotation(bool enable)
        {
            rotation_enabled_ = enable;
        }

        void FileAppender::rotateFile()
        {
            file_stream_.close();

            // Remove oldest file if exists
            if (max_files_ > 0)
            {
                std::string oldest = getRotatedFilename(max_files_);
                std::remove(oldest.c_str());

                // Rotate existing files
                for (int i = max_files_ - 1; i >= 1; i--)
                {
                    std::string old_name = getRotatedFilename(i);
                    std::string new_name = getRotatedFilename(i + 1);
                    std::rename(old_name.c_str(), new_name.c_str());
                }

                // Rename current file
                std::string backup = getRotatedFilename(1);
                std::rename(filename_.c_str(), backup.c_str());
            }

            // Open new file
            file_stream_.open(filename_, std::ios::out);
            current_file_size_ = 0;
        }

        std::string FileAppender::getRotatedFilename(int index) const
        {
            return filename_ + "." + std::to_string(index);
        }

        // ==================== RotatingFileAppender Implementation ====================
        RotatingFileAppender::RotatingFileAppender(const std::string &filename, size_t max_size, int max_files)
            : FileAppender(filename, true)
        {
            setMaxFileSize(max_size);
            setMaxFiles(max_files);
            enableRotation(true);
        }

        // ==================== SyslogAppender Implementation ====================
#ifdef __linux__
        SyslogAppender::SyslogAppender(const std::string &ident, int facility)
            : ident_(ident), facility_(facility), opened_(false)
        {
            if (!formatter_)
            {
                formatter_ = std::make_unique<DefaultFormatter>("{level} {logger}: {message}");
            }
            openlog(ident_.c_str(), LOG_PID | LOG_CONS, facility_);
            opened_ = true;
        }

        SyslogAppender::~SyslogAppender()
        {
            close();
        }

        bool SyslogAppender::append(const LogEntry &entry)
        {
            if (entry.level < level_ || !opened_)
            {
                return false;
            }

            std::string formatted = formatter_->format(entry);
            int priority = getSyslogPriority(entry.level);
            syslog(priority, "%s", formatted.c_str());
            
            return true;
        }

        void SyslogAppender::flush()
        {
            // Syslog doesn't need explicit flush
        }

        void SyslogAppender::close()
        {
            if (opened_)
            {
                closelog();
                opened_ = false;
            }
        }

        std::unique_ptr<LogAppender> SyslogAppender::clone() const
        {
            auto cloned = std::make_unique<SyslogAppender>(ident_, facility_);
            if (formatter_)
            {
                cloned->setFormatter(formatter_->clone());
            }
            cloned->setLevel(level_);
            return cloned;
        }

        int SyslogAppender::getSyslogPriority(LogLevel level) const
        {
            switch (level)
            {
                case LogLevel::TRACE:
                case LogLevel::DEBUG:   return LOG_DEBUG;
                case LogLevel::INFO:    return LOG_INFO;
                case LogLevel::WARN:    return LOG_WARNING;
                case LogLevel::ERROR:   return LOG_ERR;
                case LogLevel::FATAL:   return LOG_CRIT;
                default:                return LOG_INFO;
            }
        }
#else
        // Stub implementation for non-Linux platforms
        SyslogAppender::SyslogAppender(const std::string &ident, int facility)
            : ident_(ident), facility_(facility), opened_(false)
        {
        }

        SyslogAppender::~SyslogAppender() {}
        bool SyslogAppender::append(const LogEntry &entry) { (void)entry; return false; }
        void SyslogAppender::flush() {}
        void SyslogAppender::close() {}
        std::unique_ptr<LogAppender> SyslogAppender::clone() const 
        { 
            return std::make_unique<SyslogAppender>(ident_, facility_); 
        }
        int SyslogAppender::getSyslogPriority(LogLevel level) const { (void)level; return 0; }
#endif

        // ==================== NetworkAppender Implementation ====================
#ifdef __linux__
        NetworkAppender::NetworkAppender(const std::string &host, int port)
            : host_(host), port_(port), socket_fd_(-1)
        {
            if (!formatter_)
            {
                formatter_ = std::make_unique<JsonFormatter>(false);
            }
            initSocket();
        }

        NetworkAppender::~NetworkAppender()
        {
            close();
        }

        bool NetworkAppender::append(const LogEntry &entry)
        {
            if (entry.level < level_ || socket_fd_ < 0)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(network_mutex_);
            
            std::string formatted = formatter_->format(entry);
            
            struct sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port_);
            inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr);

            ssize_t sent = sendto(socket_fd_, formatted.c_str(), formatted.length(), 0,
                                 (struct sockaddr *)&server_addr, sizeof(server_addr));
            
            return sent > 0;
        }

        void NetworkAppender::flush()
        {
            // UDP doesn't need explicit flush
        }

        void NetworkAppender::close()
        {
            std::lock_guard<std::mutex> lock(network_mutex_);
            if (socket_fd_ >= 0)
            {
                ::close(socket_fd_);
                socket_fd_ = -1;
            }
        }

        std::unique_ptr<LogAppender> NetworkAppender::clone() const
        {
            auto cloned = std::make_unique<NetworkAppender>(host_, port_);
            if (formatter_)
            {
                cloned->setFormatter(formatter_->clone());
            }
            cloned->setLevel(level_);
            return cloned;
        }

        bool NetworkAppender::initSocket()
        {
            socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
            return socket_fd_ >= 0;
        }
#else
        // Stub implementation for non-Linux platforms
        NetworkAppender::NetworkAppender(const std::string &host, int port)
            : host_(host), port_(port), socket_fd_(-1)
        {
        }

        NetworkAppender::~NetworkAppender() {}
        bool NetworkAppender::append(const LogEntry &entry) { (void)entry; return false; }
        void NetworkAppender::flush() {}
        void NetworkAppender::close() {}
        std::unique_ptr<LogAppender> NetworkAppender::clone() const 
        { 
            return std::make_unique<NetworkAppender>(host_, port_); 
        }
        bool NetworkAppender::initSocket() { return false; }
#endif

        // ==================== CallbackAppender Implementation ====================
        CallbackAppender::CallbackAppender(LogCallback callback)
            : callback_(callback)
        {
            if (!formatter_)
            {
                formatter_ = std::make_unique<DefaultFormatter>();
            }
        }

        bool CallbackAppender::append(const LogEntry &entry)
        {
            if (entry.level < level_ || !callback_)
            {
                return false;
            }

            callback_(entry);
            return true;
        }

        void CallbackAppender::flush()
        {
            // Callback doesn't need flush
        }

        void CallbackAppender::close()
        {
            // Nothing to close
        }

        std::unique_ptr<LogAppender> CallbackAppender::clone() const
        {
            auto cloned = std::make_unique<CallbackAppender>(callback_);
            if (formatter_)
            {
                cloned->setFormatter(formatter_->clone());
            }
            cloned->setLevel(level_);
            return cloned;
        }

        // ==================== Logger Implementation ====================
        Logger::Logger(const std::string &name)
            : name_(name),
              level_(LogLevel::INFO),
              async_enabled_(false),
              async_stop_(false),
              max_queue_size_(10000)
        {
        }

        Logger::~Logger()
        {
            if (async_enabled_.load())
            {
                enableAsyncLogging(false);
            }
            close();
        }

        void Logger::trace(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::TRACE, message, file, function, line);
        }

        void Logger::debug(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::DEBUG, message, file, function, line);
        }

        void Logger::info(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::INFO, message, file, function, line);
        }

        void Logger::warn(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::WARN, message, file, function, line);
        }

        void Logger::error(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::ERROR, message, file, function, line);
        }

        void Logger::fatal(const std::string &message, const std::string &file, const std::string &function, int line)
        {
            log(LogLevel::FATAL, message, file, function, line);
        }

        void Logger::log(LogLevel level, const std::string &message, const std::string &file, const std::string &function, int line)
        {
            if (!isLevelEnabled(level))
            {
                return;
            }

            LogEntry entry(level, name_, message, file, function, line);

            if (async_enabled_.load())
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                if (async_queue_.size() < max_queue_size_)
                {
                    async_queue_.push(entry);
                    async_cv_.notify_one();
                }
                // else: drop log (queue full)
            }
            else
            {
                processEntry(entry);
            }
        }

        void Logger::setLevel(LogLevel level)
        {
            level_.store(level);
        }

        LogLevel Logger::getLevel() const
        {
            return level_.load();
        }

        bool Logger::isLevelEnabled(LogLevel level) const
        {
            return level >= level_.load();
        }

        void Logger::addAppender(std::unique_ptr<LogAppender> appender)
        {
            std::unique_lock<std::shared_mutex> lock(appenders_mutex_);
            appenders_.push_back(std::move(appender));
        }

        void Logger::removeAllAppenders()
        {
            std::unique_lock<std::shared_mutex> lock(appenders_mutex_);
            appenders_.clear();
        }

        size_t Logger::getAppenderCount() const
        {
            std::shared_lock<std::shared_mutex> lock(appenders_mutex_);
            return appenders_.size();
        }

        const std::string &Logger::getName() const
        {
            return name_;
        }

        void Logger::flush()
        {
            std::shared_lock<std::shared_mutex> lock(appenders_mutex_);
            for (auto &appender : appenders_)
            {
                appender->flush();
            }
        }

        void Logger::close()
        {
            flush();
            std::unique_lock<std::shared_mutex> lock(appenders_mutex_);
            for (auto &appender : appenders_)
            {
                appender->close();
            }
        }

        void Logger::enableAsyncLogging(bool enable)
        {
            if (enable && !async_enabled_.load())
            {
                async_stop_.store(false);
                async_enabled_.store(true);
                async_thread_ = std::thread(&Logger::asyncWorker, this);
            }
            else if (!enable && async_enabled_.load())
            {
                async_stop_.store(true);
                async_cv_.notify_all();
                if (async_thread_.joinable())
                {
                    async_thread_.join();
                }
                async_enabled_.store(false);
            }
        }

        bool Logger::isAsyncLoggingEnabled() const
        {
            return async_enabled_.load();
        }

        void Logger::setAsyncQueueSize(size_t size)
        {
            max_queue_size_ = size;
        }

        void Logger::processEntry(const LogEntry &entry)
        {
            std::shared_lock<std::shared_mutex> lock(appenders_mutex_);
            for (auto &appender : appenders_)
            {
                appender->append(entry);
            }
        }

        void Logger::asyncWorker()
        {
            while (!async_stop_.load())
            {
                std::unique_lock<std::mutex> lock(async_mutex_);
                async_cv_.wait(lock, [this]() {
                    return !async_queue_.empty() || async_stop_.load();
                });

                while (!async_queue_.empty())
                {
                    LogEntry entry = async_queue_.front();
                    async_queue_.pop();
                    lock.unlock();

                    processEntry(entry);

                    lock.lock();
                }
            }

            // Process remaining entries
            std::unique_lock<std::mutex> lock(async_mutex_);
            while (!async_queue_.empty())
            {
                LogEntry entry = async_queue_.front();
                async_queue_.pop();
                lock.unlock();

                processEntry(entry);

                lock.lock();
            }
        }

        // ==================== LoggerManager Implementation ====================
        LoggerManager::LoggerManager()
            : global_async_enabled_(false),
              global_level_(LogLevel::INFO)
        {
            // Create default formatter
            default_formatter_ = std::make_unique<DefaultFormatter>();
            
            // Create default console appender
            auto console_appender = std::make_unique<ConsoleAppender>(true);
            default_appenders_.push_back(std::move(console_appender));
        }

        LoggerManager::~LoggerManager()
        {
            shutdown();
        }

        std::shared_ptr<Logger> LoggerManager::getLogger(const std::string &name)
        {
            {
                std::shared_lock<std::shared_mutex> lock(loggers_mutex_);
                auto it = loggers_.find(name);
                if (it != loggers_.end())
                {
                    return it->second;
                }
            }

            // Logger not found, create new one
            return createLogger(name);
        }

        std::shared_ptr<Logger> LoggerManager::createLogger(const std::string &name)
        {
            std::unique_lock<std::shared_mutex> lock(loggers_mutex_);
            
            // Check again if logger was created by another thread
            auto it = loggers_.find(name);
            if (it != loggers_.end())
            {
                return it->second;
            }

            // Create new logger
            auto logger = std::make_shared<Logger>(name);
            logger->setLevel(global_level_);

            // Apply default configuration
            applyDefaultConfiguration(logger);

            loggers_[name] = logger;
            return logger;
        }

        bool LoggerManager::removeLogger(const std::string &name)
        {
            std::unique_lock<std::shared_mutex> lock(loggers_mutex_);
            auto it = loggers_.find(name);
            if (it != loggers_.end())
            {
                it->second->close();
                loggers_.erase(it);
                return true;
            }
            return false;
        }

        std::vector<std::string> LoggerManager::getAllLoggerNames() const
        {
            std::shared_lock<std::shared_mutex> lock(loggers_mutex_);
            std::vector<std::string> names;
            names.reserve(loggers_.size());
            for (const auto &pair : loggers_)
            {
                names.push_back(pair.first);
            }
            return names;
        }

        void LoggerManager::setGlobalLevel(LogLevel level)
        {
            global_level_ = level;
            std::shared_lock<std::shared_mutex> lock(loggers_mutex_);
            for (auto &pair : loggers_)
            {
                pair.second->setLevel(level);
            }
        }

        bool LoggerManager::loadConfiguration(const std::string &config_file)
        {
            // TODO: Implement configuration file loading
            // This would typically parse a JSON/YAML/XML config file
            (void)config_file; // Suppress unused parameter warning
            return false;
        }

        bool LoggerManager::loadConfigurationFromJson(const std::string &json_config)
        {
            // TODO: Implement JSON configuration parsing
            (void)json_config; // Suppress unused parameter warning
            return false;
        }

        void LoggerManager::shutdown()
        {
            std::unique_lock<std::shared_mutex> lock(loggers_mutex_);
            for (auto &pair : loggers_)
            {
                pair.second->close();
            }
            loggers_.clear();
        }

        void LoggerManager::flushAll()
        {
            std::shared_lock<std::shared_mutex> lock(loggers_mutex_);
            for (auto &pair : loggers_)
            {
                pair.second->flush();
            }
        }

        void LoggerManager::setDefaultFormatter(std::unique_ptr<LogFormatter> formatter)
        {
            default_formatter_ = std::move(formatter);
        }

        void LoggerManager::addDefaultAppender(std::unique_ptr<LogAppender> appender)
        {
            default_appenders_.push_back(std::move(appender));
        }

        void LoggerManager::enableGlobalAsyncLogging(bool enable)
        {
            global_async_enabled_.store(enable);
            std::shared_lock<std::shared_mutex> lock(loggers_mutex_);
            for (auto &pair : loggers_)
            {
                pair.second->enableAsyncLogging(enable);
            }
        }

        void LoggerManager::applyDefaultConfiguration(std::shared_ptr<Logger> logger)
        {
            // Clone and add default appenders
            for (const auto &appender : default_appenders_)
            {
                logger->addAppender(appender->clone());
            }

            // Enable async if globally enabled
            if (global_async_enabled_.load())
            {
                logger->enableAsyncLogging(true);
            }
        }

        // ==================== Helper functions ====================
        
        std::string logLevelToString(LogLevel level)
        {
            switch (level)
            {
                case LogLevel::TRACE:   return "TRACE";
                case LogLevel::DEBUG:   return "DEBUG";
                case LogLevel::INFO:    return "INFO";
                case LogLevel::WARN:    return "WARN";
                case LogLevel::ERROR:   return "ERROR";
                case LogLevel::FATAL:   return "FATAL";
                case LogLevel::OFF:     return "OFF";
                default:                return "UNKNOWN";
            }
        }

        LogLevel stringToLogLevel(const std::string &level_str)
        {
            std::string upper = level_str;
            std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            if (upper == "TRACE") return LogLevel::TRACE;
            if (upper == "DEBUG") return LogLevel::DEBUG;
            if (upper == "INFO") return LogLevel::INFO;
            if (upper == "WARN" || upper == "WARNING") return LogLevel::WARN;
            if (upper == "ERROR") return LogLevel::ERROR;
            if (upper == "FATAL" || upper == "CRITICAL") return LogLevel::FATAL;
            if (upper == "OFF") return LogLevel::OFF;

            return LogLevel::INFO; // Default
        }

        std::string getLogLevelColor(LogLevel level)
        {
            switch (level)
            {
                case LogLevel::TRACE:   return "\033[37m";  // White
                case LogLevel::DEBUG:   return "\033[36m";  // Cyan
                case LogLevel::INFO:    return "\033[32m";  // Green
                case LogLevel::WARN:    return "\033[33m";  // Yellow
                case LogLevel::ERROR:   return "\033[31m";  // Red
                case LogLevel::FATAL:   return "\033[35m";  // Magenta
                default:                return "\033[0m";   // Reset
            }
        }

    } // namespace Common
} // namespace NetworkSecurity
