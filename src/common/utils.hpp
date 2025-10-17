// src/common/utils.hpp
#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <atomic>
#include <functional>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Lớp tiện ích chung cho hệ thống
         */
        class Utils
        {
        public:
            // ==================== Time utilities ====================
            /**
             * @brief Lấy thời gian hiện tại dưới dạng string
             * @return Chuỗi thời gian định dạng "YYYY-MM-DD HH:MM:SS.mmm"
             */
            static std::string getCurrentTimestamp();

            /**
             * @brief Lấy thời gian hiện tại tính bằng milliseconds
             * @return Timestamp tính bằng milliseconds từ epoch
             */
            static uint64_t getCurrentTimestampMs();

            /**
             * @brief Lấy thời gian hiện tại tính bằng microseconds
             * @return Timestamp tính bằng microseconds từ epoch
             */
            static uint64_t getCurrentTimestampUs();

            /**
             * @brief Chuyển đổi timestamp thành string
             * @param timestamp Timestamp tính bằng milliseconds
             * @return Chuỗi thời gian đã định dạng
             */
            static std::string formatTimestamp(uint64_t timestamp);

            /**
             * @brief Chuyển đổi timestamp thành string với định dạng tùy chỉnh
             * @param timestamp Timestamp tính bằng milliseconds
             * @param format Định dạng thời gian (strftime format)
             * @return Chuỗi thời gian đã định dạng
             */
            static std::string formatTimestamp(uint64_t timestamp, const std::string &format);

            /**
             * @brief Tính khoảng thời gian giữa 2 timestamp
             * @param start_time Thời gian bắt đầu
             * @param end_time Thời gian kết thúc
             * @return Khoảng thời gian tính bằng milliseconds
             */
            static uint64_t timeDifference(uint64_t start_time, uint64_t end_time);

            // ==================== String utilities ====================
            /**
             * @brief Tách chuỗi thành vector bằng delimiter
             * @param str Chuỗi cần tách
             * @param delimiter Ký tự phân cách
             * @return Vector chứa các phần đã tách
             */
            static std::vector<std::string> split(const std::string &str, char delimiter);

            /**
             * @brief Tách chuỗi thành vector bằng delimiter string
             * @param str Chuỗi cần tách
             * @param delimiter Chuỗi phân cách
             * @return Vector chứa các phần đã tách
             */
            static std::vector<std::string> split(const std::string &str, const std::string &delimiter);

            /**
             * @brief Cắt bỏ khoảng trắng ở đầu/cuối chuỗi
             * @param str Chuỗi cần xử lý
             * @return Chuỗi đã loại bỏ khoảng trắng
             */
            static std::string trim(const std::string &str);

            /**
             * @brief Cắt bỏ ký tự chỉ định ở đầu/cuối chuỗi
             * @param str Chuỗi cần xử lý
             * @param chars Các ký tự cần loại bỏ
             * @return Chuỗi đã xử lý
             */
            static std::string trim(const std::string &str, const std::string &chars);

            /**
             * @brief Chuyển chuỗi sang chữ thường
             * @param str Chuỗi cần chuyển đổi
             * @return Chuỗi chữ thường
             */
            static std::string toLowerCase(const std::string &str);

            /**
             * @brief Chuyển chuỗi sang chữ hoa
             * @param str Chuỗi cần chuyển đổi
             * @return Chuỗi chữ hoa
             */
            static std::string toUpperCase(const std::string &str);

            /**
             * @brief Kiểm tra chuỗi có bắt đầu bằng prefix không
             * @param str Chuỗi cần kiểm tra
             * @param prefix Tiền tố
             * @return true nếu bắt đầu bằng prefix
             */
            static bool startsWith(const std::string &str, const std::string &prefix);

            /**
             * @brief Kiểm tra chuỗi có kết thúc bằng suffix không
             * @param str Chuỗi cần kiểm tra
             * @param suffix Hậu tố
             * @return true nếu kết thúc bằng suffix
             */
            static bool endsWith(const std::string &str, const std::string &suffix);

            /**
             * @brief Thay thế tất cả substring trong chuỗi
             * @param str Chuỗi gốc
             * @param from Chuỗi cần thay thế
             * @param to Chuỗi thay thế
             * @return Chuỗi đã thay thế
             */
            static std::string replaceAll(const std::string &str, const std::string &from, const std::string &to);

            /**
             * @brief Ghép vector string thành chuỗi với delimiter
             * @param strings Vector các chuỗi
             * @param delimiter Ký tự phân cách
             * @return Chuỗi đã ghép
             */
            static std::string join(const std::vector<std::string> &strings, const std::string &delimiter);

            /**
             * @brief Kiểm tra chuỗi có chứa substring không (case insensitive)
             * @param str Chuỗi cần kiểm tra
             * @param substring Chuỗi con
             * @return true nếu chứa substring
             */
            static bool containsIgnoreCase(const std::string &str, const std::string &substring);

            // ==================== Hash utilities ====================
            /**
             * @brief Tính MD5 hash của dữ liệu
             * @param data Dữ liệu cần hash
             * @return Chuỗi MD5 hex
             */
            static std::string calculateMD5(const std::string &data);

            /**
             * @brief Tính MD5 hash của dữ liệu binary
             * @param data Con trỏ tới dữ liệu
             * @param length Độ dài dữ liệu
             * @return Chuỗi MD5 hex
             */
            static std::string calculateMD5(const void *data, size_t length);

            /**
             * @brief Tính SHA256 hash của dữ liệu
             * @param data Dữ liệu cần hash
             * @return Chuỗi SHA256 hex
             */
            static std::string calculateSHA256(const std::string &data);

            /**
             * @brief Tính SHA256 hash của dữ liệu binary
             * @param data Con trỏ tới dữ liệu
             * @param length Độ dài dữ liệu
             * @return Chuỗi SHA256 hex
             */
            static std::string calculateSHA256(const void *data, size_t length);

            /**
             * @brief Tính CRC32 checksum
             * @param data Con trỏ tới dữ liệu
             * @param length Độ dài dữ liệu
             * @return Giá trị CRC32
             */
            static uint32_t calculateCRC32(const void *data, size_t length);

            /**
             * @brief Tính hash đơn giản cho string (FNV-1a)
             * @param str Chuỗi cần hash
             * @return Giá trị hash
             */
            static uint64_t hashString(const std::string &str);

            // ==================== File utilities ====================
            /**
             * @brief Kiểm tra file có tồn tại không
             * @param filepath Đường dẫn file
             * @return true nếu file tồn tại
             */
            static bool fileExists(const std::string &filepath);

            /**
             * @brief Kiểm tra thư mục có tồn tại không
             * @param dirpath Đường dẫn thư mục
             * @return true nếu thư mục tồn tại
             */
            static bool directoryExists(const std::string &dirpath);

            /**
             * @brief Tạo thư mục (bao gồm thư mục cha)
             * @param dirpath Đường dẫn thư mục
             * @return true nếu tạo thành công
             */
            static bool createDirectory(const std::string &dirpath);

            /**
             * @brief Đọc toàn bộ file thành string
             * @param filepath Đường dẫn file
             * @return Nội dung file hoặc chuỗi rỗng nếu lỗi
             */
            static std::string readFileToString(const std::string &filepath);

            /**
             * @brief Đọc file thành vector bytes
             * @param filepath Đường dẫn file
             * @return Vector bytes hoặc rỗng nếu lỗi
             */
            static std::vector<uint8_t> readFileToBytes(const std::string &filepath);

            /**
             * @brief Ghi string vào file
             * @param filepath Đường dẫn file
             * @param content Nội dung cần ghi
             * @param append true để append, false để ghi đè
             * @return true nếu ghi thành công
             */
            static bool writeStringToFile(const std::string &filepath, const std::string &content, bool append = false);

            /**
             * @brief Ghi bytes vào file
             * @param filepath Đường dẫn file
             * @param data Vector bytes
             * @param append true để append, false để ghi đè
             * @return true nếu ghi thành công
             */
            static bool writeBytesToFile(const std::string &filepath, const std::vector<uint8_t> &data, bool append = false);

            /**
             * @brief Lấy kích thước file
             * @param filepath Đường dẫn file
             * @return Kích thước file (bytes) hoặc 0 nếu lỗi
             */
            static size_t getFileSize(const std::string &filepath);

            /**
             * @brief Lấy thời gian sửa đổi file cuối cùng
             * @param filepath Đường dẫn file
             * @return Timestamp sửa đổi cuối cùng
             */
            static uint64_t getFileModificationTime(const std::string &filepath);

            /**
             * @brief Lấy tên file từ đường dẫn
             * @param filepath Đường dẫn đầy đủ
             * @return Tên file
             */
            static std::string getFileName(const std::string &filepath);

            /**
             * @brief Lấy thư mục cha từ đường dẫn
             * @param filepath Đường dẫn đầy đủ
             * @return Đường dẫn thư mục cha
             */
            static std::string getDirectoryName(const std::string &filepath);

            /**
             * @brief Lấy extension của file
             * @param filepath Đường dẫn file
             * @return Extension (bao gồm dấu chấm)
             */
            static std::string getFileExtension(const std::string &filepath);

            // ==================== Memory utilities ====================
            /**
             * @brief Định dạng kích thước bytes thành string dễ đọc
             * @param bytes Số bytes
             * @return Chuỗi định dạng (VD: "1.5 MB")
             */
            static std::string formatBytes(size_t bytes);

            /**
             * @brief Xuất hex dump của dữ liệu
             * @param data Con trỏ tới dữ liệu
             * @param length Độ dài dữ liệu
             * @param os Output stream
             * @param bytes_per_line Số bytes mỗi dòng
             */
            static void hexDump(const void *data, size_t length, std::ostream &os, size_t bytes_per_line = 16);

            /**
             * @brief Chuyển đổi bytes thành hex string
             * @param data Con trỏ tới dữ liệu
             * @param length Độ dài dữ liệu
             * @return Chuỗi hex
             */
            static std::string bytesToHex(const void *data, size_t length);

            /**
             * @brief Chuyển đổi hex string thành bytes
             * @param hex_str Chuỗi hex
             * @return Vector bytes
             */
            static std::vector<uint8_t> hexToBytes(const std::string &hex_str);

            /**
             * @brief So sánh memory an toàn (constant time)
             * @param ptr1 Con trỏ dữ liệu 1
             * @param ptr2 Con trỏ dữ liệu 2
             * @param length Độ dài so sánh
             * @return true nếu giống nhau
             */
            static bool secureMemoryCompare(const void *ptr1, const void *ptr2, size_t length);

            // ==================== System utilities ====================
            /**
             * @brief Lấy số lượng CPU cores
             * @return Số CPU cores
             */
            static int getCPUCount();

            /**
             * @brief Lấy lượng memory đang sử dụng của process hiện tại
             * @return Memory usage (bytes)
             */
            static size_t getMemoryUsage();

            /**
             * @brief Lấy tổng memory của hệ thống
             * @return Tổng memory (bytes)
             */
            static size_t getTotalSystemMemory();

            /**
             * @brief Lấy memory khả dụng của hệ thống
             * @return Memory khả dụng (bytes)
             */
            static size_t getAvailableSystemMemory();

            /**
             * @brief Lấy hostname của hệ thống
             * @return Hostname
             */
            static std::string getHostname();

            /**
             * @brief Lấy tên process hiện tại
             * @return Tên process
             */
            static std::string getProcessName();

            /**
             * @brief Lấy PID của process hiện tại
             * @return Process ID
             */
            static int getProcessId();

            /**
             * @brief Lấy user ID hiện tại
             * @return User ID
             */
            static int getUserId();

            /**
             * @brief Lấy thông tin CPU usage
             * @return CPU usage percentage (0-100)
             */
            static double getCPUUsage();

            // ==================== Random utilities ====================
            /**
             * @brief Tạo số ngẫu nhiên trong khoảng
             * @param min Giá trị nhỏ nhất
             * @param max Giá trị lớn nhất
             * @return Số ngẫu nhiên
             */
            static int randomInt(int min, int max);

            /**
             * @brief Tạo số thực ngẫu nhiên trong khoảng
             * @param min Giá trị nhỏ nhất
             * @param max Giá trị lớn nhất
             * @return Số thực ngẫu nhiên
             */
            static double randomDouble(double min, double max);

            /**
             * @brief Tạo chuỗi ngẫu nhiên
             * @param length Độ dài chuỗi
             * @param charset Bộ ký tự sử dụng
             * @return Chuỗi ngẫu nhiên
             */
            static std::string randomString(size_t length, const std::string &charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");

            /**
             * @brief Tạo UUID v4
             * @return UUID string
             */
            static std::string generateUUID();

            // ==================== Validation utilities ====================
            /**
             * @brief Kiểm tra chuỗi có phải số không
             * @param str Chuỗi cần kiểm tra
             * @return true nếu là số
             */
            static bool isNumeric(const std::string &str);

            /**
             * @brief Kiểm tra chuỗi có phải số nguyên không
             * @param str Chuỗi cần kiểm tra
             * @return true nếu là số nguyên
             */
            static bool isInteger(const std::string &str);

            /**
             * @brief Kiểm tra chuỗi có phải số thực không
             * @param str Chuỗi cần kiểm tra
             * @return true nếu là số thực
             */
            static bool isFloat(const std::string &str);

            /**
             * @brief Kiểm tra email hợp lệ
             * @param email Email cần kiểm tra
             * @return true nếu email hợp lệ
             */
            static bool isValidEmail(const std::string &email);

            // ==================== Conversion utilities ====================
            /**
             * @brief Chuyển đổi string thành int an toàn
             * @param str Chuỗi cần chuyển đổi
             * @param default_value Giá trị mặc định nếu lỗi
             * @return Giá trị int
             */
            static int stringToInt(const std::string &str, int default_value = 0);

            /**
             * @brief Chuyển đổi string thành double an toàn
             * @param str Chuỗi cần chuyển đổi
             * @param default_value Giá trị mặc định nếu lỗi
             * @return Giá trị double
             */
            static double stringToDouble(const std::string &str, double default_value = 0.0);

            /**
             * @brief Chuyển đổi string thành bool
             * @param str Chuỗi cần chuyển đổi ("true", "false", "1", "0", "yes", "no")
             * @param default_value Giá trị mặc định nếu lỗi
             * @return Giá trị bool
             */
            static bool stringToBool(const std::string &str, bool default_value = false);

        private:
            Utils() = default;
            ~Utils() = default;
            Utils(const Utils &) = delete;
            Utils &operator=(const Utils &) = delete;
        };

        /**
         * @brief RAII Timer cho đo hiệu suất
         */
        class Timer
        {
        public:
            Timer();
            explicit Timer(const std::string &name);
            ~Timer();

            /**
             * @brief Bắt đầu đo thời gian
             */
            void start();

            /**
             * @brief Dừng đo thời gian
             */
            void stop();

            /**
             * @brief Lấy thời gian đã trôi qua (milliseconds)
             * @return Thời gian tính bằng milliseconds
             */
            double getElapsedMs() const;

            /**
             * @brief Lấy thời gian đã trôi qua (microseconds)
             * @return Thời gian tính bằng microseconds
             */
            double getElapsedUs() const;

            /**
             * @brief Reset timer
             */
            void reset();

            /**
             * @brief Lấy tên timer
             * @return Tên timer
             */
            const std::string &getName() const;

        private:
            std::string name_;
            std::chrono::high_resolution_clock::time_point start_time_;
            std::chrono::high_resolution_clock::time_point end_time_;
            bool is_running_;
            bool auto_print_;
        };

        /**
         * @brief Thread-safe Singleton template
         */
        template <typename T>
        class Singleton
        {
        public:
            /**
             * @brief Lấy instance duy nhất
             * @return Reference tới instance
             */
            static T &getInstance()
            {
                static T instance;
                return instance;
            }

            /**
             * @brief Kiểm tra instance đã được tạo chưa
             * @return true nếu đã tạo
             */
            static bool isInstantiated()
            {
                static std::atomic<bool> instantiated{false};
                if (!instantiated.load())
                {
                    getInstance(); // Trigger creation
                    instantiated.store(true);
                }
                return instantiated.load();
            }

        protected:
            Singleton() = default;
            virtual ~Singleton() = default;

        public:
            Singleton(const Singleton &) = delete;
            Singleton &operator=(const Singleton &) = delete;
            Singleton(Singleton &&) = delete;
            Singleton &operator=(Singleton &&) = delete;
        };

        /**
         * @brief Scope guard để thực hiện cleanup tự động
         */
        class ScopeGuard
        {
        public:
            explicit ScopeGuard(std::function<void()> cleanup_func);
            ~ScopeGuard();

            /**
             * @brief Hủy bỏ cleanup (sẽ không thực hiện khi destructor được gọi)
             */
            void dismiss();

        private:
            std::function<void()> cleanup_func_;
            bool dismissed_;
        };

// Macro tiện ích cho ScopeGuard
#define SCOPE_GUARD(func) ScopeGuard _sg([&]() { func; })

    } // namespace Common
} // namespace NetworkSecurity

#endif // UTILS_HPP
