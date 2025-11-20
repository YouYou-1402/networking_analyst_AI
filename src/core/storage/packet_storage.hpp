// src/core/storage/packet_storage.hpp
#ifndef PACKET_STORAGE_HPP
#define PACKET_STORAGE_HPP

#include "pcap_writer.hpp"
#include "../../common/packet_parser.hpp"
#include <string>
#include <memory>
#include <atomic>
#include <mutex>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Storage
        {
            /**
             * @brief Cấu hình cho Storage
             */
            struct StorageConfig
            {
                std::string output_dir = "./captured_data";     // Thư mục lưu file
                bool enable_rotation = true;                    // Bật rotation
                size_t max_file_size_mb = 100;                  // Kích thước tối đa (MB)
                size_t max_file_duration_sec = 3600;            // Thời gian tối đa (giây)
                int datalink_type = DLT_EN10MB;                 // Loại datalink
                std::string file_prefix = "capture";            // Prefix cho tên file

                StorageConfig() = default;
            };

            /**
             * @brief Thống kê Storage (non-atomic version for returning)
             */
            struct StorageStatsSnapshot
            {
                uint64_t total_packets{0};         // Tổng số packets
                uint64_t total_bytes{0};           // Tổng số bytes
                uint64_t files_created{0};         // Số file đã tạo
                uint64_t write_errors{0};          // Số lỗi ghi
                std::string current_file;          // File hiện tại
                uint64_t start_time_us{0};         // Thời gian bắt đầu
                uint64_t last_write_time_us{0};    // Lần ghi cuối

                double getWriteRate() const
                {
                    uint64_t elapsed = last_write_time_us - start_time_us;
                    if (elapsed == 0)
                        return 0.0;
                    return (double)total_packets * 1000000.0 / elapsed;
                }

                double getThroughputMbps() const
                {
                    uint64_t elapsed = last_write_time_us - start_time_us;
                    if (elapsed == 0)
                        return 0.0;
                    return (double)total_bytes * 8.0 / elapsed;
                }
            };

            /**
             * @brief Thống kê Storage (internal - with atomics)
             */
            struct StorageStats
            {
                std::atomic<uint64_t> total_packets{0};         // Tổng số packets
                std::atomic<uint64_t> total_bytes{0};           // Tổng số bytes
                std::atomic<uint64_t> files_created{0};         // Số file đã tạo
                std::atomic<uint64_t> write_errors{0};          // Số lỗi ghi
                std::string current_file;                       // File hiện tại
                std::atomic<uint64_t> start_time_us{0};         // Thời gian bắt đầu
                std::atomic<uint64_t> last_write_time_us{0};    // Lần ghi cuối

                void reset()
                {
                    total_packets = 0;
                    total_bytes = 0;
                    files_created = 0;
                    write_errors = 0;
                    current_file.clear();
                    start_time_us = 0;
                    last_write_time_us = 0;
                }

                // Tạo snapshot để return
                StorageStatsSnapshot snapshot() const
                {
                    StorageStatsSnapshot snap;
                    snap.total_packets = total_packets.load();
                    snap.total_bytes = total_bytes.load();
                    snap.files_created = files_created.load();
                    snap.write_errors = write_errors.load();
                    snap.current_file = current_file;
                    snap.start_time_us = start_time_us.load();
                    snap.last_write_time_us = last_write_time_us.load();
                    return snap;
                }
            };

            /**
             * @brief Packet Storage Manager
             * Quản lý việc lưu trữ packets vào file PCAP
             */
            class PacketStorage
            {
            public:
                /**
                 * @brief Constructor
                 * @param config Cấu hình storage
                 */
                explicit PacketStorage(const StorageConfig &config = StorageConfig());

                /**
                 * @brief Destructor
                 */
                ~PacketStorage();

                /**
                 * @brief Khởi tạo storage
                 * @return true nếu thành công
                 */
                bool initialize();

                /**
                 * @brief Lưu packet
                 * @param packet Packet đã parse
                 * @return true nếu thành công
                 */
                bool savePacket(const Common::ParsedPacket &packet);

                /**
                 * @brief Lưu raw packet
                 * @param data Raw packet data
                 * @param length Packet length
                 * @param timestamp_us Timestamp (microseconds)
                 * @return true nếu thành công
                 */
                bool saveRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us);

                /**
                 * @brief Đóng storage
                 */
                void close();

                /**
                 * @brief Flush dữ liệu
                 */
                void flush();

                /**
                 * @brief Lấy thống kê (snapshot)
                 */
                StorageStatsSnapshot getStats() const 
                { 
                    return m_stats.snapshot(); 
                }

                /**
                 * @brief Reset thống kê
                 */
                void resetStats() { m_stats.reset(); }

            private:
                StorageConfig m_config;
                StorageStats m_stats;
                std::unique_ptr<PcapWriter> m_writer;
                std::mutex m_mutex;

                uint64_t m_file_start_time_us{0};

                /**
                 * @brief Tạo file mới
                 */
                bool createNewFile();

                /**
                 * @brief Kiểm tra có cần rotation không
                 */
                bool needRotation() const;

                /**
                 * @brief Tạo tên file
                 */
                std::string generateFilename() const;
            };

        } // namespace Storage
    }     // namespace Core
} // namespace NetworkSecurity

#endif // PACKET_STORAGE_HPP
