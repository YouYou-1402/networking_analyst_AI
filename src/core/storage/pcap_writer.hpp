// src/core/storage/pcap_writer.hpp
#ifndef PCAP_WRITER_HPP
#define PCAP_WRITER_HPP

#include "../../common/packet_parser.hpp"
#include <string>
#include <atomic>
#include <memory>
#include <pcap/pcap.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Storage
        {
            /**
             * @brief PCAP file writer - Ghi packets vào file PCAP
             */
            class PcapWriter
            {
            public:
                /**
                 * @brief Constructor
                 * @param output_dir Thư mục lưu file PCAP
                 */
                explicit PcapWriter(const std::string &output_dir);

                /**
                 * @brief Destructor
                 */
                ~PcapWriter();

                /**
                 * @brief Mở file PCAP mới
                 * @param filename Tên file
                 * @param datalink_type Loại datalink (DLT_EN10MB, DLT_LINUX_SLL, ...)
                 * @return true nếu thành công
                 */
                bool open(const std::string &filename, int datalink_type = DLT_EN10MB);

                /**
                 * @brief Ghi packet vào file PCAP
                 * @param packet Packet đã parse
                 * @return true nếu thành công
                 */
                bool writePacket(const Common::ParsedPacket &packet);

                /**
                 * @brief Ghi raw packet vào file PCAP
                 * @param data Raw packet data
                 * @param length Packet length
                 * @param timestamp_us Timestamp (microseconds)
                 * @return true nếu thành công
                 */
                bool writeRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us);

                /**
                 * @brief Đóng file PCAP hiện tại
                 */
                void close();

                /**
                 * @brief Flush dữ liệu buffer ra disk
                 */
                void flush();

                /**
                 * @brief Kiểm tra file có đang mở không
                 */
                bool isOpen() const { return m_pcap_dumper != nullptr; }

                /**
                 * @brief Lấy tên file hiện tại
                 */
                std::string getCurrentFile() const { return m_current_file; }

                /**
                 * @brief Lấy kích thước file hiện tại (bytes)
                 */
                size_t getCurrentSize() const { return m_current_size.load(); }

                /**
                 * @brief Lấy số lượng packets đã ghi
                 */
                uint64_t getPacketCount() const { return m_packet_count.load(); }

            private:
                std::string m_output_dir;                   // Thư mục output
                std::string m_current_file;                 // File hiện tại
                std::atomic<size_t> m_current_size{0};      // Kích thước file
                std::atomic<uint64_t> m_packet_count{0};    // Số packets đã ghi

                pcap_t *m_pcap_handle{nullptr};             // PCAP handle
                pcap_dumper_t *m_pcap_dumper{nullptr};      // PCAP dumper

                // Flush counter
                std::atomic<uint64_t> m_writes_since_flush{0};
                static constexpr uint64_t FLUSH_INTERVAL = 100;
            };

        } // namespace Storage
    }     // namespace Core
} // namespace NetworkSecurity

#endif // PCAP_WRITER_HPP
