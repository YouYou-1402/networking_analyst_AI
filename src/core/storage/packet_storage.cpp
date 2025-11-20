// src/core/storage/packet_storage.cpp
#include "packet_storage.hpp"
#include "../../common/utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Storage
        {
            PacketStorage::PacketStorage(const StorageConfig &config)
                : m_config(config)
            {
                m_writer = std::make_unique<PcapWriter>(m_config.output_dir);
            }

            PacketStorage::~PacketStorage()
            {
                close();
            }

            bool PacketStorage::initialize()
            {
                std::cout << "[PacketStorage] Initializing..." << std::endl;
                std::cout << "[PacketStorage] Output directory: " << m_config.output_dir << std::endl;

                // Tạo thư mục nếu chưa tồn tại
                struct stat st;
                if (stat(m_config.output_dir.c_str(), &st) != 0)
                {
                    if (mkdir(m_config.output_dir.c_str(), 0755) != 0)
                    {
                        std::cerr << "[PacketStorage] Failed to create output directory" << std::endl;
                        return false;
                    }
                }

                // Tạo file đầu tiên
                if (!createNewFile())
                {
                    return false;
                }

                // Khởi tạo thống kê
                m_stats.start_time_us = Common::Utils::getCurrentTimestampUs();

                std::cout << "[PacketStorage] Initialized successfully" << std::endl;
                return true;
            }

            bool PacketStorage::savePacket(const Common::ParsedPacket &packet)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                // Kiểm tra rotation
                if (m_config.enable_rotation && needRotation())
                {
                    if (!createNewFile())
                    {
                        m_stats.write_errors++;
                        return false;
                    }
                }

                // Ghi packet
                if (!m_writer->writePacket(packet))
                {
                    m_stats.write_errors++;
                    return false;
                }

                // Cập nhật thống kê
                m_stats.total_packets++;
                m_stats.total_bytes += packet.packet_size;
                m_stats.last_write_time_us = packet.timestamp;

                return true;
            }

            bool PacketStorage::saveRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                // Kiểm tra rotation
                if (m_config.enable_rotation && needRotation())
                {
                    if (!createNewFile())
                    {
                        m_stats.write_errors++;
                        return false;
                    }
                }

                // Ghi packet
                if (!m_writer->writeRawPacket(data, length, timestamp_us))
                {
                    m_stats.write_errors++;
                    return false;
                }

                // Cập nhật thống kê
                m_stats.total_packets++;
                m_stats.total_bytes += length;
                m_stats.last_write_time_us = timestamp_us;

                return true;
            }

            void PacketStorage::flush()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_writer->flush();
            }

            void PacketStorage::close()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_writer->close();
                std::cout << "[PacketStorage] Closed" << std::endl;
            }

            bool PacketStorage::createNewFile()
            {
                // Đóng file cũ
                if (m_writer->isOpen())
                {
                    m_writer->close();
                }

                // Tạo tên file mới
                std::string filename = generateFilename();

                // Mở file mới
                if (!m_writer->open(filename, m_config.datalink_type))
                {
                    std::cerr << "[PacketStorage] Failed to create new file" << std::endl;
                    return false;
                }

                // Cập nhật thống kê
                m_stats.files_created++;
                m_stats.current_file = m_writer->getCurrentFile();
                m_file_start_time_us = Common::Utils::getCurrentTimestampUs();

                std::cout << "[PacketStorage] Created new file: " << filename << std::endl;
                return true;
            }

            bool PacketStorage::needRotation() const
            {
                if (!m_writer->isOpen())
                {
                    return false;
                }

                // Kiểm tra kích thước file
                size_t current_size_mb = m_writer->getCurrentSize() / (1024 * 1024);
                if (current_size_mb >= m_config.max_file_size_mb)
                {
                    std::cout << "[PacketStorage] Rotation needed: file size limit reached ("
                              << current_size_mb << " MB)" << std::endl;
                    return true;
                }

                // Kiểm tra thời gian
                uint64_t current_time = Common::Utils::getCurrentTimestampUs();
                uint64_t elapsed_sec = (current_time - m_file_start_time_us) / 1000000;
                if (elapsed_sec >= m_config.max_file_duration_sec)
                {
                    std::cout << "[PacketStorage] Rotation needed: time limit reached ("
                              << elapsed_sec << " seconds)" << std::endl;
                    return true;
                }

                return false;
            }

            std::string PacketStorage::generateFilename() const
            {
                // Tạo tên file: prefix_YYYYMMDD_HHMMSS.pcap
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                auto tm = *std::localtime(&time_t);

                std::stringstream ss;
                ss << m_config.file_prefix << "_"
                   << std::put_time(&tm, "%Y%m%d_%H%M%S")
                   << ".pcap";

                return ss.str();
            }

        } // namespace Storage
    }     // namespace Core
} // namespace NetworkSecurity
