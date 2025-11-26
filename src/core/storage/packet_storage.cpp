// src/core/storage/packet_storage.cpp
#include "packet_storage.hpp"
#include "utils.hpp"
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
                // Khởi tạo logger
                m_logger = Common::LoggerManager::getInstance().getLogger("PacketStorage");
                
                m_logger->info("Creating PacketStorage instance");
                m_logger->debug("Configuration: output_dir=" + config.output_dir + 
                               ", enable_rotation=" + std::to_string(config.enable_rotation) +
                               ", max_file_size_mb=" + std::to_string(config.max_file_size_mb) +
                               ", max_file_duration_sec=" + std::to_string(config.max_file_duration_sec) +
                               ", file_prefix=" + config.file_prefix);

                m_writer = std::make_unique<PcapWriter>(m_config.output_dir);
            }

            PacketStorage::~PacketStorage()
            {
                m_logger->info("Destroying PacketStorage instance");
                close();
            }

            bool PacketStorage::initialize()
            {
                m_logger->info("Initializing PacketStorage");
                m_logger->info("Output directory: " + m_config.output_dir);

                // Tạo thư mục nếu chưa tồn tại
                struct stat st;
                if (stat(m_config.output_dir.c_str(), &st) != 0)
                {
                    m_logger->debug("Output directory does not exist, creating...");
                    if (mkdir(m_config.output_dir.c_str(), 0755) != 0)
                    {
                        m_logger->error("Failed to create output directory: " + m_config.output_dir);
                        return false;
                    }
                    m_logger->info("Output directory created successfully");
                }
                else
                {
                    m_logger->debug("Output directory already exists");
                }

                // Tạo file đầu tiên
                m_logger->debug("Creating initial capture file");
                if (!createNewFile())
                {
                    m_logger->error("Failed to create initial capture file");
                    return false;
                }

                // Khởi tạo thống kê
                m_stats.start_time_us = Common::Utils::getCurrentTimestampUs();
                m_logger->debug("Statistics initialized, start_time=" + 
                               std::to_string(m_stats.start_time_us.load()) + "us");

                m_logger->info("PacketStorage initialized successfully");
                return true;
            }

            bool PacketStorage::savePacket(const Common::ParsedPacket &packet)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_logger->trace("Saving packet: size=" + std::to_string(packet.packet_size) + 
                               " bytes, timestamp=" + std::to_string(packet.timestamp) + "us");

                // Kiểm tra rotation
                if (m_config.enable_rotation && needRotation())
                {
                    m_logger->info("File rotation triggered");
                    if (!createNewFile())
                    {
                        m_stats.write_errors++;
                        m_logger->error("Failed to create new file during rotation");
                        return false;
                    }
                }

                // Ghi packet
                if (!m_writer->writePacket(packet))
                {
                    m_stats.write_errors++;
                    m_logger->error("Failed to write packet to file");
                    return false;
                }

                // Cập nhật thống kê
                m_stats.total_packets++;
                m_stats.total_bytes += packet.packet_size;
                m_stats.last_write_time_us = packet.timestamp;

                // Log định kỳ (mỗi 10000 packets)
                if (m_stats.total_packets % 10000 == 0)
                {
                    auto stats_snap = m_stats.snapshot();
                    m_logger->info("Statistics: packets=" + std::to_string(stats_snap.total_packets) +
                                  ", bytes=" + std::to_string(stats_snap.total_bytes) +
                                  ", files=" + std::to_string(stats_snap.files_created) +
                                  ", errors=" + std::to_string(stats_snap.write_errors) +
                                  ", rate=" + std::to_string(stats_snap.getWriteRate()) + " pps" +
                                  ", throughput=" + std::to_string(stats_snap.getThroughputMbps()) + " Mbps");
                }

                return true;
            }

            bool PacketStorage::saveRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us)
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                m_logger->trace("Saving raw packet: size=" + std::to_string(length) + 
                               " bytes, timestamp=" + std::to_string(timestamp_us) + "us");

                // Kiểm tra rotation
                if (m_config.enable_rotation && needRotation())
                {
                    m_logger->info("File rotation triggered");
                    if (!createNewFile())
                    {
                        m_stats.write_errors++;
                        m_logger->error("Failed to create new file during rotation");
                        return false;
                    }
                }

                // Ghi packet
                if (!m_writer->writeRawPacket(data, length, timestamp_us))
                {
                    m_stats.write_errors++;
                    m_logger->error("Failed to write raw packet to file");
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
                m_logger->debug("Flushing storage");
                m_writer->flush();
            }

            void PacketStorage::close()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                auto stats_snap = m_stats.snapshot();
                m_logger->info("Closing PacketStorage - Final statistics:");
                m_logger->info("  Total packets: " + std::to_string(stats_snap.total_packets));
                m_logger->info("  Total bytes: " + std::to_string(stats_snap.total_bytes));
                m_logger->info("  Files created: " + std::to_string(stats_snap.files_created));
                m_logger->info("  Write errors: " + std::to_string(stats_snap.write_errors));
                m_logger->info("  Average write rate: " + std::to_string(stats_snap.getWriteRate()) + " pps");
                m_logger->info("  Average throughput: " + std::to_string(stats_snap.getThroughputMbps()) + " Mbps");
                
                m_writer->close();
                m_logger->info("PacketStorage closed");
            }

            bool PacketStorage::createNewFile()
            {
                // Đóng file cũ
                if (m_writer->isOpen())
                {
                    m_logger->debug("Closing current file before creating new one");
                    m_writer->close();
                }

                // Tạo tên file mới
                std::string filename = generateFilename();
                m_logger->info("Creating new capture file: " + filename);

                // Mở file mới
                if (!m_writer->open(filename, m_config.datalink_type))
                {
                    m_logger->error("Failed to create new capture file: " + filename);
                    return false;
                }

                // Cập nhật thống kê
                m_stats.files_created++;
                m_stats.current_file = m_writer->getCurrentFile();
                m_file_start_time_us = Common::Utils::getCurrentTimestampUs();

                m_logger->info("New capture file created successfully: " + filename);
                m_logger->debug("File start time: " + std::to_string(m_file_start_time_us) + "us");
                m_logger->debug("Total files created: " + std::to_string(m_stats.files_created.load()));

                return true;
            }

            bool PacketStorage::needRotation() const
            {
                if (!m_writer->isOpen())
                {
                    m_logger->trace("Rotation check: file not open");
                    return false;
                }

                // Kiểm tra kích thước file
                size_t current_size_mb = m_writer->getCurrentSize() / (1024 * 1024);
                if (current_size_mb >= m_config.max_file_size_mb)
                {
                    m_logger->info("Rotation needed: file size limit reached (" +
                                  std::to_string(current_size_mb) + " MB >= " +
                                  std::to_string(m_config.max_file_size_mb) + " MB)");
                    return true;
                }

                // Kiểm tra thời gian
                uint64_t current_time = Common::Utils::getCurrentTimestampUs();
                uint64_t elapsed_sec = (current_time - m_file_start_time_us) / 1000000;
                if (elapsed_sec >= m_config.max_file_duration_sec)
                {
                    m_logger->info("Rotation needed: time limit reached (" +
                                  std::to_string(elapsed_sec) + " seconds >= " +
                                  std::to_string(m_config.max_file_duration_sec) + " seconds)");
                    return true;
                }

                m_logger->trace("Rotation check: not needed (size=" + 
                               std::to_string(current_size_mb) + "MB, elapsed=" +
                               std::to_string(elapsed_sec) + "s)");
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

                std::string filename = ss.str();
                m_logger->debug("Generated filename: " + filename);
                
                return filename;
            }

        } // namespace Storage
    }     // namespace Core
} // namespace NetworkSecurity
