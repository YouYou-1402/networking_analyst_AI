// src/core/storage/pcap_writer.cpp
#include "pcap_writer.hpp"
#include "utils.hpp"
#include <sys/stat.h>
#include <cstring>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Storage
        {
            PcapWriter::PcapWriter(const std::string &output_dir)
                : m_output_dir(output_dir)
            {
                // Khởi tạo logger
                m_logger = Common::LoggerManager::getInstance().getLogger("PcapWriter");
                
                m_logger->info("Initializing PcapWriter with output directory: " + output_dir);

                // Tạo thư mục nếu chưa tồn tại
                struct stat st;
                if (stat(m_output_dir.c_str(), &st) != 0)
                {
                    if (mkdir(m_output_dir.c_str(), 0755) == 0)
                    {
                        m_logger->info("Created output directory: " + m_output_dir);
                    }
                    else
                    {
                        m_logger->error("Failed to create output directory: " + m_output_dir);
                    }
                }
                else
                {
                    m_logger->debug("Output directory already exists: " + m_output_dir);
                }
            }

            PcapWriter::~PcapWriter()
            {
                m_logger->debug("Destroying PcapWriter");
                close();
            }

            bool PcapWriter::open(const std::string &filename, int datalink_type)
            {
                // Đóng file cũ nếu đang mở
                if (m_pcap_dumper)
                {
                    m_logger->debug("Closing existing file before opening new one");
                    close();
                }

                // Tạo đường dẫn đầy đủ
                m_current_file = m_output_dir + "/" + filename;

                m_logger->info("Opening PCAP file: " + m_current_file + 
                              " (datalink_type=" + std::to_string(datalink_type) + ")");

                // Tạo pcap handle cho việc ghi
                m_pcap_handle = pcap_open_dead(datalink_type, 65535);
                if (!m_pcap_handle)
                {
                    m_logger->error("Failed to create PCAP handle for file: " + m_current_file);
                    return false;
                }

                m_logger->debug("PCAP handle created successfully");

                // Mở file để ghi
                m_pcap_dumper = pcap_dump_open(m_pcap_handle, m_current_file.c_str());
                if (!m_pcap_dumper)
                {
                    std::string error_msg = pcap_geterr(m_pcap_handle);
                    m_logger->error("Failed to open PCAP dump file: " + m_current_file + 
                                   " - Error: " + error_msg);
                    pcap_close(m_pcap_handle);
                    m_pcap_handle = nullptr;
                    return false;
                }

                // Reset counters
                m_current_size = 0;
                m_packet_count = 0;
                m_writes_since_flush = 0;

                m_logger->info("PCAP file opened successfully: " + m_current_file);
                return true;
            }

            bool PcapWriter::writePacket(const Common::ParsedPacket &packet)
            {
                if (!m_pcap_dumper)
                {
                    m_logger->error("Cannot write packet: PCAP dumper not initialized");
                    return false;
                }

                if (!packet.raw_data || packet.captured_length == 0)
                {
                    m_logger->warn("Invalid packet data: raw_data=" + 
                                  std::to_string(reinterpret_cast<uintptr_t>(packet.raw_data)) + 
                                  ", captured_length=" + std::to_string(packet.captured_length));
                    return false;
                }

                m_logger->trace("Writing packet: size=" + std::to_string(packet.captured_length) + 
                               " bytes, timestamp=" + std::to_string(packet.timestamp) + "us");

                bool success = writeRawPacket(packet.raw_data, packet.captured_length, packet.timestamp);
                
                if (!success)
                {
                    m_logger->error("Failed to write packet to file: " + m_current_file);
                }
                
                return success;
            }

            bool PcapWriter::writeRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us)
            {
                if (!m_pcap_dumper)
                {
                    m_logger->error("Cannot write raw packet: PCAP dumper not initialized");
                    return false;
                }

                if (!data || length == 0)
                {
                    m_logger->warn("Invalid raw packet data: data=" + 
                                  std::to_string(reinterpret_cast<uintptr_t>(data)) + 
                                  ", length=" + std::to_string(length));
                    return false;
                }

                // Chuyển đổi timestamp sang định dạng pcap
                struct pcap_pkthdr header;
                header.ts.tv_sec = timestamp_us / 1000000;
                header.ts.tv_usec = timestamp_us % 1000000;
                header.caplen = length;
                header.len = length;

                // Ghi packet
                pcap_dump(reinterpret_cast<u_char *>(m_pcap_dumper), &header, data);

                // Cập nhật thống kê
                m_packet_count++;
                m_current_size += length + sizeof(struct pcap_pkthdr);
                m_writes_since_flush++;

                // Log định kỳ (mỗi 1000 packets)
                if (m_packet_count % 1000 == 0)
                {
                    m_logger->debug("Written " + std::to_string(m_packet_count.load()) + 
                                   " packets (" + std::to_string(m_current_size.load()) + " bytes) to " + 
                                   m_current_file);
                }

                // Flush định kỳ
                if (m_writes_since_flush >= FLUSH_INTERVAL)
                {
                    m_logger->trace("Auto-flushing after " + std::to_string(FLUSH_INTERVAL) + " writes");
                    flush();
                    m_writes_since_flush = 0;
                }

                return true;
            }

            void PcapWriter::flush()
            {
                if (m_pcap_dumper)
                {
                    m_logger->trace("Flushing PCAP file: " + m_current_file);
                    pcap_dump_flush(m_pcap_dumper);
                }
            }

            void PcapWriter::close()
            {
                if (m_pcap_dumper)
                {
                    m_logger->info("Closing PCAP file: " + m_current_file + 
                                  " (packets=" + std::to_string(m_packet_count.load()) + 
                                  ", size=" + std::to_string(m_current_size.load()) + " bytes)");
                    
                    flush();
                    pcap_dump_close(m_pcap_dumper);
                    m_pcap_dumper = nullptr;
                }

                if (m_pcap_handle)
                {
                    pcap_close(m_pcap_handle);
                    m_pcap_handle = nullptr;
                }

                m_current_file.clear();
                m_current_size = 0;
                m_packet_count = 0;
            }

        } // namespace Storage
    }     // namespace Core
} // namespace NetworkSecurity
