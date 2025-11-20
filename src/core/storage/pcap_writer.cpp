// src/core/storage/pcap_writer.cpp
#include "pcap_writer.hpp"
#include "../../common/utils.hpp"
#include <sys/stat.h>
#include <iostream>
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
                // Tạo thư mục nếu chưa tồn tại
                struct stat st;
                if (stat(m_output_dir.c_str(), &st) != 0)
                {
                    mkdir(m_output_dir.c_str(), 0755);
                }
            }

            PcapWriter::~PcapWriter()
            {
                close();
            }

            bool PcapWriter::open(const std::string &filename, int datalink_type)
            {
                // Đóng file cũ nếu đang mở
                if (m_pcap_dumper)
                {
                    close();
                }

                // Tạo đường dẫn đầy đủ
                m_current_file = m_output_dir + "/" + filename;

                std::cout << "[PcapWriter] Opening file: " << m_current_file << std::endl;

                // Tạo pcap handle cho việc ghi
                m_pcap_handle = pcap_open_dead(datalink_type, 65535);
                if (!m_pcap_handle)
                {
                    std::cerr << "[PcapWriter] Failed to create pcap handle" << std::endl;
                    return false;
                }

                // Mở file để ghi
                m_pcap_dumper = pcap_dump_open(m_pcap_handle, m_current_file.c_str());
                if (!m_pcap_dumper)
                {
                    std::cerr << "[PcapWriter] Failed to open dump file: "
                              << pcap_geterr(m_pcap_handle) << std::endl;
                    pcap_close(m_pcap_handle);
                    m_pcap_handle = nullptr;
                    return false;
                }

                // Reset counters
                m_current_size = 0;
                m_packet_count = 0;
                m_writes_since_flush = 0;

                std::cout << "[PcapWriter] File opened successfully" << std::endl;
                return true;
            }

            bool PcapWriter::writePacket(const Common::ParsedPacket &packet)
            {
                if (!m_pcap_dumper)
                {
                    std::cerr << "[PcapWriter] PCAP dumper not initialized" << std::endl;
                    return false;
                }

                // Kiểm tra payload
                if (!packet.payload || packet.payload_length == 0)
                {
                    std::cerr << "[PcapWriter] Invalid packet data" << std::endl;
                    return false;
                }

                // Sử dụng payload và captured_length từ ParsedPacket
                return writeRawPacket(packet.payload, packet.captured_length, packet.timestamp);
            }

            bool PcapWriter::writeRawPacket(const uint8_t *data, size_t length, uint64_t timestamp_us)
            {
                if (!m_pcap_dumper)
                {
                    std::cerr << "[PcapWriter] PCAP dumper not initialized" << std::endl;
                    return false;
                }

                if (!data || length == 0)
                {
                    std::cerr << "[PcapWriter] Invalid packet data" << std::endl;
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

                // Flush định kỳ
                if (m_writes_since_flush >= FLUSH_INTERVAL)
                {
                    flush();
                    m_writes_since_flush = 0;
                }

                return true;
            }

            void PcapWriter::flush()
            {
                if (m_pcap_dumper)
                {
                    pcap_dump_flush(m_pcap_dumper);
                }
            }

            void PcapWriter::close()
            {
                if (m_pcap_dumper)
                {
                    flush();
                    pcap_dump_close(m_pcap_dumper);
                    m_pcap_dumper = nullptr;
                    std::cout << "[PcapWriter] Closed file: " << m_current_file
                              << " (" << m_packet_count << " packets, "
                              << m_current_size << " bytes)" << std::endl;
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
