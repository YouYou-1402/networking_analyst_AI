// tests/gui/packet_index.hpp
#ifndef PACKET_INDEX_HPP
#define PACKET_INDEX_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <packet_parser.hpp>
#include <pcap.h>
namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Lightweight packet index - chỉ lưu metadata
         */
        struct PacketIndex
        {
            uint64_t file_offset;      // Vị trí trong file
            uint64_t timestamp_us;     // Timestamp
            uint32_t packet_length;    // Độ dài packet
            uint32_t captured_length;  // Độ dài captured
            
            // Basic info để hiển thị (không cần load full packet)
            std::string protocol;      // TCP/UDP/ICMP...
            std::string src_addr;      // Source address
            std::string dst_addr;      // Destination address
            uint16_t src_port;         // Source port (nếu có)
            uint16_t dst_port;         // Destination port (nếu có)
            
            PacketIndex()
                : file_offset(0), timestamp_us(0), packet_length(0),
                  captured_length(0), src_port(0), dst_port(0) {}
        };
        
        /**
         * @brief PCAP Index Manager - quản lý index của file PCAP
         */
        class PcapIndexManager
        {
        public:
            PcapIndexManager();
            ~PcapIndexManager();
            
            // Build index từ PCAP file
            bool buildIndex(const std::string& pcap_file);
            
            // Get packet index
            const PacketIndex* getPacketIndex(size_t index) const;
            
            // Load full packet data từ file
            bool loadPacket(size_t index, NetworkSecurity::Common::ParsedPacket& packet);
            
            // Get total packets
            size_t getPacketCount() const { return m_indices.size(); }
            
            // Clear index
            void clear();
            
            // Get PCAP file path
            std::string getPcapFile() const { return m_pcap_file; }
            bool matchesSimpleFilter(size_t index, const std::string& filter) const;
        private:
            std::string m_pcap_file;
            std::vector<PacketIndex> m_indices;
            pcap_t* m_pcap_handle;
            
            // Parse basic info từ raw data
            bool parseBasicInfo(const u_char* data, uint32_t length, PacketIndex& index);
            bool matchesProtocol(const PacketIndex& pkt, const std::string& protocol) const;
            bool matchesAddress(const PacketIndex& pkt, const std::string& addr) const;
            bool matchesPort(const PacketIndex& pkt, uint16_t port) const;
        };
    }
}

#endif // PACKET_INDEX_HPP
