// tests/gui/packet_index.cpp
#include "packet_index.hpp"
#include "../../src/common/packet_parser.hpp"
#include <pcap/pcap.h>
#include <spdlog/spdlog.h>
#include <arpa/inet.h>
#include <algorithm>  
#include <cctype>     
using namespace NetworkSecurity::GUI;
using namespace NetworkSecurity::Common;

PcapIndexManager::PcapIndexManager()
    : m_pcap_handle(nullptr)
{
}

PcapIndexManager::~PcapIndexManager()
{
    clear();
}

bool PcapIndexManager::buildIndex(const std::string& pcap_file)
{
    clear();
    
    m_pcap_file = pcap_file;
    
    // Open PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    m_pcap_handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    
    if (!m_pcap_handle) {
        spdlog::error("Failed to open PCAP file: {}", errbuf);
        return false;
    }
    
    spdlog::info("Building index for: {}", pcap_file);
    
    // Read packets and build index
    struct pcap_pkthdr *header;
    const u_char *data;
    uint64_t file_offset = 24; // PCAP global header size
    
    while (pcap_next_ex(m_pcap_handle, &header, &data) >= 0) {
        PacketIndex index;
        index.file_offset = file_offset;
        index.timestamp_us = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
        index.packet_length = header->len;
        index.captured_length = header->caplen;
        
        // Parse basic info (lightweight)
        parseBasicInfo(data, header->caplen, index);
        
        m_indices.push_back(index);
        
        // Update offset (packet header + data)
        file_offset += 16 + header->caplen; // 16 = pcap packet header size
    }
    
    spdlog::info("Index built: {} packets", m_indices.size());
    
    return true;
}

bool PcapIndexManager::parseBasicInfo(const u_char* data, uint32_t length, PacketIndex& index)
{
    if (length < 14) return false; // Minimum Ethernet header
    
    // Ethernet header
    uint16_t ether_type = ntohs(*(uint16_t*)(data + 12));
    
    // IPv4
    if (ether_type == 0x0800 && length >= 34) {
        const u_char* ip_header = data + 14;
        uint8_t protocol = ip_header[9];
        
        // Source IP
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip_header + 12, src_ip, INET_ADDRSTRLEN);
        index.src_addr = src_ip;
        
        // Destination IP
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip_header + 16, dst_ip, INET_ADDRSTRLEN);
        index.dst_addr = dst_ip;
        
        uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4;
        const u_char* transport_header = ip_header + ip_header_len;
        
        // TCP
        if (protocol == 6 && length >= 34 + ip_header_len + 4) {
            index.protocol = "TCP";
            index.src_port = ntohs(*(uint16_t*)transport_header);
            index.dst_port = ntohs(*(uint16_t*)(transport_header + 2));
        }
        // UDP
        else if (protocol == 17 && length >= 34 + ip_header_len + 4) {
            index.protocol = "UDP";
            index.src_port = ntohs(*(uint16_t*)transport_header);
            index.dst_port = ntohs(*(uint16_t*)(transport_header + 2));
        }
        // ICMP
        else if (protocol == 1) {
            index.protocol = "ICMP";
        }
        else {
            index.protocol = "IPv4";
        }
    }
    // ARP
    else if (ether_type == 0x0806) {
        index.protocol = "ARP";
        // Parse ARP addresses if needed
    }
    // IPv6
    else if (ether_type == 0x86DD) {
        index.protocol = "IPv6";
        // Parse IPv6 addresses if needed
    }
    else {
        index.protocol = "Ethernet";
    }
    
    return true;
}

const PacketIndex* PcapIndexManager::getPacketIndex(size_t index) const
{
    if (index >= m_indices.size()) {
        return nullptr;
    }
    return &m_indices[index];
}

bool PcapIndexManager::loadPacket(size_t index, ParsedPacket& packet)
{
    if (index >= m_indices.size() || !m_pcap_handle) {
        return false;
    }
    
    // Reopen file để seek (pcap_t không hỗ trợ seek tốt)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* temp_handle = pcap_open_offline(m_pcap_file.c_str(), errbuf);
    if (!temp_handle) {
        return false;
    }
    
    // Skip đến packet cần load
    struct pcap_pkthdr *header;
    const u_char *data;
    size_t current = 0;
    
    while (current <= index && pcap_next_ex(temp_handle, &header, &data) >= 0) {
        if (current == index) {
            // Parse full packet
            PacketParser parser;
            bool success = parser.parsePacket(data, header->caplen, packet);
            packet.timestamp = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
            
            pcap_close(temp_handle);
            return success;
        }
        current++;
    }
    
    pcap_close(temp_handle);
    return false;
}

void PcapIndexManager::clear()
{
    m_indices.clear();
    if (m_pcap_handle) {
        pcap_close(m_pcap_handle);
        m_pcap_handle = nullptr;
    }
    m_pcap_file.clear();
}


bool PcapIndexManager::matchesSimpleFilter(size_t index, const std::string& filter) const
{
    const PacketIndex* pkt = getPacketIndex(index);
    if (!pkt) return false;
    
    if (filter.empty()) return true;
    
    std::string lower_filter = filter;
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);
    
    // Protocol filters
    if (lower_filter == "tcp") {
        return matchesProtocol(*pkt, "TCP");
    }
    if (lower_filter == "udp") {
        return matchesProtocol(*pkt, "UDP");
    }
    if (lower_filter == "icmp") {
        return matchesProtocol(*pkt, "ICMP");
    }
    if (lower_filter == "arp") {
        return matchesProtocol(*pkt, "ARP");
    }
    if (lower_filter == "ipv4") {
        return matchesProtocol(*pkt, "IPv4");
    }
    if (lower_filter == "ipv6") {
        return matchesProtocol(*pkt, "IPv6");
    }
    
    // Port filters: tcp.port == 80
    if (lower_filter.find("tcp.port") != std::string::npos ||
        lower_filter.find("udp.port") != std::string::npos) {
        
        size_t pos = lower_filter.find("==");
        if (pos != std::string::npos) {
            std::string port_str = lower_filter.substr(pos + 2);
            port_str.erase(0, port_str.find_first_not_of(" \t"));
            
            try {
                uint16_t port = std::stoi(port_str);
                return matchesPort(*pkt, port);
            } catch (...) {
                return false;
            }
        }
    }
    
    // IP address filters: ip.addr == 192.168.1.1
    if (lower_filter.find("ip.addr") != std::string::npos ||
        lower_filter.find("ip.src") != std::string::npos ||
        lower_filter.find("ip.dst") != std::string::npos) {
        
        size_t pos = lower_filter.find("==");
        if (pos != std::string::npos) {
            std::string addr = lower_filter.substr(pos + 2);
            addr.erase(0, addr.find_first_not_of(" \t"));
            addr.erase(addr.find_last_not_of(" \t") + 1);
            
            return matchesAddress(*pkt, addr);
        }
    }
    
    // Combined filters with && and ||
    if (lower_filter.find("&&") != std::string::npos) {
        size_t pos = lower_filter.find("&&");
        std::string left = lower_filter.substr(0, pos);
        std::string right = lower_filter.substr(pos + 2);
        
        left.erase(0, left.find_first_not_of(" \t"));
        left.erase(left.find_last_not_of(" \t") + 1);
        right.erase(0, right.find_first_not_of(" \t"));
        right.erase(right.find_last_not_of(" \t") + 1);
        
        return matchesSimpleFilter(index, left) && matchesSimpleFilter(index, right);
    }
    
    if (lower_filter.find("||") != std::string::npos) {
        size_t pos = lower_filter.find("||");
        std::string left = lower_filter.substr(0, pos);
        std::string right = lower_filter.substr(pos + 2);
        
        left.erase(0, left.find_first_not_of(" \t"));
        left.erase(left.find_last_not_of(" \t") + 1);
        right.erase(0, right.find_first_not_of(" \t"));
        right.erase(right.find_last_not_of(" \t") + 1);
        
        return matchesSimpleFilter(index, left) || matchesSimpleFilter(index, right);
    }
    
    return false;
}

bool PcapIndexManager::matchesProtocol(const PacketIndex& pkt, const std::string& protocol) const
{
    return pkt.protocol == protocol;
}

bool PcapIndexManager::matchesAddress(const PacketIndex& pkt, const std::string& addr) const
{
    return pkt.src_addr.find(addr) != std::string::npos ||
           pkt.dst_addr.find(addr) != std::string::npos;
}

bool PcapIndexManager::matchesPort(const PacketIndex& pkt, uint16_t port) const
{
    return pkt.src_port == port || pkt.dst_port == port;
}
