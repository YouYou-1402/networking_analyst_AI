// test_packet_capture.cpp
#include "packet_ingress.hpp"
#include "packet_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <chrono>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

using namespace NetworkSecurity::Layer1;
using namespace NetworkSecurity::Common;

// ==================== Global Variables ====================
std::atomic<bool> g_running(true);
std::unique_ptr<PacketIngress> g_ingress;
std::atomic<uint64_t> g_packet_count(0);

// ==================== Signal Handler ====================
void signalHandler(int signum) {
    std::cout << "\n\n🛑 Received signal " << signum << ", stopping capture...\n" << std::endl;
    g_running.store(false);
    if (g_ingress) {
        g_ingress->stop();
    }
}

// ==================== Helper Functions ====================



// /**
//  * @brief Format timestamp từ microseconds
//  */
// std::string formatTimestamp(uint64_t timestamp_us) {
//     time_t seconds = timestamp_us / 1000000;
//     uint64_t microseconds = timestamp_us % 1000000;
    
//     struct tm timeinfo;
//     localtime_r(&seconds, &timeinfo);
    
//     char buffer[64];
//     strftime(buffer, sizeof(buffer), "%H:%M:%S", &timeinfo);
//     snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), 
//              ".%06lu", microseconds);
    
//     return std::string(buffer);
// }

/**
 * @brief Format bytes size
 */
std::string formatBytes(uint64_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    } else if (bytes < 1024 * 1024) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
        return std::string(buf);
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024.0));
        return std::string(buf);
    }
}

/**
 * @brief Get color code cho protocol
 */
std::string getProtocolColor(const std::string& protocol) {
    if (protocol == "TCP") return "\033[1;32m";      // Green
    if (protocol == "UDP") return "\033[1;34m";      // Blue
    if (protocol == "ICMP") return "\033[1;33m";     // Yellow
    if (protocol == "ARP") return "\033[1;35m";      // Magenta
    if (protocol == "IPv6") return "\033[1;36m";     // Cyan
    return "\033[1;37m";                              // White
}

std::string resetColor() {
    return "\033[0m";
}

// ==================== Display Functions ====================

/**
 * @brief Display header của bảng
 */
void displayHeader() {
    std::cout << "\n";
    std::cout << "╔════════╦═════════════════╦═══════╦═══════════════════════════════════════════════════════════════════╦═════════╗\n";
    std::cout << "║ " << std::setw(6) << std::left << "Count"
              << " ║ " << std::setw(15) << "Time"
              << " ║ " << std::setw(5) << "Proto"
              << " ║ " << std::setw(69) << "Connection"
              << " ║ " << std::setw(7) << "Size" << " ║\n";
    std::cout << "╠════════╬═════════════════╬═══════╬═══════════════════════════════════════════════════════════════════╬═════════╣\n";
    std::cout << std::flush;
}

/**
 * @brief Display footer
 */
void displayFooter() {
    std::cout << "╚════════╩═════════════════╩═══════╩═══════════════════════════════════════════════════════════════════╩═════════╝\n";
    std::cout << std::flush;
}

/**
 * @brief Display packet info - Compact format
 */
void displayPacketCompact(const ParsedPacket& packet) {
    uint64_t count = g_packet_count.fetch_add(1) + 1;
    
    std::string protocol = PacketParser::getProtocolTypeName(packet.protocol_type);
    std::string time_str = Utils::formatTimestampUs(packet.timestamp);
    std::string size_str = std::to_string(packet.packet_size);
    
    // Build connection string
    std::string connection;
    
    if (packet.has_arp) {
        connection = PacketParser::ipv4ToString(packet.arp.sender_ip) + " -> " +
                     PacketParser::ipv4ToString(packet.arp.target_ip) + " (" +
                     PacketParser::arpOpcodeToString(packet.arp.opcode) + ")";
    }
    else if (packet.has_ipv4) {
        connection = PacketParser::ipv4ToString(packet.ipv4.src_ip);
        
        if (packet.has_tcp || packet.has_udp) {
            connection += ":" + std::to_string(packet.src_port);
        }
        
        connection += " -> " + PacketParser::ipv4ToString(packet.ipv4.dst_ip);
        
        if (packet.has_tcp || packet.has_udp) {
            connection += ":" + std::to_string(packet.dst_port);
        }
        
        if (packet.has_tcp) {
            connection += " [" + PacketParser::tcpFlagsToString(packet.tcp.flags) + "]";
        }
    }
    else if (packet.has_ipv6) {
        // Shorten IPv6 for display
        std::string src_ipv6 = PacketParser::ipv6ToString(packet.ipv6.src_ip);
        std::string dst_ipv6 = PacketParser::ipv6ToString(packet.ipv6.dst_ip);
        
        // Take first 20 chars
        if (src_ipv6.length() > 20) src_ipv6 = src_ipv6.substr(0, 17) + "...";
        if (dst_ipv6.length() > 20) dst_ipv6 = dst_ipv6.substr(0, 17) + "...";
        
        connection = src_ipv6 + " -> " + dst_ipv6;
    }
    else {
        connection = PacketParser::macToString(packet.src_mac) + " -> " +
                     PacketParser::macToString(packet.dst_mac);
    }
    
    // Truncate connection if too long
    if (connection.length() > 69) {
        connection = connection.substr(0, 66) + "...";
    }
    
    // Print with color
    std::string color = getProtocolColor(protocol);
    
    std::cout << "║ " << std::setw(6) << std::right << count
              << " ║ " << std::setw(15) << std::left << time_str
              << " ║ " << color << std::setw(5) << std::left << protocol << resetColor()
              << " ║ " << std::setw(69) << std::left << connection
              << " ║ " << std::setw(7) << std::right << size_str << " ║\n";
    std::cout << std::flush;
}

/**
 * @brief Display packet info - Detailed format
 */
void displayPacketDetailed(const ParsedPacket& packet) {
    uint64_t count = g_packet_count.fetch_add(1) + 1;
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║ Packet #" << count << " - " << Utils::formatTimestampUs(packet.timestamp) << std::string(72 - std::to_string(count).length(), ' ') << "║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    
    // Ethernet
    if (packet.has_ethernet) {
        std::cout << "║ ETHERNET                                                                                              ║\n";
        std::cout << "║   Source MAC      : " << std::setw(78) << std::left 
                  << PacketParser::macToString(packet.ethernet.src_mac) << "║\n";
        std::cout << "║   Destination MAC : " << std::setw(78) << std::left 
                  << PacketParser::macToString(packet.ethernet.dst_mac) << "║\n";
        std::cout << "║   EtherType       : 0x" << std::hex << std::setw(4) << std::setfill('0') 
                  << ntohs(packet.ethernet.ether_type) << std::dec << std::setfill(' ') 
                  << std::string(72, ' ') << "║\n";
        
        if (packet.ethernet.has_vlan) {
            std::cout << "║   VLAN ID         : " << packet.ethernet.vlan_id 
                      << std::string(78 - std::to_string(packet.ethernet.vlan_id).length(), ' ') << "║\n";
        }
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // ARP
    if (packet.has_arp) {
        std::cout << "║ ARP                                                                                                   ║\n";
        std::cout << "║   Operation       : " << std::setw(78) << std::left 
                  << PacketParser::arpOpcodeToString(packet.arp.opcode) << "║\n";
        std::cout << "║   Sender MAC      : " << std::setw(78) << std::left 
                  << PacketParser::macToString(packet.arp.sender_mac) << "║\n";
        std::cout << "║   Sender IP       : " << std::setw(78) << std::left 
                  << PacketParser::ipv4ToString(packet.arp.sender_ip) << "║\n";
        std::cout << "║   Target MAC      : " << std::setw(78) << std::left 
                  << PacketParser::macToString(packet.arp.target_mac) << "║\n";
        std::cout << "║   Target IP       : " << std::setw(78) << std::left 
                  << PacketParser::ipv4ToString(packet.arp.target_ip) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // IPv4
    if (packet.has_ipv4) {
        std::cout << "║ IPv4                                                                                                  ║\n";
        std::cout << "║   Source IP       : " << std::setw(78) << std::left 
                  << PacketParser::ipv4ToString(packet.ipv4.src_ip) << "║\n";
        std::cout << "║   Destination IP  : " << std::setw(78) << std::left 
                  << PacketParser::ipv4ToString(packet.ipv4.dst_ip) << "║\n";
        std::cout << "║   Protocol        : " << std::setw(78) << std::left 
                  << PacketParser::protocolToString(packet.ipv4.protocol) << "║\n";
        std::cout << "║   TTL             : " << std::setw(78) << std::left 
                  << std::to_string(packet.ipv4.ttl) << "║\n";
        std::cout << "║   Total Length    : " << std::setw(78) << std::left 
                  << std::to_string(packet.ipv4.total_length) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // IPv6
    if (packet.has_ipv6) {
        std::cout << "║ IPv6                                                                                                  ║\n";
        std::cout << "║   Source IP       : " << std::setw(78) << std::left 
                  << PacketParser::ipv6ToString(packet.ipv6.src_ip) << "║\n";
        std::cout << "║   Destination IP  : " << std::setw(78) << std::left 
                  << PacketParser::ipv6ToString(packet.ipv6.dst_ip) << "║\n";
        std::cout << "║   Next Header     : " << std::setw(78) << std::left 
                  << PacketParser::protocolToString(packet.ipv6.next_header) << "║\n";
        std::cout << "║   Hop Limit       : " << std::setw(78) << std::left 
                  << std::to_string(packet.ipv6.hop_limit) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // TCP
    if (packet.has_tcp) {
        std::cout << "║ TCP                                                                                                   ║\n";
        std::cout << "║   Source Port     : " << std::setw(78) << std::left 
                  << std::to_string(packet.tcp.src_port) << "║\n";
        std::cout << "║   Destination Port: " << std::setw(78) << std::left 
                  << std::to_string(packet.tcp.dst_port) << "║\n";
        std::cout << "║   Sequence Number : " << std::setw(78) << std::left 
                  << std::to_string(packet.tcp.seq_number) << "║\n";
        std::cout << "║   Ack Number      : " << std::setw(78) << std::left 
                  << std::to_string(packet.tcp.ack_number) << "║\n";
        std::cout << "║   Flags           : " << std::setw(78) << std::left 
                  << PacketParser::tcpFlagsToString(packet.tcp.flags) << "║\n";
        std::cout << "║   Window Size     : " << std::setw(78) << std::left 
                  << std::to_string(packet.tcp.window_size) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // UDP
    if (packet.has_udp) {
        std::cout << "║ UDP                                                                                                   ║\n";
        std::cout << "║   Source Port     : " << std::setw(78) << std::left 
                  << std::to_string(packet.udp.src_port) << "║\n";
        std::cout << "║   Destination Port: " << std::setw(78) << std::left 
                  << std::to_string(packet.udp.dst_port) << "║\n";
        std::cout << "║   Length          : " << std::setw(78) << std::left 
                  << std::to_string(packet.udp.length) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // ICMP
    if (packet.has_icmp) {
        std::cout << "║ ICMP                                                                                                  ║\n";
        std::cout << "║   Type            : " << std::setw(78) << std::left 
                  << PacketParser::icmpTypeToString(packet.icmp.type) << "║\n";
        std::cout << "║   Code            : " << std::setw(78) << std::left 
                  << std::to_string(packet.icmp.code) << "║\n";
        std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    }
    
    // Payload
    std::cout << "║ PAYLOAD                                                                                               ║\n";
    std::cout << "║   Size            : " << std::setw(78) << std::left 
              << std::to_string(packet.payload_length) + " bytes" << "║\n";
    
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::flush;
}

// ==================== Packet Callback ====================

/**
 * @brief Callback được gọi cho mỗi packet
 */
void packetCallback(const ParsedPacket& packet) {
    // Display packet (compact mode)
    displayPacketCompact(packet);
    
    // Uncomment để dùng detailed mode:
    // displayPacketDetailed(packet);
}

// ==================== Main Function ====================

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Setup spdlog
    auto console = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    
    // Parse arguments
    std::string interface = "wlan0";  // Default interface
    std::string bpf_filter = "";
    bool promiscuous = true;
    
    if (argc >= 2) {
        interface = argv[1];
    }
    if (argc >= 3) {
        bpf_filter = argv[2];
    }
    
    // Print banner
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                    NETWORK PACKET CAPTURE                                            ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Interface         : " << std::setw(78) << std::left << interface << "║\n";
    std::cout << "║ Promiscuous Mode  : " << std::setw(78) << std::left << (promiscuous ? "Enabled" : "Disabled") << "║\n";
    std::cout << "║ BPF Filter        : " << std::setw(78) << std::left << (bpf_filter.empty() ? "None" : bpf_filter) << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::flush;
    
    // Check available interfaces
    auto interfaces = PacketIngress::listInterfaces();
    if (interfaces.empty()) {
        spdlog::error("No network interfaces found!");
        return 1;
    }
    
    spdlog::info("Available interfaces:");
    for (const auto& iface : interfaces) {
        spdlog::info("  - {}", iface);
    }
    
    // Check permissions
    if (!PacketIngress::checkPermissions()) {
        spdlog::error("Insufficient permissions! Run with sudo.");
        return 1;
    }
    
    // Create ingress config
    IngressConfig config;
    config.interface = interface;
    config.snaplen = 65535;
    config.buffer_size = 16 * 1024 * 1024;  // 256 MB
    config.timeout_ms = 1000;
    config.promiscuous = promiscuous;
    config.enable_timestamp = true;
    config.bpf_filter = bpf_filter;
    
    // Create PacketIngress
    g_ingress = std::make_unique<PacketIngress>(config);
    
    // Initialize
    if (!g_ingress->initialize()) {
        spdlog::error("Failed to initialize packet ingress");
        return 1;
    }
    
    // Display header
    displayHeader();
    
    // Start capture
    if (!g_ingress->start(packetCallback)) {
        spdlog::error("Failed to start packet capture");
        return 1;
    }
    
    // Wait for stop signal
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Display footer
    displayFooter();
    
    // Get final stats
    IngressStats stats = g_ingress->getStats();
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                      CAPTURE STATISTICS                                               ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Packets Received  : " << std::setw(78) << std::left << stats.packets_received << "║\n";
    std::cout << "║ Packets Dropped   : " << std::setw(78) << std::left << stats.packets_dropped << "║\n";
    std::cout << "║ Bytes Received    : " << std::setw(78) << std::left << formatBytes(stats.bytes_received) << "║\n";
    std::cout << "║ Errors            : " << std::setw(78) << std::left << stats.errors << "║\n";
    
    char rate_buf[80];
    snprintf(rate_buf, sizeof(rate_buf), "%.2f packets/sec", stats.capture_rate);
    std::cout << "║ Capture Rate      : " << std::setw(78) << std::left << rate_buf << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    spdlog::info("Program terminated successfully");
    
    return 0;
}
