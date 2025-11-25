// test_packet_capture_storage.cpp
#include "packet_ingress.hpp"
#include "packet_parser.hpp"
#include "packet_storage.hpp"
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
using namespace NetworkSecurity::Core::Storage;

// ==================== Global Variables ====================
std::atomic<bool> g_running(true);
std::unique_ptr<PacketIngress> g_ingress;
std::unique_ptr<PacketStorage> g_storage;
std::atomic<uint64_t> g_packet_count(0);
std::atomic<uint64_t> g_saved_count(0);
std::atomic<uint64_t> g_error_count(0);

// ==================== Signal Handler ====================
void signalHandler(int signum) {
    std::cout << "\n\n🛑 Received signal " << signum << ", stopping capture...\n" << std::endl;
    g_running.store(false);
    if (g_ingress) {
        g_ingress->stop();
    }
}

// ==================== Helper Functions ====================

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

std::string formatBytes(uint64_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    } else if (bytes < 1024 * 1024) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
        return std::string(buf);
    } else if (bytes < 1024ULL * 1024 * 1024) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024.0));
        return std::string(buf);
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        return std::string(buf);
    }
}

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

void displayHeader() {
    std::cout << "\n";
    std::cout << "╔════════╦═════════════════╦═══════╦═══════════════════════════════════════════════════════════╦═════════╦════════╗\n";
    std::cout << "║ " << std::setw(6) << std::left << "Count"
              << " ║ " << std::setw(15) << "Time"
              << " ║ " << std::setw(5) << "Proto"
              << " ║ " << std::setw(57) << "Connection"
              << " ║ " << std::setw(7) << "Size"
              << " ║ " << std::setw(6) << "Status" << " ║\n";
    std::cout << "╠════════╬═════════════════╬═══════╬═══════════════════════════════════════════════════════════╬═════════╬════════╣\n";
    std::cout << std::flush;
}

void displayFooter() {
    std::cout << "╚════════╩═════════════════╩═══════╩═══════════════════════════════════════════════════════════╩═════════╩════════╝\n";
    std::cout << std::flush;
}

void displayPacketCompact(const ParsedPacket& packet, bool saved) {
    uint64_t count = g_packet_count.fetch_add(1) + 1;
    
    std::string protocol = PacketParser::getProtocolTypeName(packet.protocol_type);
    std::string time_str = Utils::formatTimestampUs(packet.timestamp);
    std::string size_str = std::to_string(packet.packet_size);
    
    // Build connection string
    std::string connection;
    
    if (packet.has_arp) {
        connection = PacketParser::ipv4ToString(packet.arp.sender_ip) + " -> " +
                     PacketParser::ipv4ToString(packet.arp.target_ip);
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
        std::string src_ipv6 = PacketParser::ipv6ToString(packet.ipv6.src_ip);
        std::string dst_ipv6 = PacketParser::ipv6ToString(packet.ipv6.dst_ip);
        
        if (src_ipv6.length() > 20) src_ipv6 = src_ipv6.substr(0, 17) + "...";
        if (dst_ipv6.length() > 20) dst_ipv6 = dst_ipv6.substr(0, 17) + "...";
        
        connection = src_ipv6 + " -> " + dst_ipv6;
    }
    else {
        connection = PacketParser::macToString(packet.src_mac) + " -> " +
                     PacketParser::macToString(packet.dst_mac);
    }
    
    // Truncate connection if too long
    if (connection.length() > 57) {
        connection = connection.substr(0, 54) + "...";
    }
    
    // Status
    std::string status = saved ? "✓ OK" : "✗ ERR";
    std::string status_color = saved ? "\033[1;32m" : "\033[1;31m";
    
    // Print with color
    std::string color = getProtocolColor(protocol);
    
    std::cout << "║ " << std::setw(6) << std::right << count
              << " ║ " << std::setw(15) << std::left << time_str
              << " ║ " << color << std::setw(5) << std::left << protocol << resetColor()
              << " ║ " << std::setw(57) << std::left << connection
              << " ║ " << std::setw(7) << std::right << size_str
              << " ║ " << status_color << std::setw(6) << status << resetColor() << " ║\n";
    std::cout << std::flush;
}

// ==================== Packet Callback ====================

void packetCallback(const ParsedPacket& packet) {
    // Lưu packet vào storage
    bool saved = g_storage->savePacket(packet);
    
    if (saved) {
        g_saved_count.fetch_add(1);
    } else {
        g_error_count.fetch_add(1);
    }
    
    // Display packet
    displayPacketCompact(packet, saved);
    
    // Flush định kỳ (mỗi 100 packets)
    if (g_packet_count.load() % 100 == 0) {
        g_storage->flush();
    }
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
    std::string interface = "wlan0";
    std::string bpf_filter = "";
    std::string output_dir = "./data/pcap";
    size_t max_file_size_mb = 100;
    size_t max_duration_sec = 300; // 5 minutes
    
    if (argc >= 2) {
        interface = argv[1];
    }
    if (argc >= 3) {
        bpf_filter = argv[2];
    }
    if (argc >= 4) {
        output_dir = argv[3];
    }
    if (argc >= 5) {
        max_file_size_mb = std::stoul(argv[4]);
    }
    if (argc >= 6) {
        max_duration_sec = std::stoul(argv[5]);
    }
    
    // Print banner
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                              NETWORK PACKET CAPTURE & STORAGE                                         ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Interface         : " << std::setw(78) << std::left << interface << "║\n";
    std::cout << "║ BPF Filter        : " << std::setw(78) << std::left << (bpf_filter.empty() ? "None" : bpf_filter) << "║\n";
    std::cout << "║ Output Directory  : " << std::setw(78) << std::left << output_dir << "║\n";
    std::cout << "║ Max File Size     : " << std::setw(78) << std::left << (std::to_string(max_file_size_mb) + " MB") << "║\n";
    std::cout << "║ Max Duration      : " << std::setw(78) << std::left << (std::to_string(max_duration_sec) + " seconds") << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::flush;
    
    // Check permissions
    if (!PacketIngress::checkPermissions()) {
        spdlog::error("Insufficient permissions! Run with sudo.");
        return 1;
    }
    
    // Create storage config
    StorageConfig storage_config;
    storage_config.output_dir = output_dir;
    storage_config.file_prefix = "capture";
    storage_config.max_file_size_mb = max_file_size_mb;
    storage_config.max_file_duration_sec = max_duration_sec;
    storage_config.enable_rotation = true;
    storage_config.datalink_type = DLT_EN10MB; // Ethernet
    
    // Create PacketStorage
    g_storage = std::make_unique<PacketStorage>(storage_config);
    if (!g_storage->initialize()) {
        spdlog::error("Failed to initialize packet storage");
        return 1;
    }
    
    // Create ingress config
    IngressConfig config;
    config.interface = interface;
    config.snaplen = 65535;
    config.buffer_size = 16 * 1024 * 1024;  // 16 MB
    config.timeout_ms = 1000;
    config.promiscuous = true;
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
    
    // Flush and close storage
    g_storage->flush();
    g_storage->close();
    
    // Get final stats
    IngressStats ingress_stats = g_ingress->getStats();
    StorageStatsSnapshot storage_stats = g_storage->getStats();
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                      CAPTURE STATISTICS                                               ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ INGRESS                                                                                               ║\n";
    std::cout << "║   Packets Received  : " << std::setw(78) << std::left << ingress_stats.packets_received << "║\n";
    std::cout << "║   Packets Dropped   : " << std::setw(78) << std::left << ingress_stats.packets_dropped << "║\n";
    std::cout << "║   Bytes Received    : " << std::setw(78) << std::left << formatBytes(ingress_stats.bytes_received) << "║\n";
    std::cout << "║   Errors            : " << std::setw(78) << std::left << ingress_stats.errors << "║\n";
    
    char rate_buf[80];
    snprintf(rate_buf, sizeof(rate_buf), "%.2f packets/sec", ingress_stats.capture_rate);
    std::cout << "║   Capture Rate      : " << std::setw(78) << std::left << rate_buf << "║\n";
    
    std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    std::cout << "║ STORAGE                                                                                               ║\n";
    std::cout << "║   Packets Saved     : " << std::setw(78) << std::left << storage_stats.total_packets << "║\n";
    std::cout << "║   Bytes Saved       : " << std::setw(78) << std::left << formatBytes(storage_stats.total_bytes) << "║\n";
    std::cout << "║   Files Created     : " << std::setw(78) << std::left << storage_stats.files_created << "║\n";
    std::cout << "║   Write Errors      : " << std::setw(78) << std::left << storage_stats.write_errors << "║\n";
    std::cout << "║   Current File      : " << std::setw(78) << std::left << storage_stats.current_file << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    spdlog::info("Program terminated successfully");
    
    return 0;
}
