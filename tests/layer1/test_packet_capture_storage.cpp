// tests/layer1/test_packet_capture_storage.cpp
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/core/storage/packet_storage.hpp"
#include "../../src/common/packet_parser.hpp"
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
std::unique_ptr<PacketStorage> g_storage;  // ← THÊM STORAGE
std::atomic<uint64_t> g_packet_count(0);

// ==================== Signal Handler ====================
void signalHandler(int signum) {
    std::cout << "\n\n🛑 Received signal " << signum << ", stopping capture...\n" << std::endl;
    g_running.store(false);
    if (g_ingress) {
        g_ingress->stop();
    }
    // ← THÊM: Flush storage khi thoát
    if (g_storage) {
        g_storage->flush();
    }
}

// ==================== Helper Functions ====================

/**
 * @brief Format timestamp từ microseconds
 */
std::string formatTimestamp(uint64_t timestamp_us) {
    time_t seconds = timestamp_us / 1000000;
    uint64_t microseconds = timestamp_us % 1000000;
    
    struct tm timeinfo;
    localtime_r(&seconds, &timeinfo);
    
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &timeinfo);
    snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), 
             ".%06lu", microseconds);
    
    return std::string(buffer);
}

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
    std::string time_str = formatTimestamp(packet.timestamp);
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
    
    if (connection.length() > 69) {
        connection = connection.substr(0, 66) + "...";
    }
    
    std::string color = getProtocolColor(protocol);
    
    std::cout << "║ " << std::setw(6) << std::right << count
              << " ║ " << std::setw(15) << std::left << time_str
              << " ║ " << color << std::setw(5) << std::left << protocol << resetColor()
              << " ║ " << std::setw(69) << std::left << connection
              << " ║ " << std::setw(7) << std::right << size_str << " ║\n";
    std::cout << std::flush;
}

// ==================== THÊM: Display Storage Statistics ====================
void displayStorageStats(const StorageStatsSnapshot& stats) {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                        📁 STORAGE STATISTICS                                           ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Packets Saved : " << std::setw(77) << std::left << stats.total_packets << "║\n";
    std::cout << "║ Total Bytes Saved   : " << std::setw(77) << std::left << formatBytes(stats.total_bytes) << "║\n";
    std::cout << "║ Files Created       : " << std::setw(77) << std::left << stats.files_created << "║\n";
    std::cout << "║ Write Errors        : " << std::setw(77) << std::left << stats.write_errors << "║\n";
    
    char rate_buf[80];
    snprintf(rate_buf, sizeof(rate_buf), "%.2f pps", stats.getWriteRate());
    std::cout << "║ Write Rate          : " << std::setw(77) << std::left << rate_buf << "║\n";
    
    snprintf(rate_buf, sizeof(rate_buf), "%.2f Mbps", stats.getThroughputMbps());
    std::cout << "║ Throughput          : " << std::setw(77) << std::left << rate_buf << "║\n";
    
    if (!stats.current_file.empty()) {
        std::cout << "║ Current File        : " << std::setw(77) << std::left << stats.current_file << "║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::flush;
}

// ==================== Main ====================
int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Setup logging
    auto console = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::info);
    
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                              🔍 Network Packet Capture & Storage Test                                 ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    // ==================== Cấu hình Ingress ====================
    IngressConfig ingress_config;
    
    if (argc > 1) {
        ingress_config.interface = argv[1];
    } else {
        ingress_config.interface = "wlan0";
    }
    
    ingress_config.snaplen = 65535;
    ingress_config.buffer_size = 32;
    ingress_config.timeout_ms = 1000;
    ingress_config.promiscuous = true;
    ingress_config.enable_timestamp = true;
    
    if (argc > 2) {
        ingress_config.bpf_filter = argv[2];
    }
    
    // ==================== THÊM: Cấu hình Storage ====================
    StorageConfig storage_config;
    storage_config.output_dir = "./data";
    storage_config.enable_rotation = true;
    storage_config.max_file_size_mb = 50;
    storage_config.max_file_duration_sec = 300;  // 5 phút
    storage_config.datalink_type = DLT_EN10MB;
    storage_config.file_prefix = "capture";
    
    std::cout << "\n📋 Configuration:\n";
    std::cout << "  Interface        : " << ingress_config.interface << "\n";
    std::cout << "  Snaplen          : " << ingress_config.snaplen << " bytes\n";
    std::cout << "  Buffer Size      : " << ingress_config.buffer_size << " MB\n";
    std::cout << "  Promiscuous Mode : " << (ingress_config.promiscuous ? "Yes" : "No") << "\n";
    std::cout << "  BPF Filter       : " << (ingress_config.bpf_filter.empty() ? "None" : ingress_config.bpf_filter) << "\n";
    std::cout << "  Output Directory : " << storage_config.output_dir << "\n";
    std::cout << "  Max File Size    : " << storage_config.max_file_size_mb << " MB\n";
    std::cout << "  Max File Duration: " << storage_config.max_file_duration_sec << " seconds\n";
    std::cout << "\n";
    
    // ==================== THÊM: Khởi tạo Storage ====================
    g_storage = std::make_unique<PacketStorage>(storage_config);
    if (!g_storage->initialize()) {
        spdlog::error("❌ Failed to initialize storage!");
        return 1;
    }
    spdlog::info("✅ Storage initialized");
    
    // ==================== Khởi tạo Ingress ====================
    g_ingress = std::make_unique<PacketIngress>(ingress_config);
    
    if (!g_ingress->start()) {
        spdlog::error("❌ Failed to start packet capture!");
        return 1;
    }
    
    spdlog::info("✅ Packet capture started on interface: {}", ingress_config.interface);
    
    // ==================== Packet Callback ====================
    bool compact_mode = true;  // Compact mode by default
    
    if (argc > 3 && std::string(argv[3]) == "--detailed") {
        compact_mode = false;
    }
    
    if (compact_mode) {
        displayHeader();
    }
    
    g_ingress->setPacketCallback([&](const ParsedPacket& packet) {
        // ← THÊM: Lưu packet vào storage
        if (!g_storage->savePacket(packet)) {
            spdlog::warn("⚠️  Failed to save packet to storage");
        }
        
        // Display packet
        if (compact_mode) {
            displayPacketCompact(packet);
        }
    });
    
    std::cout << "\n🚀 Capturing packets... Press Ctrl+C to stop\n";
    std::cout << "💾 PCAP files will be saved to: " << storage_config.output_dir << "\n\n";
    
    // ==================== Main Loop ====================
    auto last_stats_time = std::chrono::steady_clock::now();
    const int stats_interval_sec = 10;  // Hiển thị stats mỗi 10 giây
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();
        
        if (elapsed >= stats_interval_sec) {
            if (compact_mode) {
                displayFooter();
            }
            
            // Ingress stats
            auto ingress_stats = g_ingress->getStats();
            std::cout << "\n";
            std::cout << "╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                                        📊 CAPTURE STATISTICS                                           ║\n";
            std::cout << "╠════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
            std::cout << "║ Packets Received    : " << std::setw(77) << std::left << ingress_stats.packets_received << "║\n";
            std::cout << "║ Packets Dropped     : " << std::setw(77) << std::left << ingress_stats.packets_dropped << "║\n";
            std::cout << "║ Bytes Received      : " << std::setw(77) << std::left << formatBytes(ingress_stats.bytes_received) << "║\n";
            
            char rate_buf[80];
            snprintf(rate_buf, sizeof(rate_buf), "%.2f pps", ingress_stats.capture_rate);
            std::cout << "║ Capture Rate        : " << std::setw(77) << std::left << rate_buf << "║\n";
            std::cout << "║ Errors              : " << std::setw(77) << std::left << ingress_stats.errors << "║\n";
            std::cout << "╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
            
            // ← THÊM: Storage stats
            auto storage_stats = g_storage->getStats();
            displayStorageStats(storage_stats);
            
            if (compact_mode) {
                displayHeader();
            }
            
            last_stats_time = now;
        }
    }
    
    // ==================== Cleanup ====================
    if (compact_mode) {
        displayFooter();
    }
    
    std::cout << "\n🛑 Stopping capture...\n";
    
    g_ingress->stop();
    
    // ← THÊM: Đóng storage
    g_storage->flush();
    g_storage->close();
    
    // Final stats
    auto final_ingress_stats = g_ingress->getStats();
    auto final_storage_stats = g_storage->getStats();
    
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                        📈 FINAL STATISTICS                                             ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Packets Captured : " << std::setw(74) << std::left << final_ingress_stats.packets_received << "║\n";
    std::cout << "║ Total Packets Saved    : " << std::setw(74) << std::left << final_storage_stats.total_packets << "║\n";
    std::cout << "║ Total Bytes Saved      : " << std::setw(74) << std::left << formatBytes(final_storage_stats.total_bytes) << "║\n";
    std::cout << "║ Files Created          : " << std::setw(74) << std::left << final_storage_stats.files_created << "║\n";
    std::cout << "║ Packets Dropped        : " << std::setw(74) << std::left << final_ingress_stats.packets_dropped << "║\n";
    std::cout << "║ Write Errors           : " << std::setw(74) << std::left << final_storage_stats.write_errors << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    std::cout << "\n✅ Capture completed successfully!\n";
    std::cout << "💾 PCAP files saved in: " << storage_config.output_dir << "\n\n";
    
    return 0;
}
