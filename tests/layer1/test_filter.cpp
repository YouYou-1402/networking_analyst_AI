// tests/layer1/test_packet_filter.cpp

#include "../../src/core/layer1/packet_filter.hpp"
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/common/packet_parser.hpp"
#include "../../src/common/utils.hpp"
#include "string.h"
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
std::unique_ptr<AdvancedFilterManager> g_filter_manager;
std::atomic<uint64_t> g_total_packets(0);
std::atomic<uint64_t> g_matched_packets(0);
std::atomic<uint64_t> g_filtered_packets(0);

// ==================== Signal Handler ====================
void signalHandler(int signum) {
    std::cout << "\n\n🛑 Received signal " << signum << ", stopping capture...\n" << std::endl;
    g_running.store(false);
    if (g_ingress) {
        g_ingress->stop();
    }
}

// ==================== Helper Functions ====================

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
              << " ║ " << std::setw(6) << "Match" << " ║\n";
    std::cout << "╠════════╬═════════════════╬═══════╬═══════════════════════════════════════════════════════════╬═════════╬════════╣\n";
    std::cout << std::flush;
}

void displayFooter() {
    std::cout << "╚════════╩═════════════════╩═══════╩═══════════════════════════════════════════════════════════╩═════════╩════════╝\n";
    std::cout << std::flush;
}

void displayPacketCompact(const ParsedPacket& packet, bool matched) {
    uint64_t count = g_total_packets.fetch_add(1) + 1;
    
    if (matched) {
        g_matched_packets.fetch_add(1);
    } else {
        g_filtered_packets.fetch_add(1);
    }
    
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
    std::string status = matched ? "✓ YES" : "✗ NO";
    std::string status_color = matched ? "\033[1;32m" : "\033[1;31m";
    
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

// ==================== Filter Test Functions ====================

void testBasicFilters() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║              TESTING BASIC FILTER SYNTAX                      ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    std::vector<std::string> test_filters = {
        "tcp",
        "udp",
        "icmp",
        "arp",
        "ip",
        "ipv6",
        "tcp.port == 80",
        "tcp.port == 443",
        "udp.port == 53",
        "ip.src == 192.168.1.1",
        "ip.dst == 8.8.8.8",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "frame.len > 1000",
        "tcp && ip.src == 192.168.1.1",
        "udp || icmp",
        "tcp.port == 80 || tcp.port == 443",
        "ip.addr == 192.168.1.0/24",
        "!arp",
        "tcp.flags.syn && !tcp.flags.ack"
    };
    
    std::string error_msg;
    int passed = 0;
    int failed = 0;
    
    for (const auto& filter : test_filters) {
        bool valid = g_filter_manager->validateFilter(filter, error_msg);
        
        if (valid) {
            std::cout << "✓ PASS: " << filter << "\n";
            passed++;
        } else {
            std::cout << "✗ FAIL: " << filter << " - " << error_msg << "\n";
            failed++;
        }
    }
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║ Total: " << std::setw(3) << (passed + failed) 
              << " | Passed: " << std::setw(3) << passed 
              << " | Failed: " << std::setw(3) << failed << "                      ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
}

void testInvalidFilters() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           TESTING INVALID FILTER DETECTION                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    std::vector<std::string> invalid_filters = {
        "tcp.port",                    // Missing operator
        "tcp.port == ",                // Missing value
        "unknown.field == 123",        // Unknown field
        "tcp.port === 80",             // Invalid operator
        "tcp.port == abc",             // Invalid value for numeric field
        "ip.src == 999.999.999.999",   // Invalid IP
        "tcp && ",                     // Incomplete expression
        "(tcp.port == 80",             // Unmatched parenthesis
        "tcp.port == 80)",             // Unmatched parenthesis
        "tcp.port == 80 &&& udp"       // Invalid operator
    };
    
    std::string error_msg;
    int detected = 0;
    
    for (const auto& filter : invalid_filters) {
        bool valid = g_filter_manager->validateFilter(filter, error_msg);
        
        if (!valid) {
            std::cout << "✓ Correctly rejected: " << filter << "\n";
            std::cout << "  Error: " << error_msg << "\n\n";
            detected++;
        } else {
            std::cout << "✗ Should have rejected: " << filter << "\n\n";
        }
    }
    
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║ Detected: " << std::setw(3) << detected 
              << " / " << std::setw(3) << invalid_filters.size() << "                                          ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
}

void displayPresets() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                      AVAILABLE FILTER PRESETS                                         ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n";
    
    auto presets = g_filter_manager->getPresets();
    
    std::string current_category;
    for (const auto& preset : presets) {
        if (preset.category != current_category) {
            current_category = preset.category;
            std::cout << "\n┌─ " << current_category << " ─────────────────────────────────────────────────────────\n";
        }
        
        std::cout << "│ " << std::setw(20) << std::left << preset.name 
                  << " : " << preset.filter << "\n";
        std::cout << "│ " << std::setw(20) << " " 
                  << "   " << preset.description << "\n";
    }
    
    std::cout << "└────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n";
}

void displayFilterSuggestions() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  FILTER AUTO-COMPLETION TEST                  ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    std::vector<std::string> partials = {"tcp", "ip.", "eth.", "udp.p", "icmp."};
    
    for (const auto& partial : partials) {
        auto suggestions = FilterSuggestions::getFieldSuggestions(partial);
        
        std::cout << "Input: \"" << partial << "\" → Suggestions:\n";
        for (size_t i = 0; i < std::min(suggestions.size(), size_t(5)); ++i) {
            std::cout << "  • " << suggestions[i] << "\n";
        }
        if (suggestions.size() > 5) {
            std::cout << "  ... and " << (suggestions.size() - 5) << " more\n";
        }
        std::cout << "\n";
    }
}

void displayFilterBuilder() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    FILTER BUILDER TEST                        ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    // Test 1: Simple HTTP filter
    FilterBuilder builder1;
    std::string filter1 = builder1.tcpPort(80).build();
    std::cout << "HTTP Filter: " << filter1 << "\n";
    
    // Test 2: HTTP or HTTPS
    FilterBuilder builder2;
    std::string filter2 = builder2.tcpPort(80).or_().tcpPort(443).build();
    std::cout << "HTTP/HTTPS Filter: " << filter2 << "\n";
    
    // Test 3: Specific IP and port
    FilterBuilder builder3;
    std::string filter3 = builder3.ipSrc("192.168.1.100").and_().tcpDstPort(22).build();
    std::cout << "SSH from specific IP: " << filter3 << "\n";
    
    // Test 4: Complex filter with groups
    FilterBuilder builder4;
    std::string filter4 = builder4.beginGroup()
                                   .tcpPort(80).or_().tcpPort(443)
                                   .endGroup()
                                   .and_()
                                   .ipAddr("192.168.1.0/24")
                                   .build();
    std::cout << "Web traffic from subnet: " << filter4 << "\n";
    
    // Test 5: TCP SYN packets
    FilterBuilder builder5;
    std::string filter5 = builder5.tcpSyn().and_().not_().tcpAck().build();
    std::cout << "TCP SYN (no ACK): " << filter5 << "\n";
    
    std::cout << "\n";
}

// ==================== Packet Callback ====================

void packetCallback(const ParsedPacket& packet) {
    // Check if packet matches filter
    bool matched = g_filter_manager->matchesDisplayFilter(packet);
    
    // Only display matched packets
    if (matched) {
        displayPacketCompact(packet, matched);
    }
}

// ==================== Interactive Menu ====================

void displayMenu() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    FILTER CONTROL MENU                        ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ 1. Set custom filter                                          ║\n";
    std::cout << "║ 2. Apply preset filter                                        ║\n";
    std::cout << "║ 3. Clear filter (show all)                                    ║\n";
    std::cout << "║ 4. Show current filter                                        ║\n";
    std::cout << "║ 5. Show statistics                                            ║\n";
    std::cout << "║ 6. Show filter history                                        ║\n";
    std::cout << "║ 7. Test filter syntax                                         ║\n";
    std::cout << "║ 0. Exit                                                       ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    std::cout << "Choice: ";
}

void interactiveMode() {
    while (g_running.load()) {
        displayMenu();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::cout << "Enter filter expression: ";
                std::string filter;
                std::getline(std::cin, filter);
                
                if (g_filter_manager->setDisplayFilter(filter)) {
                    std::cout << "✓ Filter applied successfully\n";
                    g_total_packets.store(0);
                    g_matched_packets.store(0);
                    g_filtered_packets.store(0);
                } else {
                    std::cout << "✗ Invalid filter\n";
                }
                break;
            }
            
            case 2: {
                displayPresets();
                std::cout << "\nEnter preset name: ";
                std::string preset_name;
                std::getline(std::cin, preset_name);
                
                if (g_filter_manager->applyPreset(preset_name)) {
                    std::cout << "✓ Preset applied successfully\n";
                    g_total_packets.store(0);
                    g_matched_packets.store(0);
                    g_filtered_packets.store(0);
                } else {
                    std::cout << "✗ Preset not found\n";
                }
                break;
            }
            
            case 3: {
                g_filter_manager->clearDisplayFilter();
                std::cout << "✓ Filter cleared\n";
                g_total_packets.store(0);
                g_matched_packets.store(0);
                g_filtered_packets.store(0);
                break;
            }
            
            case 4: {
                auto stats = g_filter_manager->getStats();
                std::cout << "\nCurrent filter: " 
                          << (stats.current_filter.empty() ? "(none)" : stats.current_filter) 
                          << "\n";
                break;
            }
            
            case 5: {
                auto stats = g_filter_manager->getStats();
                std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
                std::cout << "║                    FILTER STATISTICS                          ║\n";
                std::cout << "╠═══════════════════════════════════════════════════════════════╣\n";
                std::cout << "║ Total Packets     : " << std::setw(42) << std::left << stats.total_packets << "║\n";
                std::cout << "║ Matched Packets   : " << std::setw(42) << std::left << stats.matched_packets << "║\n";
                std::cout << "║ Filtered Packets  : " << std::setw(42) << std::left << stats.filtered_packets << "║\n";
                
                char rate_buf[50];
                snprintf(rate_buf, sizeof(rate_buf), "%.2f%%", stats.match_rate);
                std::cout << "║ Match Rate        : " << std::setw(42) << std::left << rate_buf << "║\n";
                std::cout << "║ Current Filter    : " << std::setw(42) << std::left 
                          << (stats.current_filter.empty() ? "(none)" : stats.current_filter.substr(0, 42)) << "║\n";
                std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
                break;
            }
            
            case 6: {
                auto history = g_filter_manager->getHistory().getHistory();
                std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
                std::cout << "║                     FILTER HISTORY                            ║\n";
                std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
                
                if (history.empty()) {
                    std::cout << "No filter history\n";
                } else {
                    for (size_t i = 0; i < history.size(); ++i) {
                        std::cout << std::setw(3) << (i + 1) << ". " << history[i] << "\n";
                    }
                }
                break;
            }
            
            case 7: {
                testBasicFilters();
                testInvalidFilters();
                displayFilterSuggestions();
                displayFilterBuilder();
                break;
            }
            
            case 0: {
                g_running.store(false);
                if (g_ingress) {
                    g_ingress->stop();
                }
                return;
            }
            
            default:
                std::cout << "Invalid choice\n";
                break;
        }
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
    std::string initial_filter = "";
    bool run_tests = false;
    bool interactive = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                interface = argv[++i];
            }
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) {
                initial_filter = argv[++i];
            }
        } else if (arg == "-t" || arg == "--test") {
            run_tests = true;
        } else if (arg == "--interactive") {
            interactive = true;
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n";
            std::cout << "Options:\n";
            std::cout << "  -i, --interface <name>   Network interface (default: wlan0)\n";
            std::cout << "  -f, --filter <expr>      Initial filter expression\n";
            std::cout << "  -t, --test               Run filter syntax tests\n";
            std::cout << "  --interactive            Interactive mode with menu\n";
            std::cout << "  -h, --help               Show this help\n";
            return 0;
        }
    }
    
    // Print banner
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                  PACKET FILTER TEST PROGRAM                                           ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Interface         : " << std::setw(78) << std::left << interface << "║\n";
    std::cout << "║ Initial Filter    : " << std::setw(78) << std::left << (initial_filter.empty() ? "(none)" : initial_filter) << "║\n";
    std::cout << "║ Mode              : " << std::setw(78) << std::left << (interactive ? "Interactive" : "Capture") << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::flush;
    
    // Create filter manager
    g_filter_manager = std::make_unique<AdvancedFilterManager>();
    
    // Run tests if requested
    if (run_tests) {
        testBasicFilters();
        testInvalidFilters();
        displayPresets();
        displayFilterSuggestions();
        displayFilterBuilder();
        
        std::cout << "\nPress Enter to continue to capture mode...";
        std::cin.get();
    }
    
    // Set initial filter
    if (!initial_filter.empty()) {
        if (!g_filter_manager->setDisplayFilter(initial_filter)) {
            spdlog::error("Invalid initial filter");
            return 1;
        }
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
    config.buffer_size = 16 * 1024 * 1024;  // 16 MB
    config.timeout_ms = 1000;
    config.promiscuous = true;
    config.enable_timestamp = true;
    
    // Create PacketIngress
    g_ingress = std::make_unique<PacketIngress>(config);
    
    // Initialize
    if (!g_ingress->initialize()) {
        spdlog::error("Failed to initialize packet ingress");
        return 1;
    }
    
    // Start capture in separate thread
    std::thread capture_thread([&]() {
        displayHeader();
        
        if (!g_ingress->start(packetCallback)) {
            spdlog::error("Failed to start packet capture");
            g_running.store(false);
        }
    });
    
    // Interactive mode or wait
    if (interactive) {
        interactiveMode();
    } else {
        // Wait for stop signal
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    // Wait for capture thread
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
    
    // Display footer
    displayFooter();
    
    // Get final stats
    auto filter_stats = g_filter_manager->getStats();
    auto ingress_stats = g_ingress->getStats();
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                      FINAL STATISTICS                                                 ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ FILTER                                                                                                ║\n";
    std::cout << "║   Current Filter    : " << std::setw(78) << std::left << filter_stats.current_filter << "║\n";
    std::cout << "║   Total Packets     : " << std::setw(78) << std::left << filter_stats.total_packets << "║\n";
    std::cout << "║   Matched Packets   : " << std::setw(78) << std::left << filter_stats.matched_packets << "║\n";
    std::cout << "║   Filtered Packets  : " << std::setw(78) << std::left << filter_stats.filtered_packets << "║\n";
    
    char rate_buf[80];
    snprintf(rate_buf, sizeof(rate_buf), "%.2f%%", filter_stats.match_rate);
    std::cout << "║   Match Rate        : " << std::setw(78) << std::left << rate_buf << "║\n";
    
    std::cout << "╟───────────────────────────────────────────────────────────────────────────────────────────────────────╢\n";
    std::cout << "║ INGRESS                                                                                               ║\n";
    std::cout << "║   Packets Received  : " << std::setw(78) << std::left << ingress_stats.packets_received << "║\n";
    std::cout << "║   Packets Dropped   : " << std::setw(78) << std::left << ingress_stats.packets_dropped << "║\n";
    std::cout << "║   Bytes Received    : " << std::setw(78) << std::left << formatBytes(ingress_stats.bytes_received) << "║\n";
    
    snprintf(rate_buf, sizeof(rate_buf), "%.2f packets/sec", ingress_stats.capture_rate);
    std::cout << "║   Capture Rate      : " << std::setw(78) << std::left << rate_buf << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    spdlog::info("Program terminated successfully");
    
    return 0;
}
