// interfaces/cli/packet_capture_cli.cpp (OPTIMIZED VERSION)
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/common/packet_parser.hpp"
#include "../../src/common/network_utils.hpp"
#include "../../src/common/utils.hpp"

#include <iostream>
#include <iomanip>
#include <signal.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <fstream>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <condition_variable>

using namespace NetworkSecurity;

// Global variables for signal handling
std::atomic<bool> g_running{true};
Layer1::PacketIngress* g_ingress = nullptr;

// Packet logging with buffer
struct PacketLog {
    uint64_t packet_num;
    uint64_t timestamp;
    size_t length;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    uint16_t src_port;
    uint16_t dst_port;
};

std::queue<PacketLog> g_log_queue;
std::mutex g_log_mutex;
std::condition_variable g_log_cv;
std::atomic<bool> g_logging_enabled{false};
std::thread g_log_thread;

// Statistics
std::atomic<uint64_t> g_packet_count{0};
std::atomic<uint64_t> g_tcp_count{0};
std::atomic<uint64_t> g_udp_count{0};
std::atomic<uint64_t> g_icmp_count{0};
std::atomic<uint64_t> g_other_count{0};

// Display mode
enum class DisplayMode {
    STATS_ONLY,      // Chỉ hiển thị thống kê
    PACKET_SUMMARY,  // Hiển thị tóm tắt packet
    FULL_DETAILS     // Hiển thị chi tiết đầy đủ
};

DisplayMode g_display_mode = DisplayMode::STATS_ONLY;

// Signal handler
void signalHandler(int signum) {
    std::cout << "\n\n[!] Received signal " << signum << ", shutting down gracefully...\n";
    g_running = false;
    g_logging_enabled = false;
    g_log_cv.notify_all();
    
    if (g_ingress) {
        g_ingress->stop();
    }
}

// ANSI color codes
namespace Color {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string BOLD = "\033[1m";
}

// Print banner
void printBanner() {
    std::cout << Color::CYAN << Color::BOLD;
    std::cout << R"(
╔═══════════════════════════════════════════════════════════╗
║   ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗   ║
║   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝   ║
║   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║        ║
║   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║        ║
║   ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗   ║
║         Network Security AI - Packet Capture CLI         ║
║                     Version 1.0.0                         ║
╚═══════════════════════════════════════════════════════════╝
)" << Color::RESET << "\n";
}

// List available network interfaces
std::vector<std::string> listInterfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << Color::RED << "[ERROR] " << errbuf << Color::RESET << "\n";
        return interfaces;
    }
    
    std::cout << Color::YELLOW << "\n[+] Available Network Interfaces:\n" << Color::RESET;
    std::cout << std::string(60, '=') << "\n";
    
    int index = 1;
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        interfaces.push_back(dev->name);
        
        std::cout << Color::GREEN << "[" << index << "] " << Color::RESET;
        std::cout << Color::BOLD << dev->name << Color::RESET << "\n";
        
        if (dev->description) {
            std::cout << "    Description: " << dev->description << "\n";
        }
        
        // Print addresses
        for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in* addr_in = (struct sockaddr_in*)addr->addr;
                inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
                std::cout << "    IPv4: " << Color::CYAN << ip << Color::RESET << "\n";
            }
        }
        
        std::cout << "\n";
        index++;
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

// Select interface
std::string selectInterface() {
    auto interfaces = listInterfaces();
    
    if (interfaces.empty()) {
        std::cerr << Color::RED << "[ERROR] No interfaces found!\n" << Color::RESET;
        return "";
    }
    
    std::cout << Color::YELLOW << "Select interface (1-" << interfaces.size() << "): " << Color::RESET;
    int choice;
    std::cin >> choice;
    
    if (choice < 1 || choice > static_cast<int>(interfaces.size())) {
        std::cerr << Color::RED << "[ERROR] Invalid choice!\n" << Color::RESET;
        return "";
    }
    
    return interfaces[choice - 1];
}

// Get BPF filter from user
std::string getBPFFilter() {
    std::cout << Color::YELLOW << "\n[?] Enter BPF filter (press Enter for none): " << Color::RESET;
    std::cin.ignore();
    std::string filter;
    std::getline(std::cin, filter);
    return filter;
}

// Select display mode
DisplayMode selectDisplayMode() {
    std::cout << Color::YELLOW << "\n[?] Select display mode:\n" << Color::RESET;
    std::cout << "  [1] Statistics only (Low CPU/RAM)\n";
    std::cout << "  [2] Packet summary (Medium CPU/RAM)\n";
    std::cout << "  [3] Full details (High CPU/RAM)\n";
    std::cout << Color::YELLOW << "Choice (1-3): " << Color::RESET;
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 2: return DisplayMode::PACKET_SUMMARY;
        case 3: return DisplayMode::FULL_DETAILS;
        default: return DisplayMode::STATS_ONLY;
    }
}

// Logging thread function
void loggingThread(const std::string& filename) {
    std::ofstream log_file(filename);
    if (!log_file.is_open()) {
        std::cerr << Color::RED << "[ERROR] Failed to open log file!\n" << Color::RESET;
        return;
    }
    
    log_file << "# Packet Capture Log\n";
    log_file << "# Format: PacketNum, Timestamp, Length, SrcIP, DstIP, Protocol, SrcPort, DstPort\n\n";
    
    size_t batch_count = 0;
    const size_t BATCH_SIZE = 100; // Ghi batch để tối ưu I/O
    
    while (g_logging_enabled || !g_log_queue.empty()) {
        std::unique_lock<std::mutex> lock(g_log_mutex);
        
        // Đợi có data hoặc shutdown
        g_log_cv.wait_for(lock, std::chrono::milliseconds(100), [] {
            return !g_log_queue.empty() || !g_logging_enabled;
        });
        
        // Process batch
        while (!g_log_queue.empty() && batch_count < BATCH_SIZE) {
            PacketLog log = g_log_queue.front();
            g_log_queue.pop();
            
            log_file << log.packet_num << ","
                    << log.timestamp << ","
                    << log.length << ","
                    << log.src_ip << ","
                    << log.dst_ip << ","
                    << log.protocol << ","
                    << log.src_port << ","
                    << log.dst_port << "\n";
            
            batch_count++;
        }
        
        // Flush batch
        if (batch_count >= BATCH_SIZE) {
            log_file.flush();
            batch_count = 0;
        }
    }
    
    log_file.close();
}

// Packet callback (OPTIMIZED)
Common::PacketParser g_parser;

void packetCallback(const uint8_t* data, size_t length, uint64_t timestamp) {
    g_packet_count++;
    
    // Parse packet
    Common::ParsedPacket parsed;
    if (!g_parser.parsePacket(data, length, parsed)) {
        g_other_count++;
        return;
    }
    
    // Update protocol stats
    if (parsed.has_tcp) {
        g_tcp_count++;
    } else if (parsed.has_udp) {
        g_udp_count++;
    } else if (parsed.has_icmp) {
        g_icmp_count++;
    } else {
        g_other_count++;
    }
    
    // Display based on mode
    if (g_display_mode == DisplayMode::PACKET_SUMMARY) {
        // Chỉ hiển thị mỗi 100 packets
        if (g_packet_count % 100 == 0) {
            std::cout << Color::GREEN << "#" << g_packet_count << Color::RESET << " ";
            
            if (parsed.has_ipv4) {
                std::cout << Common::NetworkUtils::ipIntToString(parsed.ipv4.src_ip) 
                         << " -> " 
                         << Common::NetworkUtils::ipIntToString(parsed.ipv4.dst_ip);
            }
            
            if (parsed.has_tcp) {
                std::cout << " TCP:" << parsed.tcp.src_port << "->" << parsed.tcp.dst_port;
            } else if (parsed.has_udp) {
                std::cout << " UDP:" << parsed.udp.src_port << "->" << parsed.udp.dst_port;
            }
            
            std::cout << " (" << length << " bytes)\n";
        }
    } else if (g_display_mode == DisplayMode::FULL_DETAILS) {
        // Chỉ hiển thị mỗi 50 packets
        if (g_packet_count % 50 == 0) {
            std::cout << Color::CYAN << "\n=== Packet #" << g_packet_count << " ===" << Color::RESET << "\n";
            std::cout << "Timestamp: " << timestamp << "\n";
            std::cout << "Length: " << length << " bytes\n";
            
            if (parsed.has_ipv4) {
                std::cout << "Src IP: " << Common::NetworkUtils::ipIntToString(parsed.ipv4.src_ip) << "\n";
                std::cout << "Dst IP: " << Common::NetworkUtils::ipIntToString(parsed.ipv4.dst_ip) << "\n";
            }
            
            if (parsed.has_tcp) {
                std::cout << "Protocol: TCP\n";
                std::cout << "Src Port: " << parsed.tcp.src_port << "\n";
                std::cout << "Dst Port: " << parsed.tcp.dst_port << "\n";
            } else if (parsed.has_udp) {
                std::cout << "Protocol: UDP\n";
                std::cout << "Src Port: " << parsed.udp.src_port << "\n";
                std::cout << "Dst Port: " << parsed.udp.dst_port << "\n";
            }
        }
    }
    
    // Log to file (with queue to avoid blocking)
    if (g_logging_enabled && g_log_queue.size() < 10000) { // Limit queue size
        PacketLog log;
        log.packet_num = g_packet_count;
        log.timestamp = timestamp;
        log.length = length;
        
        if (parsed.has_ipv4) {
            log.src_ip = Common::NetworkUtils::ipIntToString(parsed.ipv4.src_ip);
            log.dst_ip = Common::NetworkUtils::ipIntToString(parsed.ipv4.dst_ip);
        }
        
        if (parsed.has_tcp) {
            log.protocol = "TCP";
            log.src_port = parsed.tcp.src_port;
            log.dst_port = parsed.tcp.dst_port;
        } else if (parsed.has_udp) {
            log.protocol = "UDP";
            log.src_port = parsed.udp.src_port;
            log.dst_port = parsed.udp.dst_port;
        } else {
            log.protocol = "OTHER";
            log.src_port = 0;
            log.dst_port = 0;
        }
        
        std::lock_guard<std::mutex> lock(g_log_mutex);
        g_log_queue.push(log);
        g_log_cv.notify_one();
    }
}

// Display statistics
void displayStats(const Layer1::PacketIngress& ingress) {
    std::cout << "\n" << Color::CYAN << "Press Ctrl+C to stop capture..." << Color::RESET << "\n\n";
    
    auto start_time = std::chrono::steady_clock::now();
    
    while (g_running) {
        auto stats = ingress.getStats();
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        // Clear screen (ANSI escape code)
        std::cout << "\033[2J\033[1;1H";
        
        // Display stats
        std::cout << Color::BOLD << Color::GREEN;
        std::cout << "╔════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PACKET CAPTURE STATISTICS                     ║\n";
        std::cout << "╠════════════════════════════════════════════════════════════╣\n";
        std::cout << Color::RESET;
        
        std::cout << Color::YELLOW << "  Packets Received:  " << Color::RESET 
                  << Color::BOLD << std::setw(15) << stats.packets_received << Color::RESET << "\n";
        
        std::cout << Color::YELLOW << "  Packets Dropped:   " << Color::RESET 
                  << Color::BOLD << std::setw(15) << stats.packets_dropped << Color::RESET << "\n";
        
        std::cout << Color::YELLOW << "  Bytes Received:    " << Color::RESET 
                  << Color::BOLD << std::setw(15) << Common::Utils::formatBytes(stats.bytes_received) << Color::RESET << "\n";
        
        std::cout << Color::YELLOW << "  Capture Rate:      " << Color::RESET 
                  << Color::BOLD << std::setw(15) << std::fixed << std::setprecision(2) 
                  << stats.capture_rate << " pps" << Color::RESET << "\n";
        
        std::cout << Color::YELLOW << "  Uptime:            " << Color::RESET 
                  << Color::BOLD << std::setw(15) << uptime << "s" << Color::RESET << "\n";
        
        std::cout << Color::GREEN;
        std::cout << "╠════════════════════════════════════════════════════════════╣\n";
        std::cout << "║              PROTOCOL DISTRIBUTION                         ║\n";
        std::cout << "╠════════════════════════════════════════════════════════════╣\n";
        std::cout << Color::RESET;
        
        uint64_t total = g_packet_count.load();
        if (total > 0) {
            std::cout << Color::CYAN << "  TCP:    " << Color::RESET 
                     << std::setw(10) << g_tcp_count.load() 
                     << " (" << std::fixed << std::setprecision(1) 
                     << (g_tcp_count.load() * 100.0 / total) << "%)\n";
            
            std::cout << Color::CYAN << "  UDP:    " << Color::RESET 
                     << std::setw(10) << g_udp_count.load() 
                     << " (" << std::fixed << std::setprecision(1) 
                     << (g_udp_count.load() * 100.0 / total) << "%)\n";
            
            std::cout << Color::CYAN << "  ICMP:   " << Color::RESET 
                     << std::setw(10) << g_icmp_count.load() 
                     << " (" << std::fixed << std::setprecision(1) 
                     << (g_icmp_count.load() * 100.0 / total) << "%)\n";
            
            std::cout << Color::CYAN << "  Other:  " << Color::RESET 
                     << std::setw(10) << g_other_count.load() 
                     << " (" << std::fixed << std::setprecision(1) 
                     << (g_other_count.load() * 100.0 / total) << "%)\n";
        }
        
        std::cout << Color::GREEN;
        std::cout << "╚════════════════════════════════════════════════════════════╝\n";
        std::cout << Color::RESET;
        
        if (g_logging_enabled) {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << Color::MAGENTA << "\n[LOG] Queue size: " << g_log_queue.size() << Color::RESET << "\n";
        }
        
        std::cout << Color::CYAN << "\nPress Ctrl+C to stop...\n" << Color::RESET;
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Main function
int main(int, char* argv[]) {
    // Check root privileges
    if (geteuid() != 0) {
        std::cerr << Color::RED << "[ERROR] This program requires root privileges!\n" << Color::RESET;
        std::cerr << "Please run with: sudo " << argv[0] << "\n";
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Print banner
    printBanner();
    
    // Select interface
    std::string interface = selectInterface();
    if (interface.empty()) {
        return 1;
    }
    
    std::cout << Color::GREEN << "\n[+] Selected interface: " << Color::BOLD << interface << Color::RESET << "\n";
    
    // Get BPF filter
    std::string filter = getBPFFilter();
    if (!filter.empty()) {
        std::cout << Color::GREEN << "[+] BPF Filter: " << Color::BOLD << filter << Color::RESET << "\n";
    }
    
    // Select display mode
    g_display_mode = selectDisplayMode();
    
    // Ask if want to log packets
    std::cout << Color::YELLOW << "\n[?] Save packets to log file? (y/n): " << Color::RESET;
    char log_choice;
    std::cin >> log_choice;
    
    std::string log_filename;
    if (log_choice == 'y' || log_choice == 'Y') {
        log_filename = "packets_" + std::to_string(time(nullptr)) + ".csv";
        g_logging_enabled = true;
        g_log_thread = std::thread(loggingThread, log_filename);
        std::cout << Color::GREEN << "[+] Logging packets to: " << log_filename << Color::RESET << "\n";
    }
    
    // Initialize PacketIngress
    Layer1::PacketIngress ingress;
    g_ingress = &ingress;
    
    std::cout << Color::YELLOW << "\n[*] Initializing packet capture...\n" << Color::RESET;
    
    if (!ingress.initialize(interface, filter)) {
        std::cerr << Color::RED << "[ERROR] Failed to initialize packet capture!\n" << Color::RESET;
        return 1;
    }
    
    // Register callback
    ingress.registerCallback(packetCallback);
    
    // Start capture
    std::cout << Color::GREEN << "[+] Starting packet capture...\n" << Color::RESET;
    
    if (!ingress.start()) {
        std::cerr << Color::RED << "[ERROR] Failed to start packet capture!\n" << Color::RESET;
        return 1;
    }
    
    // Display statistics
    displayStats(ingress);
    
    // Cleanup
    std::cout << Color::YELLOW << "\n[*] Stopping capture...\n" << Color::RESET;
    ingress.stop();
    
    if (g_logging_enabled) {
        g_logging_enabled = false;
        g_log_cv.notify_all();
        if (g_log_thread.joinable()) {
            g_log_thread.join();
        }
    }
    
    // Final statistics
    auto final_stats = ingress.getStats();
    std::cout << Color::GREEN << "\n[+] Capture Summary:\n" << Color::RESET;
    std::cout << "  Total Packets: " << final_stats.packets_received << "\n";
    std::cout << "  Total Bytes: " << Common::Utils::formatBytes(final_stats.bytes_received) << "\n";
    std::cout << "  Packets Dropped: " << final_stats.packets_dropped << "\n";
    std::cout << "  TCP: " << g_tcp_count << " | UDP: " << g_udp_count 
              << " | ICMP: " << g_icmp_count << " | Other: " << g_other_count << "\n";
    
    if (!log_filename.empty()) {
        std::cout << Color::GREEN << "  Log file: " << log_filename << Color::RESET << "\n";
    }
    
    std::cout << Color::GREEN << "\n[+] Shutdown complete. Goodbye!\n" << Color::RESET;
    
    return 0;
}
