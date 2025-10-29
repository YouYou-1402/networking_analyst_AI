// tests/cli/test_packet_ingress_cli.cpp
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/common/packet_parser.hpp"
#include "../../src/common/logger.hpp"
#include "../../src/common/utils.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <atomic>
#include <map>
#include <algorithm>

using namespace NetworkSecurity::Core::Layer1;
using namespace NetworkSecurity::Common;

// ==================== Global Variables ====================

std::atomic<bool> g_running(true);
std::unique_ptr<PacketIngress> g_ingress;

// ==================== Signal Handler ====================

void signalHandler(int signum)
{
    std::cout << "\n\n[!] Received signal " << signum << ". Stopping...\n";
    g_running = false;
    if (g_ingress)
    {
        g_ingress->stop();
    }
}

// ==================== Helper Functions ====================

void clearScreen()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void printHeader()
{
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║         PACKET INGRESS CLI TEST TOOL v1.0                     ║\n";
    std::cout << "║         Network Security AI - Layer 1 Testing                 ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void printMenu()
{
    std::cout << "\n┌─────────────────────── MAIN MENU ───────────────────────┐\n";
    std::cout << "│                                                          │\n";
    std::cout << "│  1.  List Network Interfaces                             │\n";
    std::cout << "│  2.  Start Packet Capture                                │\n";
    std::cout << "│  3.  Stop Packet Capture                                 │\n";
    std::cout << "│  4.  Show Statistics                                     │\n";
    std::cout << "│  5.  Show Detailed Statistics                            │\n";
    std::cout << "│  6.  Add BPF Filter                                      │\n";
    std::cout << "│  7.  Clear BPF Filter                                    │\n";
    std::cout << "│  8.  Set Capture Mode (Promiscuous/Normal)               │\n";
    std::cout << "│  9.  Set Snapshot Length                                 │\n";
    std::cout << "│  10. Set Timeout                                         │\n";
    std::cout << "│  11. Read from PCAP File                                 │\n";
    std::cout << "│  12. Save to PCAP File                                   │\n";
    std::cout << "│  13. Live Monitor (Real-time)                            │\n";
    std::cout << "│  14. Show Top Talkers                                    │\n";
    std::cout << "│  15. Show Protocol Distribution                          │\n";
    std::cout << "│  16. Reset Statistics                                    │\n";
    std::cout << "│  17. Run Performance Test                                │\n";
    std::cout << "│  18. Show Configuration                                  │\n";
    std::cout << "│  0.  Exit                                                │\n";
    std::cout << "│                                                          │\n";
    std::cout << "└──────────────────────────────────────────────────────────┘\n";
    std::cout << "\nEnter your choice: ";
}

void printSeparator()
{
    std::cout << "────────────────────────────────────────────────────────────────\n";
}

// ==================== Feature Functions ====================

void listInterfaces()
{
    std::cout << "\n[*] Listing network interfaces...\n\n";
    
    auto interfaces = PacketIngress::openInterface("pcap_handle")-;
    
    if (interfaces.empty())
    {
        std::cout << "[!] No interfaces found!\n";
        return;
    }
    
    std::cout << "┌────┬─────────────────┬──────────────────────────────────────┐\n";
    std::cout << "│ No │ Interface       │ Description                          │\n";
    std::cout << "├────┼─────────────────┼──────────────────────────────────────┤\n";
    
    for (size_t i = 0; i < interfaces.size(); ++i)
    {
        std::cout << "│ " << std::setw(2) << (i + 1) << " │ "
                  << std::setw(15) << std::left << interfaces[i] << " │ "
                  << std::setw(36) << "Active" << " │\n";
    }
    
    std::cout << "└────┴─────────────────┴──────────────────────────────────────┘\n";
}

void startCapture()
{
    std::string interface;
    std::cout << "\n[*] Enter interface name (or 'any' for all): ";
    std::getline(std::cin, interface);
    
    if (interface.empty())
    {
        interface = "any";
    }
    
    std::cout << "[*] Starting capture on interface: " << interface << "\n";
    
    // Callback để xử lý packet
    auto callback = [](const uint8_t *data, size_t length, const PacketMetadata &metadata) {
        static std::atomic<uint64_t> packet_count(0);
        uint64_t count = ++packet_count;
        
        if (count % 100 == 0)
        {
            std::cout << "\r[*] Captured packets: " << count << std::flush;
        }
    };
    
    if (g_ingress->start(interface, callback))
    {
        std::cout << "[✓] Capture started successfully!\n";
        std::cout << "[*] Press Enter to return to menu...\n";
    }
    else
    {
        std::cout << "[✗] Failed to start capture!\n";
    }
}

void stopCapture()
{
    std::cout << "\n[*] Stopping capture...\n";
    g_ingress->stop();
    std::cout << "[✓] Capture stopped!\n";
}

void showStatistics()
{
    std::cout << "\n[*] Packet Statistics:\n\n";
    
    auto stats = g_ingress->getStatistics();
    
    std::cout << "┌─────────────────────────────────────────────────────────┐\n";
    std::cout << "│                    PACKET STATISTICS                    │\n";
    std::cout << "├─────────────────────────────────────────────────────────┤\n";
    std::cout << "│ Total Packets Received:  " << std::setw(30) << stats.packets_received << " │\n";
    std::cout << "│ Total Packets Dropped:   " << std::setw(30) << stats.packets_dropped << " │\n";
    std::cout << "│ Total Bytes Received:    " << std::setw(30) << stats.bytes_received << " │\n";
    std::cout << "│ IPv4 Packets:            " << std::setw(30) << stats.ipv4_packets << " │\n";
    std::cout << "│ IPv6 Packets:            " << std::setw(30) << stats.ipv6_packets << " │\n";
    std::cout << "│ TCP Packets:             " << std::setw(30) << stats.tcp_packets << " │\n";
    std::cout << "│ UDP Packets:             " << std::setw(30) << stats.udp_packets << " │\n";
    std::cout << "│ ICMP Packets:            " << std::setw(30) << stats.icmp_packets << " │\n";
    std::cout << "│ Other Packets:           " << std::setw(30) << stats.other_packets << " │\n";
    
    double drop_rate = stats.packets_received > 0 
        ? (static_cast<double>(stats.packets_dropped) / stats.packets_received * 100.0)
        : 0.0;
    
    std::cout << "│ Drop Rate:               " << std::setw(28) << std::fixed 
              << std::setprecision(2) << drop_rate << "% │\n";
    
    std::cout << "└─────────────────────────────────────────────────────────┘\n";
}

void showDetailedStatistics()
{
    std::cout << "\n[*] Detailed Statistics:\n\n";
    
    auto stats = g_ingress->getStatistics();
    
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║              DETAILED PACKET STATISTICS                   ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════╣\n";
    
    // Basic stats
    std::cout << "║ BASIC STATISTICS                                          ║\n";
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    std::cout << "║ Total Packets:       " << std::setw(36) << stats.packets_received << " ║\n";
    std::cout << "║ Total Bytes:         " << std::setw(36) << stats.bytes_received << " ║\n";
    std::cout << "║ Packets Dropped:     " << std::setw(36) << stats.packets_dropped << " ║\n";
    
    // Protocol distribution
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    std::cout << "║ PROTOCOL DISTRIBUTION                                     ║\n";
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    
    uint64_t total = stats.packets_received;
    if (total > 0)
    {
        auto printPercent = [total](const std::string &name, uint64_t count) {
            double percent = (static_cast<double>(count) / total) * 100.0;
            std::cout << "║ " << std::setw(20) << std::left << name << ": "
                      << std::setw(10) << std::right << count << " ("
                      << std::setw(6) << std::fixed << std::setprecision(2) << percent
                      << "%) ║\n";
        };
        
        printPercent("IPv4", stats.ipv4_packets);
        printPercent("IPv6", stats.ipv6_packets);
        printPercent("TCP", stats.tcp_packets);
        printPercent("UDP", stats.udp_packets);
        printPercent("ICMP", stats.icmp_packets);
        printPercent("Other", stats.other_packets);
    }
    
    // Performance metrics
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    std::cout << "║ PERFORMANCE METRICS                                       ║\n";
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    
    double drop_rate = total > 0 
        ? (static_cast<double>(stats.packets_dropped) / total * 100.0)
        : 0.0;
    
    std::cout << "║ Drop Rate:           " << std::setw(34) << std::fixed 
              << std::setprecision(4) << drop_rate << "% ║\n";
    
    if (total > 0)
    {
        double avg_size = static_cast<double>(stats.bytes_received) / total;
        std::cout << "║ Avg Packet Size:     " << std::setw(32) << std::fixed 
                  << std::setprecision(2) << avg_size << " bytes ║\n";
    }
    
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n";
}

void addBPFFilter()
{
    std::string filter;
    std::cout << "\n[*] Enter BPF filter expression: ";
    std::getline(std::cin, filter);
    
    if (filter.empty())
    {
        std::cout << "[!] Filter cannot be empty!\n";
        return;
    }
    
    std::cout << "[*] Setting filter: " << filter << "\n";
    
    if (g_ingress->setBPFFilter(filter))
    {
        std::cout << "[✓] Filter applied successfully!\n";
    }
    else
    {
        std::cout << "[✗] Failed to apply filter!\n";
    }
    
    std::cout << "\nCommon BPF filter examples:\n";
    std::cout << "  - tcp                    : Only TCP packets\n";
    std::cout << "  - udp port 53            : DNS traffic\n";
    std::cout << "  - host 192.168.1.1       : Traffic to/from specific host\n";
    std::cout << "  - net 192.168.0.0/16     : Traffic in subnet\n";
    std::cout << "  - tcp port 80 or 443     : HTTP/HTTPS traffic\n";
    std::cout << "  - icmp                   : ICMP packets only\n";
}

void clearBPFFilter()
{
    std::cout << "\n[*] Clearing BPF filter...\n";
    g_ingress->clearBPFFilter();
    std::cout << "[✓] Filter cleared!\n";
}

void setCaptureMode()
{
    std::cout << "\n[*] Select capture mode:\n";
    std::cout << "  1. Promiscuous mode (capture all packets)\n";
    std::cout << "  2. Normal mode (capture only packets for this host)\n";
    std::cout << "\nEnter choice (1/2): ";
    
    std::string choice;
    std::getline(std::cin, choice);
    
    bool promiscuous = (choice == "1");
    g_ingress->setPromiscuousMode(promiscuous);
    
    std::cout << "[✓] Capture mode set to: " 
              << (promiscuous ? "Promiscuous" : "Normal") << "\n";
}

void setSnapshotLength()
{
    std::cout << "\n[*] Enter snapshot length (bytes, 0 for maximum): ";
    std::string input;
    std::getline(std::cin, input);
    
    try
    {
        int snaplen = std::stoi(input);
        if (snaplen < 0)
        {
            std::cout << "[!] Invalid snapshot length!\n";
            return;
        }
        
        g_ingress->setSnapshotLength(snaplen);
        std::cout << "[✓] Snapshot length set to: " << snaplen << " bytes\n";
    }
    catch (...)
    {
        std::cout << "[!] Invalid input!\n";
    }
}

void setTimeout()
{
    std::cout << "\n[*] Enter timeout (milliseconds): ";
    std::string input;
    std::getline(std::cin, input);
    
    try
    {
        int timeout = std::stoi(input);
        if (timeout < 0)
        {
            std::cout << "[!] Invalid timeout!\n";
            return;
        }
        
        g_ingress->setTimeout(timeout);
        std::cout << "[✓] Timeout set to: " << timeout << " ms\n";
    }
    catch (...)
    {
        std::cout << "[!] Invalid input!\n";
    }
}

void readFromPCAP()
{
    std::string filename;
    std::cout << "\n[*] Enter PCAP file path: ";
    std::getline(std::cin, filename);
    
    if (filename.empty())
    {
        std::cout << "[!] Filename cannot be empty!\n";
        return;
    }
    
    std::cout << "[*] Reading from file: " << filename << "\n";
    
    auto callback = [](const uint8_t *data, size_t length, const PacketMetadata &metadata) {
        static std::atomic<uint64_t> packet_count(0);
        uint64_t count = ++packet_count;
        
        if (count % 100 == 0)
        {
            std::cout << "\r[*] Read packets: " << count << std::flush;
        }
    };
    
    if (g_ingress->readFromFile(filename, callback))
    {
        std::cout << "\n[✓] File read successfully!\n";
    }
    else
    {
        std::cout << "\n[✗] Failed to read file!\n";
    }
}

void saveToPCAP()
{
    std::string filename;
    std::cout << "\n[*] Enter output PCAP file path: ";
    std::getline(std::cin, filename);
    
    if (filename.empty())
    {
        std::cout << "[!] Filename cannot be empty!\n";
        return;
    }
    
    std::cout << "[*] Enter duration to capture (seconds, 0 for manual stop): ";
    std::string input;
    std::getline(std::cin, input);
    
    int duration = 0;
    try
    {
        duration = std::stoi(input);
    }
    catch (...)
    {
        std::cout << "[!] Invalid duration, using manual stop\n";
    }
    
    if (g_ingress->saveToFile(filename))
    {
        std::cout << "[✓] Started saving to: " << filename << "\n";
        
        if (duration > 0)
        {
            std::cout << "[*] Capturing for " << duration << " seconds...\n";
            std::this_thread::sleep_for(std::chrono::seconds(duration));
            g_ingress->stopSaving();
            std::cout << "[✓] Capture completed!\n";
        }
        else
        {
            std::cout << "[*] Press Enter to stop saving...\n";
            std::cin.get();
            g_ingress->stopSaving();
            std::cout << "[✓] Saving stopped!\n";
        }
    }
    else
    {
        std::cout << "[✗] Failed to start saving!\n";
    }
}

void liveMonitor()
{
    std::cout << "\n[*] Starting live monitor... (Press Ctrl+C to stop)\n\n";
    
    auto start_time = std::chrono::steady_clock::now();
    auto last_stats = g_ingress->getStatistics();
    
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto current_stats = g_ingress->getStatistics();
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            current_time - start_time).count();
        
        // Calculate rates
        uint64_t pps = current_stats.packets_received - last_stats.packets_received;
        uint64_t bps = current_stats.bytes_received - last_stats.bytes_received;
        
        // Clear line and print stats
        std::cout << "\r" << std::string(80, ' ') << "\r";
        std::cout << "[" << elapsed << "s] "
                  << "Packets: " << current_stats.packets_received << " "
                  << "(" << pps << " pps) | "
                  << "Bytes: " << current_stats.bytes_received << " "
                  << "(" << (bps / 1024.0) << " KB/s) | "
                  << "Dropped: " << current_stats.packets_dropped
                  << std::flush;
        
        last_stats = current_stats;
        
        // Check for user input
        if (std::cin.peek() != EOF)
        {
            break;
        }
    }
    
    std::cout << "\n[*] Monitor stopped.\n";
}

void showTopTalkers()
{
    std::cout << "\n[*] Top Talkers (Not implemented in basic version)\n";
    std::cout << "[*] This feature requires flow tracking.\n";
}

void showProtocolDistribution()
{
    std::cout << "\n[*] Protocol Distribution:\n\n";
    
    auto stats = g_ingress->getStatistics();
    uint64_t total = stats.packets_received;
    
    if (total == 0)
    {
        std::cout << "[!] No packets captured yet!\n";
        return;
    }
    
    struct ProtocolStat
    {
        std::string name;
        uint64_t count;
        double percent;
    };
    
    std::vector<ProtocolStat> protocols = {
        {"TCP", stats.tcp_packets, 0.0},
        {"UDP", stats.udp_packets, 0.0},
        {"ICMP", stats.icmp_packets, 0.0},
        {"IPv4", stats.ipv4_packets, 0.0},
        {"IPv6", stats.ipv6_packets, 0.0},
        {"Other", stats.other_packets, 0.0}
    };
    
    // Calculate percentages
    for (auto &proto : protocols)
    {
        proto.percent = (static_cast<double>(proto.count) / total) * 100.0;
    }
    
    // Sort by count
    std::sort(protocols.begin(), protocols.end(),
              [](const ProtocolStat &a, const ProtocolStat &b) {
                  return a.count > b.count;
              });
    
    std::cout << "┌──────────┬─────────────┬──────────┬────────────────────────┐\n";
    std::cout << "│ Protocol │ Packet Count│ Percent  │ Bar Chart              │\n";
    std::cout << "├──────────┼─────────────┼──────────┼────────────────────────┤\n";
    
    for (const auto &proto : protocols)
    {
        if (proto.count == 0) continue;
        
        int bar_length = static_cast<int>(proto.percent / 5.0); // Scale to 20 chars max
        std::string bar(bar_length, '█');
        
        std::cout << "│ " << std::setw(8) << std::left << proto.name << " │ "
                  << std::setw(11) << std::right << proto.count << " │ "
                  << std::setw(7) << std::fixed << std::setprecision(2) << proto.percent << "% │ "
                  << std::setw(22) << std::left << bar << " │\n";
    }
    
    std::cout << "└──────────┴─────────────┴──────────┴────────────────────────┘\n";
}

void resetStatistics()
{
    std::cout << "\n[*] Are you sure you want to reset statistics? (y/n): ";
    std::string confirm;
    std::getline(std::cin, confirm);
    
    if (confirm == "y" || confirm == "Y")
    {
        g_ingress->resetStatistics();
        std::cout << "[✓] Statistics reset!\n";
    }
    else
    {
        std::cout << "[*] Reset cancelled.\n";
    }
}

void runPerformanceTest()
{
    std::cout << "\n[*] Running performance test...\n";
    std::cout << "[*] This will capture packets for 10 seconds and measure performance.\n\n";
    
    // Reset statistics
    g_ingress->resetStatistics();
    
    // Start capture
    auto callback = [](const uint8_t *data, size_t length, const PacketMetadata &metadata) {
        // Minimal processing for performance test
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (!g_ingress->start("any", callback))
    {
        std::cout << "[✗] Failed to start capture!\n";
        return;
    }
    
    std::cout << "[*] Capturing...\n";
    
    // Capture for 10 seconds
    for (int i = 0; i < 10; ++i)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\r[*] Progress: " << (i + 1) << "/10 seconds" << std::flush;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    g_ingress->stop();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    auto stats = g_ingress->getStatistics();
    
    std::cout << "\n\n";
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║              PERFORMANCE TEST RESULTS                     ║\n";
    std::cout << "╠═══════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Duration:            " << std::setw(34) << duration << " ms ║\n";
    std::cout << "║ Total Packets:       " << std::setw(36) << stats.packets_received << " ║\n";
    std::cout << "║ Total Bytes:         " << std::setw(36) << stats.bytes_received << " ║\n";
    std::cout << "║ Packets Dropped:     " << std::setw(36) << stats.packets_dropped << " ║\n";
    
    double pps = (static_cast<double>(stats.packets_received) / duration) * 1000.0;
    double mbps = (static_cast<double>(stats.bytes_received) * 8.0 / duration / 1000.0);
    double drop_rate = stats.packets_received > 0
        ? (static_cast<double>(stats.packets_dropped) / stats.packets_received * 100.0)
        : 0.0;
    
    std::cout << "╟───────────────────────────────────────────────────────────╢\n";
    std::cout << "║ Packets per second:  " << std::setw(32) << std::fixed 
              << std::setprecision(2) << pps << " pps ║\n";
    std::cout << "║ Throughput:          " << std::setw(32) << std::fixed 
              << std::setprecision(2) << mbps << " Mbps ║\n";
    std::cout << "║ Drop Rate:           " << std::setw(34) << std::fixed 
              << std::setprecision(4) << drop_rate << "% ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n";
}

void showConfiguration()
{
    std::cout << "\n[*] Current Configuration:\n\n";
    
    std::cout << "┌─────────────────────────────────────────────────────────┐\n";
    std::cout << "│                   CONFIGURATION                         │\n";
    std::cout << "├─────────────────────────────────────────────────────────┤\n";
    std::cout << "│ Capture Status:      " << std::setw(34) 
              << (g_ingress->isRunning() ? "Running" : "Stopped") << " │\n";
    std::cout << "│ Interface:           " << std::setw(34) << "N/A" << " │\n";
    std::cout << "│ Promiscuous Mode:    " << std::setw(34) << "N/A" << " │\n";
    std::cout << "│ Snapshot Length:     " << std::setw(34) << "N/A" << " │\n";
    std::cout << "│ Timeout:             " << std::setw(34) << "N/A" << " │\n";
    std::cout << "│ BPF Filter:          " << std::setw(34) << "N/A" << " │\n";
    std::cout << "└─────────────────────────────────────────────────────────┘\n";
}

// ==================== Main Function ====================

int main(int argc, char *argv[])
{
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Initialize logger
    auto &logger = Logger::getInstance();
    logger.setLogLevel(LogLevel::INFO);
    logger.setLogToConsole(false); // Don't spam console during capture
    logger.setLogToFile(true, "packet_ingress_cli.log");
    
    // Create PacketIngress instance
    g_ingress = std::make_unique<PacketIngress>();
    
    // Print header
    clearScreen();
    printHeader();
    
    std::cout << "[*] Packet Ingress CLI Test Tool initialized.\n";
    std::cout << "[*] Run with sudo/root privileges for full functionality.\n";
    
    // Main loop
    while (g_running)
    {
        printMenu();
        
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice.empty())
        {
            continue;
        }
        
        printSeparator();
        
        try
        {
            int option = std::stoi(choice);
            
            switch (option)
            {
            case 0:
                g_running = false;
                break;
            case 1:
                listInterfaces();
                break;
            case 2:
                startCapture();
                break;
            case 3:
                stopCapture();
                break;
            case 4:
                showStatistics();
                break;
            case 5:
                showDetailedStatistics();
                break;
            case 6:
                addBPFFilter();
                break;
            case 7:
                clearBPFFilter();
                break;
            case 8:
                setCaptureMode();
                break;
            case 9:
                setSnapshotLength();
                break;
            case 10:
                setTimeout();
                break;
            case 11:
                readFromPCAP();
                break;
            case 12:
                saveToPCAP();
                break;
            case 13:
                liveMonitor();
                break;
            case 14:
                showTopTalkers();
                break;
            case 15:
                showProtocolDistribution();
                break;
            case 16:
                resetStatistics();
                break;
            case 17:
                runPerformanceTest();
                break;
            case 18:
                showConfiguration();
                break;
            default:
                std::cout << "[!] Invalid choice!\n";
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "[!] Error: " << e.what() << "\n";
        }
        
        if (g_running)
        {
            printSeparator();
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
        }
    }
    
    // Cleanup
    if (g_ingress)
    {
        g_ingress->stop();
    }
    
    std::cout << "\n[*] Exiting... Goodbye!\n\n";
    
    return 0;
}
