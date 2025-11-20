// src/main_integrated_test.cpp
// Integrated test: Packet Ingress + Database Manager
// CORRECT VERSION - Based on actual ParsedPacket struct

#include <iostream>
#include <signal.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <iomanip>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <arpa/inet.h>

#include "core/layer1/packet_ingress.hpp"
#include "core/storage/database_manager.hpp"
#include "common/packet_parser.hpp"

// ==================== NAMESPACE ALIASES ====================
using namespace NetworkSecurity;
using namespace NetworkSecurity::Layer1;
using namespace NetworkSecurity::Common;
namespace DB = netsec;

// ==================== GLOBAL VARIABLES ====================

std::atomic<bool> g_running{true};
std::unique_ptr<PacketIngress> g_ingress;
std::unique_ptr<DB::DatabaseManager> g_db_manager;

// Statistics
std::atomic<uint64_t> g_total_packets{0};
std::atomic<uint64_t> g_total_bytes{0};
std::atomic<uint64_t> g_db_inserts{0};
std::atomic<uint64_t> g_db_errors{0};

// Batch processing
std::vector<PacketParser::PacketInfo> g_packet_batch;
std::mutex g_batch_mutex;
const size_t BATCH_SIZE = 100;

// ==================== SIGNAL HANDLER ====================

void signalHandler(int signum)
{
    spdlog::warn("Signal ({}) received. Shutting down gracefully...", signum);
    g_running = false;
}

// ==================== HELPER FUNCTIONS ====================

/**
 * @brief Convert MAC address to string
 */
std::string macToString(const uint8_t* mac)
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

/**
 * @brief Convert IPv4 address (uint32_t) to string
 */
std::string ipToString(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

/**
 * @brief Get protocol name from ProtocolType enum
 */
std::string getProtocolName(ProtocolType type)
{
    switch (type)
    {
        case ProtocolType::TCP: return "TCP";
        case ProtocolType::UDP: return "UDP";
        case ProtocolType::ICMP: return "ICMP";
        case ProtocolType::ICMPV6: return "ICMPv6";
        case ProtocolType::IPV4: return "IPv4";
        case ProtocolType::IPV6: return "IPv6";
        case ProtocolType::ARP: return "ARP";
        case ProtocolType::ETHERNET: return "Ethernet";
        case ProtocolType::IGMP: return "IGMP";
        case ProtocolType::ESP: return "ESP";
        case ProtocolType::AH: return "AH";
        case ProtocolType::SCTP: return "SCTP";
        case ProtocolType::GRE: return "GRE";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Convert ParsedPacket to PacketInfo for database
 */
PacketParser::PacketInfo convertToPacketInfo(const ParsedPacket& packet)
{
    PacketParser::PacketInfo info;
    
    // ==================== Basic Info ====================
    info.timestamp = packet.timestamp;
    info.length = packet.packet_size;
    info.payload_size = packet.payload_length;
    info.protocol = getProtocolName(packet.protocol_type);
    
    // ==================== MAC Addresses ====================
    if (packet.has_ethernet)
    {
        info.src_mac = macToString(packet.src_mac);
        info.dst_mac = macToString(packet.dst_mac);
    }
    
    // ==================== IP Addresses & Ports ====================
    if (packet.has_ipv4)
    {
        info.src_ip = ipToString(packet.src_ip);
        info.dst_ip = ipToString(packet.dst_ip);
        info.ip_version = packet.ip_version;
        info.ttl = packet.ip_ttl;
        info.tos = packet.ipv4.tos;
        info.id = packet.ipv4.id;
        
        // Checksum
        char checksum[16];
        snprintf(checksum, sizeof(checksum), "0x%04x", packet.ipv4.check);
        info.checksum = checksum;
        
        // Flags
        std::string flags;
        if (packet.ipv4.flags & 0x02) flags += "DF ";
        if (packet.ipv4.flags & 0x01) flags += "MF ";
        if (!flags.empty()) 
        {
            flags.pop_back();
            info.flags = flags;
        }
        
        info.fragment_offset = packet.ipv4.frag_off;
    }
    else if (packet.has_ipv6)
    {
        // IPv6 addresses
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, packet.ipv6.src_addr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, packet.ipv6.dst_addr, dst_ip, INET6_ADDRSTRLEN);
        info.src_ip = src_ip;
        info.dst_ip = dst_ip;
        info.ip_version = 6;
        info.ttl = packet.ipv6.hop_limit;
    }
    
    // ==================== Ports ====================
    info.src_port = packet.src_port;
    info.dst_port = packet.dst_port;
    
    // ==================== TCP Specific ====================
    if (packet.has_tcp)
    {
        info.protocol = "TCP";
        info.seq_num = packet.seq_num;
        info.ack_num = packet.ack_num;
        info.window_size = packet.window_size;
        
        // TCP Flags
        std::string tcp_flags;
        if (packet.tcp_flags & 0x02) tcp_flags += "SYN ";
        if (packet.tcp_flags & 0x10) tcp_flags += "ACK ";
        if (packet.tcp_flags & 0x01) tcp_flags += "FIN ";
        if (packet.tcp_flags & 0x04) tcp_flags += "RST ";
        if (packet.tcp_flags & 0x08) tcp_flags += "PSH ";
        if (packet.tcp_flags & 0x20) tcp_flags += "URG ";
        
        if (!tcp_flags.empty())
        {
            tcp_flags.pop_back();
            info.flags = tcp_flags;
        }
    }
    
    // ==================== UDP Specific ====================
    else if (packet.has_udp)
    {
        info.protocol = "UDP";
    }
    
    // ==================== ICMP Specific ====================
    else if (packet.has_icmp)
    {
        info.protocol = "ICMP";
        info.icmp_type = packet.icmp.type;
        info.icmp_code = packet.icmp.code;
    }
    else if (packet.has_icmpv6)
    {
        info.protocol = "ICMPv6";
        info.icmp_type = packet.icmpv6.type;
        info.icmp_code = packet.icmpv6.code;
    }
    
    // ==================== ARP Specific ====================
    else if (packet.has_arp)
    {
        info.protocol = "ARP";
    }
    
    return info;
}

// ==================== PACKET CALLBACK ====================

/**
 * @brief Callback được gọi khi nhận được packet
 */
void onPacketReceived(const ParsedPacket& packet)
{
    g_total_packets++;
    g_total_bytes += packet.packet_size;

    // Convert to PacketInfo
    PacketParser::PacketInfo packet_info = convertToPacketInfo(packet);

    // Add to batch
    {
        std::lock_guard<std::mutex> lock(g_batch_mutex);
        g_packet_batch.push_back(packet_info);

        // Insert batch when full
        if (g_packet_batch.size() >= BATCH_SIZE)
        {
            if (g_db_manager)
            {
                if (g_db_manager->insertPacketBatch(g_packet_batch))
                {
                    g_db_inserts += g_packet_batch.size();
                }
                else
                {
                    g_db_errors++;
                    spdlog::error("Failed to insert batch of {} packets", g_packet_batch.size());
                }
            }
            g_packet_batch.clear();
        }
    }

    // Log every 1000 packets
    if (g_total_packets % 1000 == 0)
    {
        spdlog::info("📦 Captured {} packets ({:.2f} MB) | 💾 DB: {} inserts, {} errors",
                     g_total_packets.load(),
                     g_total_bytes.load() / (1024.0 * 1024.0),
                     g_db_inserts.load(),
                     g_db_errors.load());
    }
}

// ==================== STATISTICS THREAD ====================

void statisticsThread()
{
    auto last_time = std::chrono::steady_clock::now();
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;

    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        auto current_time = std::chrono::steady_clock::now();
        uint64_t current_packets = g_total_packets.load();
        uint64_t current_bytes = g_total_bytes.load();

        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            current_time - last_time).count();

        if (duration > 0)
        {
            uint64_t packets_diff = current_packets - last_packets;
            uint64_t bytes_diff = current_bytes - last_bytes;

            double pps = packets_diff / static_cast<double>(duration);
            double mbps = (bytes_diff * 8) / (duration * 1024.0 * 1024.0);

            spdlog::info("╔════════════════════════════════════════════════════╗");
            spdlog::info("║               📊 LIVE STATISTICS                   ║");
            spdlog::info("╠════════════════════════════════════════════════════╣");
            spdlog::info("║ Total Packets:    {:>32} ║", current_packets);
            spdlog::info("║ Total Bytes:      {:>32} ║", current_bytes);
            spdlog::info("║ Capture Rate:     {:>28.2f} pps ║", pps);
            spdlog::info("║ Throughput:       {:>28.2f} Mbps ║", mbps);
            spdlog::info("║ DB Inserts:       {:>32} ║", g_db_inserts.load());
            spdlog::info("║ DB Errors:        {:>32} ║", g_db_errors.load());
            spdlog::info("╚════════════════════════════════════════════════════╝");

            // Get ingress stats
            if (g_ingress)
            {
                auto stats = g_ingress->getStatistics();
                spdlog::info("📡 Ingress: Received={}, Dropped={}, Errors={}",
                             stats.packets_received,
                             stats.packets_dropped,
                             stats.errors);
            }

            last_time = current_time;
            last_packets = current_packets;
            last_bytes = current_bytes;
        }
    }
}

// ==================== MAINTENANCE THREAD ====================

void maintenanceThread()
{
    int counter = 0;

    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::minutes(5));

        if (!g_running) break;

        counter++;
        spdlog::info("🔧 Running database maintenance (iteration {})...", counter);

        if (g_db_manager)
        {
            // Optimize every 30 minutes
            if (counter % 6 == 0)
            {
                spdlog::info("⚡ Running OPTIMIZE...");
                if (g_db_manager->optimize())
                {
                    spdlog::info("✓ Database optimized");
                }
            }

            // Delete old packets every hour
            if (counter % 12 == 0)
            {
                spdlog::info("🧹 Cleaning old packets...");
                uint64_t deleted = g_db_manager->deleteOldPackets(30);
                if (deleted > 0)
                {
                    spdlog::info("✓ Deleted {} old packets", deleted);
                }
            }
        }
    }
}

// ==================== FLUSH THREAD ====================

void flushThread()
{
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        if (!g_running) break;

        // Flush remaining packets in batch
        std::lock_guard<std::mutex> lock(g_batch_mutex);
        
        if (!g_packet_batch.empty() && g_db_manager)
        {
            if (g_db_manager->insertPacketBatch(g_packet_batch))
            {
                g_db_inserts += g_packet_batch.size();
                spdlog::debug("💾 Flushed {} packets to database", g_packet_batch.size());
            }
            else
            {
                g_db_errors++;
                spdlog::error("❌ Failed to flush batch");
            }
            g_packet_batch.clear();
        }
    }
}

// ==================== SETUP LOGGER ====================

void setupLogger()
{
    try
    {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            "logs/network_capture.log", 1024 * 1024 * 10, 5);
        file_sink->set_level(spdlog::level::debug);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("multi_sink", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::debug);
        
        spdlog::set_default_logger(logger);
        spdlog::flush_every(std::chrono::seconds(5));

        spdlog::info("✓ Logger initialized successfully");
    }
    catch (const spdlog::spdlog_ex& ex)
    {
        std::cerr << "❌ Log initialization failed: " << ex.what() << std::endl;
    }
}

// ==================== LIST INTERFACES ====================

void listInterfaces()
{
    spdlog::info("📡 Available network interfaces:");
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        spdlog::error("Error finding devices: {}", errbuf);
        return;
    }

    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        spdlog::info("  [{}] {} - {}", 
                     i++, 
                     d->name, 
                     d->description ? d->description : "No description");
        
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next)
        {
            if (a->addr && a->addr->sa_family == AF_INET)
            {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, 
                         &((struct sockaddr_in*)a->addr)->sin_addr,
                         ip, sizeof(ip));
                spdlog::info("      IP: {}", ip);
            }
        }
    }

    pcap_freealldevs(alldevs);
}

// ==================== MAIN FUNCTION ====================

int main(int argc, char* argv[])
{
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Setup logger
    setupLogger();

    spdlog::info("╔═══════════════════════════════════════════════════════╗");
    spdlog::info("║   🛡️  Network Security AI - Capture System           ║");
    spdlog::info("║   📦 Packet Ingress + 💾 Database Manager            ║");
    spdlog::info("╚═══════════════════════════════════════════════════════╝");

    // Parse command line arguments
    std::string interface = "wlan0";
    std::string bpf_filter = "";
    
    if (argc > 1)
    {
        interface = argv[1];
    }
    
    if (argc > 2)
    {
        bpf_filter = argv[2];
    }

    spdlog::info("🔌 Interface: {}", interface);
    if (!bpf_filter.empty())
    {
        spdlog::info("🔍 BPF Filter: {}", bpf_filter);
    }

    // List available interfaces
    listInterfaces();

    // ==================== INITIALIZE DATABASE ====================

    spdlog::info("💾 Initializing database...");

    DB::DatabaseConfig db_config;
    db_config.db_path = "data/db/network_capture.db";
    db_config.enable_wal = true;
    db_config.cache_size = 20000;
    db_config.busy_timeout = 10000;
    db_config.auto_vacuum = true;
    db_config.max_packet_age_days = 30;

    // Create directories
    system("mkdir -p data/db");
    system("mkdir -p logs");

    g_db_manager = std::make_unique<DB::DatabaseManager>(db_config);

    if (!g_db_manager->initialize())
    {
        spdlog::error("❌ Failed to initialize database");
        return 1;
    }

    spdlog::info("✓ Database initialized: {}", db_config.db_path);

    // ==================== INITIALIZE PACKET INGRESS ====================

    spdlog::info("📦 Initializing packet ingress...");

    IngressConfig ingress_config;
    ingress_config.interface = interface;
    ingress_config.snaplen = 65535;
    ingress_config.buffer_size = 512;
    ingress_config.timeout_ms = 1000;
    ingress_config.promiscuous = true;
    ingress_config.enable_timestamp = true;
    ingress_config.bpf_filter = bpf_filter;

    g_ingress = std::make_unique<PacketIngress>(ingress_config);

    if (!g_ingress->initialize())
    {
        spdlog::error("❌ Failed to initialize packet ingress");
        if (g_db_manager)
        {
            g_db_manager->shutdown();
        }
        return 1;
    }

    spdlog::info("✓ Packet ingress initialized");

    // ==================== START THREADS ====================

    spdlog::info("🚀 Starting worker threads...");

    std::thread stats_thread(statisticsThread);
    std::thread maintenance_thread(maintenanceThread);
    std::thread flush_thread(flushThread);

    spdlog::info("✓ All threads started");

    // ==================== START CAPTURE ====================

    spdlog::info("╔═══════════════════════════════════════════════════════╗");
    spdlog::info("║   🎯 STARTING PACKET CAPTURE                         ║");
    spdlog::info("║   ⚠️  Press Ctrl+C to stop                           ║");
    spdlog::info("╚═══════════════════════════════════════════════════════╝");

    if (!g_ingress->start(onPacketReceived))
    {
        spdlog::error("❌ Failed to start packet capture");
        g_running = false;
    }

    // ==================== WAIT FOR SHUTDOWN ====================

    if (stats_thread.joinable())
        stats_thread.join();
    
    if (maintenance_thread.joinable())
        maintenance_thread.join();
    
    if (flush_thread.joinable())
        flush_thread.join();

    // ==================== CLEANUP ====================

    spdlog::info("🛑 Stopping packet capture...");
    if (g_ingress)
    {
        g_ingress->stop();
    }

    // Flush remaining packets
    spdlog::info("💾 Flushing remaining packets...");
    {
        std::lock_guard<std::mutex> lock(g_batch_mutex);
        if (!g_packet_batch.empty() && g_db_manager)
        {
            if (g_db_manager->insertPacketBatch(g_packet_batch))
            {
                g_db_inserts += g_packet_batch.size();
                spdlog::info("✓ Flushed {} packets", g_packet_batch.size());
            }
            g_packet_batch.clear();
        }
    }

    // Print final statistics
    spdlog::info("╔═══════════════════════════════════════════════════════╗");
    spdlog::info("║               📊 FINAL STATISTICS                     ║");
    spdlog::info("╠═══════════════════════════════════════════════════════╣");
    spdlog::info("║ Total Packets Captured: {:>30} ║", g_total_packets.load());
    spdlog::info("║ Total Bytes:            {:>30} ║", g_total_bytes.load());
    spdlog::info("║ DB Inserts:             {:>30} ║", g_db_inserts.load());
    spdlog::info("║ DB Errors:              {:>30} ║", g_db_errors.load());
    
    if (g_total_packets > 0)
    {
        double success_rate = (g_db_inserts.load() * 100.0) / g_total_packets.load();
        spdlog::info("║ Success Rate:           {:>28.2f}% ║", success_rate);
    }
    
    spdlog::info("╚═══════════════════════════════════════════════════════╝");

    // Shutdown database
    spdlog::info("💾 Shutting down database...");
    if (g_db_manager)
    {
        g_db_manager->shutdown();
    }

    spdlog::info("✓ Shutdown complete. Goodbye! 👋");

    return 0;
}
