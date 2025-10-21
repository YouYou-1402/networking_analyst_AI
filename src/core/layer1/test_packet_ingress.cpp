// src/core/layer1/test_packet_ingress.cpp
#include "packet_ingress.hpp"
#include "xdp_filter.hpp"
#include <iostream>
#include <signal.h>
#include <chrono>
#include <thread>

using namespace NetworkSecurity::Core::Layer1;

// Global pointer for signal handler
std::shared_ptr<PacketIngress> g_ingress;
bool g_running = true;

// Signal handler for Ctrl+C
void signalHandler(int signum)
{
    std::cout << "\n🛑 Interrupt signal (" << signum << ") received." << std::endl;
    g_running = false;
    if (g_ingress)
    {
        g_ingress->stop();
    }
}

// Packet callback function
void packetHandler(const PacketBuffer &packet)
{
    static uint64_t packet_count = 0;
    packet_count++;
    
    // Print every 1000th packet to avoid flooding console
    if (packet_count % 1000 == 0)
    {
        std::cout << "📦 Processed " << packet_count << " packets"
                  << " | Last packet: " << packet.length << " bytes"
                  << " | Queue size: " << g_ingress->getQueueSize()
                  << std::endl;
    }
}

void printUsage(const char *program_name)
{
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i <interface>    Network interface (default: eth0)" << std::endl;
    std::cout << "  -f <filter>       BPF filter expression (default: none)" << std::endl;
    std::cout << "  -t <threads>      Number of worker threads (default: 4)" << std::endl;
    std::cout << "  -q <size>         Packet queue size (default: 10000)" << std::endl;
    std::cout << "  -x                Enable XDP filter (default: disabled)" << std::endl;
    std::cout << "  -h                Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " -i eth0 -f \"tcp port 80\"" << std::endl;
    std::cout << "  " << program_name << " -i wlan0 -t 8 -q 20000" << std::endl;
}

int main(int argc, char *argv[])
{
    std::cout << "🚀 Network Security AI - Packet Ingress Test" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    // Parse command line arguments
    IngressConfig config;
    bool enable_xdp = false;
    
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help")
        {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "-i" && i + 1 < argc)
        {
            config.interface_name = argv[++i];
        }
        else if (arg == "-f" && i + 1 < argc)
        {
            config.capture_filter = argv[++i];
        }
        else if (arg == "-t" && i + 1 < argc)
        {
            config.worker_threads = std::stoi(argv[++i]);
        }
        else if (arg == "-q" && i + 1 < argc)
        {
            config.packet_queue_size = std::stoul(argv[++i]);
        }
        else if (arg == "-x")
        {
            enable_xdp = true;
        }
        else
        {
            std::cerr << "❌ Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Print configuration
    std::cout << "\n📋 Configuration:" << std::endl;
    std::cout << "  Interface:      " << config.interface_name << std::endl;
    std::cout << "  Filter:         " << (config.capture_filter.empty() ? "(none)" : config.capture_filter) << std::endl;
    std::cout << "  Worker threads: " << config.worker_threads << std::endl;
    std::cout << "  Queue size:     " << config.packet_queue_size << std::endl;
    std::cout << "  XDP filter:     " << (enable_xdp ? "enabled" : "disabled") << std::endl;
    std::cout << std::endl;
    
    // Register signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create packet ingress
    g_ingress = std::make_shared<PacketIngress>();
    
    // Set XDP filter if enabled
    if (enable_xdp)
    {
        std::cout << "🔧 Initializing XDP filter..." << std::endl;
        auto xdp_filter = std::make_shared<XDPFilter>();
        
        XDPFilterConfig xdp_config;
        xdp_config.interface_name = config.interface_name;
        
        if (xdp_filter->initialize(xdp_config))
        {
            g_ingress->setXDPFilter(xdp_filter);
            std::cout << "✅ XDP filter initialized" << std::endl;
        }
        else
        {
            std::cerr << "⚠️  Failed to initialize XDP filter, continuing without it" << std::endl;
        }
    }
    
    // Initialize packet ingress
    std::cout << "🔧 Initializing packet ingress..." << std::endl;
    if (!g_ingress->initialize(config))
    {
        std::cerr << "❌ Failed to initialize packet ingress" << std::endl;
        return 1;
    }
    std::cout << "✅ Packet ingress initialized" << std::endl;
    
    // Register packet callback
    g_ingress->registerPacketCallback(packetHandler);
    std::cout << "✅ Packet callback registered" << std::endl;
    
    // Start packet capture
    std::cout << "\n🎯 Starting packet capture..." << std::endl;
    if (!g_ingress->start())
    {
        std::cerr << "❌ Failed to start packet capture" << std::endl;
        return 1;
    }
    std::cout << "✅ Packet capture started" << std::endl;
    std::cout << "\n📊 Capturing packets... Press Ctrl+C to stop\n" << std::endl;
    
    // Statistics update loop
    auto last_stats_time = std::chrono::steady_clock::now();
    
    while (g_running && g_ingress->isRunning())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();
        
        // Print statistics every 5 seconds
        if (elapsed >= 5)
        {
            g_ingress->updateStatistics();
            g_ingress->printStatistics();
            
            // Print XDP statistics if enabled
            if (enable_xdp && g_ingress->getXDPFilter())
            {
                g_ingress->getXDPFilter()->updateStatistics();
                g_ingress->getXDPFilter()->printStatistics();
            }
            
            last_stats_time = now;
        }
    }
    
    // Cleanup
    std::cout << "\n🛑 Stopping packet capture..." << std::endl;
    g_ingress->shutdown();
    std::cout << "✅ Packet capture stopped" << std::endl;
    
    // Print final statistics
    std::cout << "\n📊 Final Statistics:" << std::endl;
    g_ingress->updateStatistics();
    g_ingress->printStatistics();
    
    if (enable_xdp && g_ingress->getXDPFilter())
    {
        g_ingress->getXDPFilter()->updateStatistics();
        g_ingress->getXDPFilter()->printStatistics();
    }
    
    std::cout << "\n👋 Goodbye!" << std::endl;
    
    return 0;
}
