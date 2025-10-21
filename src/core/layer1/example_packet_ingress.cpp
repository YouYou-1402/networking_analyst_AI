// example_packet_ingress.cpp
#include "packet_ingress.hpp"
#include <iostream>
#include <signal.h>

using namespace NetworkSecurity::Core::Layer1;

std::shared_ptr<PacketIngress> g_ingress;

void signalHandler(int signum)
{
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    if (g_ingress)
    {
        g_ingress->stop();
    }
}

void packetHandler(const PacketBuffer &packet)
{
    std::cout << "Received packet: "
              << packet.length << " bytes, "
              << "timestamp: " << packet.timestamp
              << std::endl;
}

int main(int argc, char *argv[])
{
    // Register signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create packet ingress
    g_ingress = std::make_shared<PacketIngress>();
    
    // Configure
    IngressConfig config;
    config.interface_name = "eth0";
    config.capture_filter = "tcp or udp";
    config.promiscuous_mode = true;
    config.packet_queue_size = 10000;
    config.worker_threads = 4;
    config.enable_xdp_filter = true;
    
    // Initialize
    if (!g_ingress->initialize(config))
    {
        std::cerr << "Failed to initialize packet ingress" << std::endl;
        return 1;
    }
    
    // Register callback
    g_ingress->registerPacketCallback(packetHandler);
    
    // Start capture
    if (!g_ingress->start())
    {
        std::cerr << "Failed to start packet ingress" << std::endl;
        return 1;
    }
    
    std::cout << "Packet capture started. Press Ctrl+C to stop." << std::endl;
    
    // Print statistics every 5 seconds
    while (g_ingress->isRunning())
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        g_ingress->updateStatistics();
        g_ingress->printStatistics();
    }
    
    // Cleanup
    g_ingress->shutdown();
    
    std::cout << "Packet capture stopped." << std::endl;
    
    return 0;
}
