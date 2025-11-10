// src/main.cpp - Example usage

#include "core/layer1/packet_ingress.hpp"
#include <spdlog/spdlog.h>
#include <signal.h>

using namespace NetworkSecurity;

// Global manager để có thể stop từ signal handler
Layer1::IngressManager *g_manager = nullptr;

void signalHandler(int signum)
{
    spdlog::info("Interrupt signal ({}) received", signum);
    if (g_manager)
    {
        g_manager->stopAll();
    }
    exit(signum);
}

void packetHandler(const Common::ParsedPacket &packet)
{
    // Xử lý packet ở đây
    // Ví dụ: in thông tin packet

    if (packet.has_ipv4 && packet.has_tcp)
    {
        spdlog::debug("TCP Packet: {}:{} -> {}:{} | Size: {} bytes",
                      Common::PacketParser::ipv4ToString(packet.ipv4.src_ip),
                      packet.tcp.src_port,
                      Common::PacketParser::ipv4ToString(packet.ipv4.dst_ip),
                      packet.tcp.dst_port,
                      packet.packet_size);
    }
    else if (packet.has_ipv4 && packet.has_udp)
    {
        spdlog::debug("UDP Packet: {}:{} -> {}:{} | Size: {} bytes",
                      Common::PacketParser::ipv4ToString(packet.ipv4.src_ip),
                      packet.udp.src_port,
                      Common::PacketParser::ipv4ToString(packet.ipv4.dst_ip),
                      packet.udp.dst_port,
                      packet.packet_size);
    }

    // TODO: Chuyển packet sang các module khác để xử lý
    // - Flow Assembly
    // - Threat Detection
    // - etc.
}

int main(int argc, char *argv[])
{
    // Setup logging
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

    spdlog::info("========================================");
    spdlog::info("Network Security IPS - Packet Ingress");
    spdlog::info("========================================");

    // Kiểm tra quyền
    if (!Layer1::PacketIngress::checkPermissions())
    {
        spdlog::error("This program requires root privileges or CAP_NET_RAW capability");
        spdlog::error("Please run with: sudo ./ips");
        return 1;
    }

    // Liệt kê interfaces
    auto interfaces = Layer1::PacketIngress::listInterfaces();
    spdlog::info("Available interfaces:");
    for (const auto &iface : interfaces)
    {
        spdlog::info("  - {}", iface);
    }

    // Tạo IngressManager
    Layer1::IngressManager manager;
    g_manager = &manager;

    // Setup signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Thêm interfaces để monitor
    Layer1::IngressConfig config1;
    config1.interface = "wlan0";
    config1.promiscuous = true;
    config1.buffer_size = 256; // 256 MB
    config1.bpf_filter = ""; // Capture all packets

    if (!manager.addInterface(config1))
    {
        spdlog::error("Failed to add interface wlan0");
        return 1;
    }

    // Có thể thêm nhiều interfaces
    // Layer1::IngressConfig config2;
    // config2.interface = "wlan0";
    // manager.addInterface(config2);

    // Bắt đầu capture
    spdlog::info("Starting packet capture...");
    if (!manager.startAll(packetHandler))
    {
        spdlog::error("Failed to start packet capture");
        return 1;
    }

    // Chờ cho đến khi bị interrupt
    spdlog::info("Capturing packets... Press Ctrl+C to stop");

    // Main loop - có thể thêm logic khác ở đây
    while (manager.getActiveCount() > 0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // In statistics định kỳ
        auto stats = manager.getTotalStats();
        spdlog::info("Total: {} packets | {:.2f} MB | {:.2f} pps",
                     stats.packets_received,
                     stats.bytes_received / (1024.0 * 1024.0),
                     stats.capture_rate);
    }

    spdlog::info("Program terminated");
    return 0;
}
