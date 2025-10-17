// tests/unit/test_network_utils.cpp
#include <gtest/gtest.h>
#include "../../src/common/network_utils.hpp"
#include <thread>
#include <chrono>

using namespace NetworkSecurity::Common;

// ==================== Test Fixture ====================
class NetworkUtilsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Setup test data
    }

    void TearDown() override
    {
        // Cleanup
    }
};

// ==================== IP Address Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestIsValidIPv4)
{
    // Valid IPv4 addresses
    EXPECT_TRUE(NetworkUtils::isValidIPv4("192.168.1.1"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("10.0.0.1"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("172.16.0.1"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("8.8.8.8"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("127.0.0.1"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("255.255.255.255"));
    EXPECT_TRUE(NetworkUtils::isValidIPv4("0.0.0.0"));

    // Invalid IPv4 addresses
    EXPECT_FALSE(NetworkUtils::isValidIPv4("256.1.1.1"));
    EXPECT_FALSE(NetworkUtils::isValidIPv4("192.168.1"));
    EXPECT_FALSE(NetworkUtils::isValidIPv4("192.168.1.1.1"));
    EXPECT_FALSE(NetworkUtils::isValidIPv4("abc.def.ghi.jkl"));
    EXPECT_FALSE(NetworkUtils::isValidIPv4(""));
    EXPECT_FALSE(NetworkUtils::isValidIPv4("192.168.-1.1"));
}

TEST_F(NetworkUtilsTest, TestIsValidIPv6)
{
    // Valid IPv6 addresses
    EXPECT_TRUE(NetworkUtils::isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    EXPECT_TRUE(NetworkUtils::isValidIPv6("2001:db8:85a3::8a2e:370:7334"));
    EXPECT_TRUE(NetworkUtils::isValidIPv6("::1"));
    EXPECT_TRUE(NetworkUtils::isValidIPv6("::"));
    EXPECT_TRUE(NetworkUtils::isValidIPv6("fe80::1"));

    // Invalid IPv6 addresses
    EXPECT_FALSE(NetworkUtils::isValidIPv6("192.168.1.1"));
    EXPECT_FALSE(NetworkUtils::isValidIPv6("2001:0db8:85a3::8a2e::7334"));
    EXPECT_FALSE(NetworkUtils::isValidIPv6("gggg::1"));
    EXPECT_FALSE(NetworkUtils::isValidIPv6(""));
}

TEST_F(NetworkUtilsTest, TestIPStringToIntConversion)
{
    // Test conversion
    EXPECT_EQ(NetworkUtils::ipStringToInt("192.168.1.1"), 0xC0A80101);
    EXPECT_EQ(NetworkUtils::ipStringToInt("10.0.0.1"), 0x0A000001);
    EXPECT_EQ(NetworkUtils::ipStringToInt("127.0.0.1"), 0x7F000001);
    EXPECT_EQ(NetworkUtils::ipStringToInt("0.0.0.0"), 0x00000000);
    EXPECT_EQ(NetworkUtils::ipStringToInt("255.255.255.255"), 0xFFFFFFFF);

    // Test reverse conversion
    EXPECT_EQ(NetworkUtils::ipIntToString(0xC0A80101), "192.168.1.1");
    EXPECT_EQ(NetworkUtils::ipIntToString(0x0A000001), "10.0.0.1");
    EXPECT_EQ(NetworkUtils::ipIntToString(0x7F000001), "127.0.0.1");
    EXPECT_EQ(NetworkUtils::ipIntToString(0x00000000), "0.0.0.0");
    EXPECT_EQ(NetworkUtils::ipIntToString(0xFFFFFFFF), "255.255.255.255");

    // Test invalid IP
    EXPECT_EQ(NetworkUtils::ipStringToInt("invalid.ip"), 0);
    EXPECT_EQ(NetworkUtils::ipIntToString(0), "0.0.0.0");
}

TEST_F(NetworkUtilsTest, TestIsPrivateIP)
{
    // Private IP ranges
    EXPECT_TRUE(NetworkUtils::isPrivateIP("10.0.0.1"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("10.255.255.254"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("172.16.0.1"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("172.31.255.254"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("192.168.0.1"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("192.168.255.254"));

    // Public IP addresses
    EXPECT_FALSE(NetworkUtils::isPrivateIP("8.8.8.8"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("1.1.1.1"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("172.15.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("172.32.0.1"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("11.0.0.1"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("192.167.1.1"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("192.169.1.1"));

    // Invalid IP
    EXPECT_FALSE(NetworkUtils::isPrivateIP("invalid.ip"));
}

TEST_F(NetworkUtilsTest, TestIsLoopbackIP)
{
    // Loopback addresses
    EXPECT_TRUE(NetworkUtils::isLoopbackIP("127.0.0.1"));
    EXPECT_TRUE(NetworkUtils::isLoopbackIP("127.0.0.2"));
    EXPECT_TRUE(NetworkUtils::isLoopbackIP("127.255.255.255"));

    // Non-loopback addresses
    EXPECT_FALSE(NetworkUtils::isLoopbackIP("192.168.1.1"));
    EXPECT_FALSE(NetworkUtils::isLoopbackIP("126.255.255.255"));
    EXPECT_FALSE(NetworkUtils::isLoopbackIP("128.0.0.1"));

    // Invalid IP
    EXPECT_FALSE(NetworkUtils::isLoopbackIP("invalid.ip"));
}

TEST_F(NetworkUtilsTest, TestIsMulticastIP)
{
    // Multicast addresses (224.0.0.0/4)
    EXPECT_TRUE(NetworkUtils::isMulticastIP("224.0.0.1"));
    EXPECT_TRUE(NetworkUtils::isMulticastIP("239.255.255.255"));
    EXPECT_TRUE(NetworkUtils::isMulticastIP("230.1.2.3"));

    // Non-multicast addresses
    EXPECT_FALSE(NetworkUtils::isMulticastIP("223.255.255.255"));
    EXPECT_FALSE(NetworkUtils::isMulticastIP("240.0.0.1"));
    EXPECT_FALSE(NetworkUtils::isMulticastIP("192.168.1.1"));

    // Invalid IP
    EXPECT_FALSE(NetworkUtils::isMulticastIP("invalid.ip"));
}

// ==================== Network Range Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestIsIPInRange)
{
    // Test various network ranges
    EXPECT_TRUE(NetworkUtils::isIPInRange("192.168.1.100", "192.168.1.0", 24));
    EXPECT_TRUE(NetworkUtils::isIPInRange("10.0.0.1", "10.0.0.0", 8));
    EXPECT_TRUE(NetworkUtils::isIPInRange("172.16.5.10", "172.16.0.0", 12));

    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.2.1", "192.168.1.0", 24));
    EXPECT_FALSE(NetworkUtils::isIPInRange("11.0.0.1", "10.0.0.0", 8));

    // Edge cases
    EXPECT_TRUE(NetworkUtils::isIPInRange("192.168.1.0", "192.168.1.0", 24));
    EXPECT_TRUE(NetworkUtils::isIPInRange("192.168.1.255", "192.168.1.0", 24));

    // Invalid inputs
    EXPECT_FALSE(NetworkUtils::isIPInRange("invalid.ip", "192.168.1.0", 24));
    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.1.1", "invalid.network", 24));
    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.1.1", "192.168.1.0", -1));
    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.1.1", "192.168.1.0", 33));
}

TEST_F(NetworkUtilsTest, TestIsIPInCIDR)
{
    // Valid CIDR tests
    EXPECT_TRUE(NetworkUtils::isIPInCIDR("192.168.1.100", "192.168.1.0/24"));
    EXPECT_TRUE(NetworkUtils::isIPInCIDR("10.0.0.1", "10.0.0.0/8"));
    EXPECT_TRUE(NetworkUtils::isIPInCIDR("172.16.5.10", "172.16.0.0/12"));

    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.2.1", "192.168.1.0/24"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("11.0.0.1", "10.0.0.0/8"));

    // Invalid CIDR format
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/33"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/-1"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/abc"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/24abc"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/24.5"));
    
    // Empty or malformed CIDR
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", ""));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "/24"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/"));
}


TEST_F(NetworkUtilsTest, TestExpandCIDR)
{
    // Test small CIDR expansion
    auto ips = NetworkUtils::expandCIDR("192.168.1.0/30");
    EXPECT_EQ(ips.size(), 2); // /30 has 2 host addresses
    if (ips.size() >= 2) {
        EXPECT_EQ(ips[0], "192.168.1.1");
        EXPECT_EQ(ips[1], "192.168.1.2");
    }

    // Test /31 (point-to-point)
    ips = NetworkUtils::expandCIDR("192.168.1.0/31");
    EXPECT_EQ(ips.size(), 0); // /31 has no host addresses

    // Test /32 (host route)
    ips = NetworkUtils::expandCIDR("192.168.1.1/32");
    EXPECT_EQ(ips.size(), 0); // /32 has no host addresses

    // Test larger network
    ips = NetworkUtils::expandCIDR("192.168.1.0/28");
    EXPECT_EQ(ips.size(), 14); // /28 has 14 host addresses

    // Invalid CIDR formats
    ips = NetworkUtils::expandCIDR("invalid/24");
    EXPECT_EQ(ips.size(), 0);

    ips = NetworkUtils::expandCIDR("192.168.1.0");
    EXPECT_EQ(ips.size(), 0);
    
    ips = NetworkUtils::expandCIDR("192.168.1.0/");
    EXPECT_EQ(ips.size(), 0);
    
    ips = NetworkUtils::expandCIDR("192.168.1.0/abc");
    EXPECT_EQ(ips.size(), 0);
    
    ips = NetworkUtils::expandCIDR("192.168.1.0/33");
    EXPECT_EQ(ips.size(), 0);
    
    ips = NetworkUtils::expandCIDR("192.168.1.0/-1");
    EXPECT_EQ(ips.size(), 0);
    
    // Empty or malformed
    ips = NetworkUtils::expandCIDR("");
    EXPECT_EQ(ips.size(), 0);
    
    ips = NetworkUtils::expandCIDR("/24");
    EXPECT_EQ(ips.size(), 0);
    
    // Test large network (should be limited)
    ips = NetworkUtils::expandCIDR("10.0.0.0/8");
    EXPECT_EQ(ips.size(), 0); // Too large, should return empty
}


// ==================== Port Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestPortValidation)
{
    // Valid ports
    EXPECT_TRUE(NetworkUtils::isValidPort(1));
    EXPECT_TRUE(NetworkUtils::isValidPort(80));
    EXPECT_TRUE(NetworkUtils::isValidPort(443));
    EXPECT_TRUE(NetworkUtils::isValidPort(65535));

    // Invalid ports
    EXPECT_FALSE(NetworkUtils::isValidPort(0));
    EXPECT_FALSE(NetworkUtils::isValidPort(-1));
    EXPECT_FALSE(NetworkUtils::isValidPort(65536));
    EXPECT_FALSE(NetworkUtils::isValidPort(100000));
}

TEST_F(NetworkUtilsTest, TestPortCategories)
{
    // Well-known ports (1-1023)
    EXPECT_TRUE(NetworkUtils::isWellKnownPort(80));
    EXPECT_TRUE(NetworkUtils::isWellKnownPort(443));
    EXPECT_TRUE(NetworkUtils::isWellKnownPort(1023));
    EXPECT_FALSE(NetworkUtils::isWellKnownPort(1024));

    // Registered ports (1024-49151)
    EXPECT_TRUE(NetworkUtils::isRegisteredPort(1024));
    EXPECT_TRUE(NetworkUtils::isRegisteredPort(8080));
    EXPECT_TRUE(NetworkUtils::isRegisteredPort(49151));
    EXPECT_FALSE(NetworkUtils::isRegisteredPort(1023));
    EXPECT_FALSE(NetworkUtils::isRegisteredPort(49152));

    // Dynamic ports (49152-65535)
    EXPECT_TRUE(NetworkUtils::isDynamicPort(49152));
    EXPECT_TRUE(NetworkUtils::isDynamicPort(60000));
    EXPECT_TRUE(NetworkUtils::isDynamicPort(65535));
    EXPECT_FALSE(NetworkUtils::isDynamicPort(49151));
}

TEST_F(NetworkUtilsTest, TestGetPortService)
{
    // Common well-known ports
    EXPECT_EQ(NetworkUtils::getPortService(80), "HTTP");
    EXPECT_EQ(NetworkUtils::getPortService(443), "HTTPS");
    EXPECT_EQ(NetworkUtils::getPortService(22), "SSH");
    EXPECT_EQ(NetworkUtils::getPortService(21), "FTP");
    EXPECT_EQ(NetworkUtils::getPortService(25), "SMTP");
    EXPECT_EQ(NetworkUtils::getPortService(53), "DNS");

    // Unknown port
    std::string service = NetworkUtils::getPortService(12345);
    EXPECT_TRUE(service == "UNKNOWN" || !service.empty()); // May return system service name
}

// ==================== Protocol Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestProtocolNameMapping)
{
    // Common protocols
    EXPECT_EQ(NetworkUtils::getProtocolName(1), "ICMP");
    EXPECT_EQ(NetworkUtils::getProtocolName(6), "TCP");
    EXPECT_EQ(NetworkUtils::getProtocolName(17), "UDP");
    EXPECT_EQ(NetworkUtils::getProtocolName(58), "ICMPv6");

    // Reverse mapping
    EXPECT_EQ(NetworkUtils::getProtocolNumber("TCP"), 6);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("UDP"), 17);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("ICMP"), 1);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("tcp"), 6); // Should handle lowercase

    // Unknown protocol
    EXPECT_EQ(NetworkUtils::getProtocolName(255), "UNKNOWN");
    EXPECT_EQ(NetworkUtils::getProtocolNumber("UNKNOWN_PROTOCOL"), -1);
}

TEST_F(NetworkUtilsTest, TestProtocolChecks)
{
    EXPECT_TRUE(NetworkUtils::isTCPProtocol(6));
    EXPECT_FALSE(NetworkUtils::isTCPProtocol(17));

    EXPECT_TRUE(NetworkUtils::isUDPProtocol(17));
    EXPECT_FALSE(NetworkUtils::isUDPProtocol(6));

    EXPECT_TRUE(NetworkUtils::isICMPProtocol(1));
    EXPECT_TRUE(NetworkUtils::isICMPProtocol(58)); // ICMPv6
    EXPECT_FALSE(NetworkUtils::isICMPProtocol(6));
}

// ==================== MAC Address Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestMACValidation)
{
    // Valid MAC addresses
    EXPECT_TRUE(NetworkUtils::isValidMAC("00:11:22:33:44:55"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("AA:BB:CC:DD:EE:FF"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("00-11-22-33-44-55"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("001122334455"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("aabbccddeeff"));

    // Invalid MAC addresses
    EXPECT_FALSE(NetworkUtils::isValidMAC("00:11:22:33:44"));
    EXPECT_FALSE(NetworkUtils::isValidMAC("00:11:22:33:44:55:66"));
    EXPECT_FALSE(NetworkUtils::isValidMAC("GG:11:22:33:44:55"));
    EXPECT_FALSE(NetworkUtils::isValidMAC("00:11:22:33:44:ZZ"));
    EXPECT_FALSE(NetworkUtils::isValidMAC(""));
    EXPECT_FALSE(NetworkUtils::isValidMAC("invalid_mac"));
}

TEST_F(NetworkUtilsTest, TestMACNormalization)
{
    // Test normalization
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("00:11:22:33:44:55"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("00-11-22-33-44-55"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("001122334455"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("aabbccddeeff"), "AA:BB:CC:DD:EE:FF");

    // Invalid MAC should return empty string
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("invalid"), "");
}

TEST_F(NetworkUtilsTest, TestMACVendorLookup)
{
    // Test known vendors (based on our simple implementation)
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("00:00:0C:12:34:56"), "Cisco Systems");
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("00:0C:29:12:34:56"), "VMware");
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("08:00:27:12:34:56"), "PCS Systemtechnik GmbH");

    // Unknown vendor
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("FF:FF:FF:12:34:56"), "UNKNOWN");

    // Invalid MAC
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("invalid"), "UNKNOWN");
}

// ==================== DNS Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestDomainValidation)
{
    // Valid domain names
    EXPECT_TRUE(NetworkUtils::isValidDomainName("example.com"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("sub.example.com"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("test-site.example.org"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("a.b.c.d.example.net"));

    // Invalid domain names
    EXPECT_FALSE(NetworkUtils::isValidDomainName(""));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(".example.com"));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("example.com."));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("example..com"));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("-example.com"));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("example-.com"));
}

// Note: DNS resolution tests are commented out as they require network access
// and may be unreliable in test environments
/*
TEST_F(NetworkUtilsTest, TestDNSResolution)
{
    // Test hostname resolution (may fail if no network)
    std::string hostname = NetworkUtils::resolveHostname("8.8.8.8");
    // Don't assert specific result as it may vary

    // Test IP resolution (may fail if no network)
    auto ips = NetworkUtils::resolveIP("google.com");
    // Don't assert specific result as it may vary
}
*/

// ==================== Network Calculation Tests ====================

TEST_F(NetworkUtilsTest, TestSubnetCalculations)
{
    // Test subnet mask calculation
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(24), 0xFFFFFF00);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(16), 0xFFFF0000);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(8), 0xFF000000);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(0), 0x00000000);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(32), 0xFFFFFFFF);

    // Test prefix length calculation
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0xFFFFFF00), 24);
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0xFFFF0000), 16);
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0xFF000000), 8);
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0x00000000), 0);
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0xFFFFFFFF), 32);

    // Test network address calculation
    uint32_t ip = NetworkUtils::ipStringToInt("192.168.1.100");
    uint32_t network = NetworkUtils::calculateNetworkAddress(ip, 24);
    EXPECT_EQ(NetworkUtils::ipIntToString(network), "192.168.1.0");

    // Test broadcast address calculation
    uint32_t broadcast = NetworkUtils::calculateBroadcastAddress(ip, 24);
    EXPECT_EQ(NetworkUtils::ipIntToString(broadcast), "192.168.1.255");
}

// ==================== Traffic Analysis Tests ====================

TEST_F(NetworkUtilsTest, TestTrafficCalculations)
{
    // Test packet rate calculation
    double packet_rate = NetworkUtils::calculatePacketRate(1000, 1000); // 1000 packets in 1 second
    EXPECT_DOUBLE_EQ(packet_rate, 1000.0);

    packet_rate = NetworkUtils::calculatePacketRate(500, 2000); // 500 packets in 2 seconds
    EXPECT_DOUBLE_EQ(packet_rate, 250.0);

    // Test bit rate calculation
    double bit_rate = NetworkUtils::calculateBitRate(1000, 1000); // 1000 bytes in 1 second
    EXPECT_DOUBLE_EQ(bit_rate, 8000.0); // 8000 bits per second

    bit_rate = NetworkUtils::calculateBitRate(125, 1000); // 125 bytes in 1 second
    EXPECT_DOUBLE_EQ(bit_rate, 1000.0); // 1000 bits per second

    // Test utilization calculation
    double utilization = NetworkUtils::calculateUtilization(125, 1000, 1000); // 125 bytes/sec on 1000 bps link
    EXPECT_DOUBLE_EQ(utilization, 100.0); // 100% utilization

    utilization = NetworkUtils::calculateUtilization(62.5, 1000, 1000); // 62.5 bytes/sec on 1000 bps link
    EXPECT_DOUBLE_EQ(utilization, 50.0); // 50% utilization

    // Test edge cases
    EXPECT_DOUBLE_EQ(NetworkUtils::calculatePacketRate(100, 0), 0.0);
    EXPECT_DOUBLE_EQ(NetworkUtils::calculateBitRate(100, 0), 0.0);
    EXPECT_DOUBLE_EQ(NetworkUtils::calculateUtilization(100, 0, 1000), 0.0);
    EXPECT_DOUBLE_EQ(NetworkUtils::calculateUtilization(100, 1000, 0), 0.0);
}

// ==================== NetworkStatsCollector Tests ====================

TEST_F(NetworkUtilsTest, TestNetworkStatsCollector)
{
    NetworkStatsCollector collector;

    // Initial stats should be zero
    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 0);
    EXPECT_EQ(stats.total_bytes, 0);
    EXPECT_EQ(stats.tcp_packets, 0);
    EXPECT_EQ(stats.udp_packets, 0);
    EXPECT_EQ(stats.icmp_packets, 0);
    EXPECT_EQ(stats.other_packets, 0);

    // Update stats with TCP packet
    collector.updateStats(100, 6); // TCP
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 1);
    EXPECT_EQ(stats.total_bytes, 100);
    EXPECT_EQ(stats.tcp_packets, 1);
    EXPECT_EQ(stats.udp_packets, 0);
    EXPECT_DOUBLE_EQ(stats.average_packet_size, 100.0);

    // Update stats with UDP packet
    collector.updateStats(200, 17); // UDP
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 2);
    EXPECT_EQ(stats.total_bytes, 300);
    EXPECT_EQ(stats.tcp_packets, 1);
    EXPECT_EQ(stats.udp_packets, 1);
    EXPECT_DOUBLE_EQ(stats.average_packet_size, 150.0);

    // Update stats with ICMP packet
    collector.updateStats(50, 1); // ICMP
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 3);
    EXPECT_EQ(stats.total_bytes, 350);
    EXPECT_EQ(stats.icmp_packets, 1);

    // Update stats with other protocol
    collector.updateStats(75, 89); // OSPF
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 4);
    EXPECT_EQ(stats.total_bytes, 425);
    EXPECT_EQ(stats.other_packets, 1);

    // Test reset
    collector.resetStats();
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 0);
    EXPECT_EQ(stats.total_bytes, 0);
    EXPECT_EQ(stats.tcp_packets, 0);
    EXPECT_EQ(stats.udp_packets, 0);
    EXPECT_EQ(stats.icmp_packets, 0);
    EXPECT_EQ(stats.other_packets, 0);
}

TEST_F(NetworkUtilsTest, TestNetworkStatsCollectorThreadSafety)
{
    NetworkStatsCollector collector;
    const int num_threads = 10;
    const int packets_per_thread = 100;

    std::vector<std::thread> threads;

    // Launch multiple threads to update stats concurrently
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&collector, packets_per_thread]() {
            for (int j = 0; j < packets_per_thread; ++j) {
                collector.updateStats(100, 6); // TCP packets
            }
        });
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Verify final stats
    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, num_threads * packets_per_thread);
    EXPECT_EQ(stats.total_bytes, num_threads * packets_per_thread * 100);
    EXPECT_EQ(stats.tcp_packets, num_threads * packets_per_thread);
}

// ==================== Geolocation Tests ====================

TEST_F(NetworkUtilsTest, TestGeolocation)
{
    // Test private IP geolocation
    auto location = NetworkUtils::getIPGeolocation("192.168.1.1");
    EXPECT_EQ(location.country, "Private/Local");
    EXPECT_EQ(location.country_code, "PR");

    // Test loopback IP geolocation
    location = NetworkUtils::getIPGeolocation("127.0.0.1");
    EXPECT_EQ(location.country, "Private/Local");
    EXPECT_EQ(location.country_code, "PR");

    // Test country check
    EXPECT_TRUE(NetworkUtils::isIPFromCountry("192.168.1.1", "PR"));
    EXPECT_FALSE(NetworkUtils::isIPFromCountry("192.168.1.1", "US"));
}

// ==================== Performance Tests ====================

TEST_F(NetworkUtilsTest, TestPerformance)
{
    auto start = std::chrono::high_resolution_clock::now();

    // Test IP validation performance
    for (int i = 0; i < 10000; ++i) {
        NetworkUtils::isValidIPv4("192.168.1." + std::to_string(i % 256));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete within reasonable time (adjust threshold as needed)
    EXPECT_LT(duration.count(), 1000); // Less than 1 second

    // Test IP conversion performance
    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; ++i) {
        uint32_t ip_int = NetworkUtils::ipStringToInt("192.168.1.1");
        NetworkUtils::ipIntToString(ip_int);
    }

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_LT(duration.count(), 1000); // Less than 1 second
}

// ==================== Edge Cases Tests ====================

TEST_F(NetworkUtilsTest, TestEdgeCases)
{
    // Test with empty strings
    EXPECT_FALSE(NetworkUtils::isValidIPv4(""));
    EXPECT_FALSE(NetworkUtils::isValidIPv6(""));
    EXPECT_FALSE(NetworkUtils::isValidMAC(""));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(""));

    // Test with very long strings
    std::string long_string(1000, 'a');
    EXPECT_FALSE(NetworkUtils::isValidIPv4(long_string));
    EXPECT_FALSE(NetworkUtils::isValidIPv6(long_string));
    EXPECT_FALSE(NetworkUtils::isValidMAC(long_string));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(long_string));

    // Test boundary values for ports
    EXPECT_FALSE(NetworkUtils::isValidPort(0));
    EXPECT_TRUE(NetworkUtils::isValidPort(1));
    EXPECT_TRUE(NetworkUtils::isValidPort(65535));
    EXPECT_FALSE(NetworkUtils::isValidPort(65536));

    // Test boundary values for prefix length
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(-1), 0);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(33), 0);

    // Test IP range with edge cases
    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.1.1", "192.168.1.0", -1));
    EXPECT_FALSE(NetworkUtils::isIPInRange("192.168.1.1", "192.168.1.0", 33));

    // Test CIDR expansion with edge cases
    auto ips = NetworkUtils::expandCIDR("192.168.1.0/32");
    EXPECT_EQ(ips.size(), 0); // /32 has no host addresses

    ips = NetworkUtils::expandCIDR("192.168.1.0/31");
    EXPECT_EQ(ips.size(), 0); // /31 has no host addresses (point-to-point)

    // Test MAC address edge cases
    EXPECT_TRUE(NetworkUtils::isValidMAC("00:00:00:00:00:00"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("FF:FF:FF:FF:FF:FF"));
    EXPECT_FALSE(NetworkUtils::isValidMAC("00:00:00:00:00:GG"));

    // Test protocol edge cases
    EXPECT_EQ(NetworkUtils::getProtocolName(0), "UNKNOWN");
    EXPECT_EQ(NetworkUtils::getProtocolName(256), "UNKNOWN");
    EXPECT_EQ(NetworkUtils::getProtocolNumber(""), -1);
}

// ==================== Integration Tests ====================

TEST_F(NetworkUtilsTest, TestIntegrationScenarios)
{
    // Scenario 1: Network analysis workflow
    std::string network = "192.168.1.0/24";
    std::string test_ip = "192.168.1.100";

    // Check if IP is in network
    EXPECT_TRUE(NetworkUtils::isIPInCIDR(test_ip, network));

    // Check IP properties
    EXPECT_TRUE(NetworkUtils::isValidIPv4(test_ip));
    EXPECT_TRUE(NetworkUtils::isPrivateIP(test_ip));
    EXPECT_FALSE(NetworkUtils::isLoopbackIP(test_ip));
    EXPECT_FALSE(NetworkUtils::isMulticastIP(test_ip));

    // Calculate network properties
    uint32_t ip_int = NetworkUtils::ipStringToInt(test_ip);
    uint32_t network_addr = NetworkUtils::calculateNetworkAddress(ip_int, 24);
    uint32_t broadcast_addr = NetworkUtils::calculateBroadcastAddress(ip_int, 24);

    EXPECT_EQ(NetworkUtils::ipIntToString(network_addr), "192.168.1.0");
    EXPECT_EQ(NetworkUtils::ipIntToString(broadcast_addr), "192.168.1.255");

    // Scenario 2: Traffic analysis workflow
    NetworkStatsCollector collector;

    // Simulate network traffic
    collector.updateStats(100, 6);  // TCP packet
    collector.updateStats(200, 17); // UDP packet
    collector.updateStats(50, 1);   // ICMP packet

    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 3);
    EXPECT_EQ(stats.total_bytes, 350);
    EXPECT_EQ(stats.tcp_packets, 1);
    EXPECT_EQ(stats.udp_packets, 1);
    EXPECT_EQ(stats.icmp_packets, 1);

    // Scenario 3: Port and protocol analysis
    int port = 80;
    int protocol = 6;

    EXPECT_TRUE(NetworkUtils::isValidPort(port));
    EXPECT_TRUE(NetworkUtils::isWellKnownPort(port));
    EXPECT_EQ(NetworkUtils::getPortService(port), "HTTP");

    EXPECT_TRUE(NetworkUtils::isTCPProtocol(protocol));
    EXPECT_EQ(NetworkUtils::getProtocolName(protocol), "TCP");

    // Scenario 4: MAC address analysis
    std::string mac = "00:0C:29:12:34:56";
    EXPECT_TRUE(NetworkUtils::isValidMAC(mac));
    EXPECT_EQ(NetworkUtils::normalizeMACAddress(mac), "00:0C:29:12:34:56");
    EXPECT_EQ(NetworkUtils::getVendorFromMAC(mac), "VMware");
}

// ==================== Stress Tests ====================

TEST_F(NetworkUtilsTest, TestStressScenarios)
{
    // Stress test: Multiple concurrent stats collectors
    const int num_collectors = 5;
    const int updates_per_collector = 1000;

    std::vector<std::unique_ptr<NetworkStatsCollector>> collectors;
    std::vector<std::thread> threads;

    // Create collectors
    for (int i = 0; i < num_collectors; ++i) {
        collectors.push_back(std::make_unique<NetworkStatsCollector>());
    }

    // Launch threads to update each collector
    for (int i = 0; i < num_collectors; ++i) {
        threads.emplace_back([&collectors, i, updates_per_collector]() {
            for (int j = 0; j < updates_per_collector; ++j) {
                collectors[i]->updateStats(100 + j % 100, 6); // Varying packet sizes
            }
        });
    }

    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }

    // Verify all collectors have correct stats
    for (int i = 0; i < num_collectors; ++i) {
        NetworkStats stats = collectors[i]->getStats();
        EXPECT_EQ(stats.total_packets, updates_per_collector);
        EXPECT_EQ(stats.tcp_packets, updates_per_collector);
        EXPECT_GT(stats.total_bytes, 0);
    }

    // Stress test: Large CIDR expansion (but limit size for test)
    auto ips = NetworkUtils::expandCIDR("192.168.1.0/28"); // /28 = 14 hosts
    EXPECT_EQ(ips.size(), 14);

    // Verify all IPs are valid and in range
    for (const auto& ip : ips) {
        EXPECT_TRUE(NetworkUtils::isValidIPv4(ip));
        EXPECT_TRUE(NetworkUtils::isIPInCIDR(ip, "192.168.1.0/28"));
    }
}

// ==================== Regression Tests ====================

TEST_F(NetworkUtilsTest, TestRegressionCases)
{
    // Regression test: Ensure IP conversion is bidirectional
    std::vector<std::string> test_ips = {
        "0.0.0.0", "127.0.0.1", "192.168.1.1", "10.0.0.1",
        "172.16.0.1", "8.8.8.8", "255.255.255.255"
    };

    for (const auto& ip : test_ips) {
        uint32_t ip_int = NetworkUtils::ipStringToInt(ip);
        std::string converted_back = NetworkUtils::ipIntToString(ip_int);
        EXPECT_EQ(ip, converted_back) << "Failed for IP: " << ip;
    }

    // Regression test: Ensure subnet calculations are consistent
    struct SubnetTest {
        std::string ip;
        int prefix;
        std::string expected_network;
        std::string expected_broadcast;
    };

    std::vector<SubnetTest> subnet_tests = {
        {"192.168.1.100", 24, "192.168.1.0", "192.168.1.255"},
        {"10.0.5.10", 8, "10.0.0.0", "10.255.255.255"},
        {"172.16.10.20", 12, "172.16.0.0", "172.31.255.255"},
        {"192.168.1.1", 30, "192.168.1.0", "192.168.1.3"}
    };

    for (const auto& test : subnet_tests) {
        uint32_t ip_int = NetworkUtils::ipStringToInt(test.ip);
        uint32_t network = NetworkUtils::calculateNetworkAddress(ip_int, test.prefix);
        uint32_t broadcast = NetworkUtils::calculateBroadcastAddress(ip_int, test.prefix);

        EXPECT_EQ(NetworkUtils::ipIntToString(network), test.expected_network)
            << "Network calculation failed for " << test.ip << "/" << test.prefix;
        EXPECT_EQ(NetworkUtils::ipIntToString(broadcast), test.expected_broadcast)
            << "Broadcast calculation failed for " << test.ip << "/" << test.prefix;
    }

    // Regression test: Ensure MAC normalization is consistent
    std::vector<std::pair<std::string, std::string>> mac_tests = {
        {"00:11:22:33:44:55", "00:11:22:33:44:55"},
        {"00-11-22-33-44-55", "00:11:22:33:44:55"},
        {"001122334455", "00:11:22:33:44:55"},
        {"aabbccddeeff", "AA:BB:CC:DD:EE:FF"},
        {"AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"}
    };

    for (const auto& test : mac_tests) {
        std::string normalized = NetworkUtils::normalizeMACAddress(test.first);
        EXPECT_EQ(normalized, test.second)
            << "MAC normalization failed for " << test.first;
    }
}

// ==================== Main Test Runner ====================

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
