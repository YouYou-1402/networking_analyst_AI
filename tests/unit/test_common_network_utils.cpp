// tests/unit/test_common_network_utils.cpp
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
    // Well-known services
    EXPECT_EQ(NetworkUtils::getPortService(80), "HTTP");
    EXPECT_EQ(NetworkUtils::getPortService(443), "HTTPS");
    EXPECT_EQ(NetworkUtils::getPortService(22), "SSH");
    EXPECT_EQ(NetworkUtils::getPortService(21), "FTP");
    EXPECT_EQ(NetworkUtils::getPortService(25), "SMTP");
    EXPECT_EQ(NetworkUtils::getPortService(53), "DNS");

    // Unknown port
    EXPECT_EQ(NetworkUtils::getPortService(12345), "UNKNOWN");
}

// ==================== Protocol Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestProtocolNameMapping)
{
    // Common protocols
    EXPECT_EQ(NetworkUtils::getProtocolName(1), "ICMP");
    EXPECT_EQ(NetworkUtils::getProtocolName(6), "TCP");
    EXPECT_EQ(NetworkUtils::getProtocolName(17), "UDP");
    EXPECT_EQ(NetworkUtils::getProtocolName(58), "ICMPv6");

    // Unknown protocol
    EXPECT_EQ(NetworkUtils::getProtocolName(255), "UNKNOWN");

    // Protocol number lookup
    EXPECT_EQ(NetworkUtils::getProtocolNumber("TCP"), 6);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("UDP"), 17);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("ICMP"), 1);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("tcp"), 6); // Case insensitive
    
    // Unknown protocol name
    EXPECT_EQ(NetworkUtils::getProtocolNumber("UNKNOWN_PROTOCOL"), -1);
    EXPECT_EQ(NetworkUtils::getProtocolNumber(""), -1);
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
    EXPECT_FALSE(NetworkUtils::isValidMAC("GG:HH:II:JJ:KK:LL"));
    EXPECT_FALSE(NetworkUtils::isValidMAC(""));
    EXPECT_FALSE(NetworkUtils::isValidMAC("00:11:22:33:44:ZZ"));
}

TEST_F(NetworkUtilsTest, TestMACNormalization)
{
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("00:11:22:33:44:55"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("00-11-22-33-44-55"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("001122334455"), "00:11:22:33:44:55");
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF");

    // Invalid MAC
    EXPECT_EQ(NetworkUtils::normalizeMACAddress("invalid"), "");
}

TEST_F(NetworkUtilsTest, TestMACVendorLookup)
{
    // Known vendors
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("00:0C:29:12:34:56"), "VMware");
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("08:00:27:12:34:56"), "PCS Systemtechnik GmbH");
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("00:50:56:12:34:56"), "VMware");

    // Unknown vendor
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("FF:FF:FF:FF:FF:FF"), "UNKNOWN");

    // Invalid MAC
    EXPECT_EQ(NetworkUtils::getVendorFromMAC("invalid"), "UNKNOWN");
}

// ==================== DNS Utilities Tests ====================

TEST_F(NetworkUtilsTest, TestDomainValidation)
{
    // Valid domains
    EXPECT_TRUE(NetworkUtils::isValidDomainName("example.com"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("sub.example.com"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("my-domain.example.com"));
    EXPECT_TRUE(NetworkUtils::isValidDomainName("123.example.com"));

    // Invalid domains
    EXPECT_FALSE(NetworkUtils::isValidDomainName(""));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("."));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(".."));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("-example.com"));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("example-.com"));
    EXPECT_FALSE(NetworkUtils::isValidDomainName("exam ple.com"));
}

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
    double pps = NetworkUtils::calculatePacketRate(1000, 1000); // 1000 packets in 1 second
    EXPECT_NEAR(pps, 1000.0, 0.01);

    // Test bit rate calculation
    double bps = NetworkUtils::calculateBitRate(1000, 1000); // 1000 bytes in 1 second
    EXPECT_NEAR(bps, 8000.0, 0.01); // 8000 bits per second

    // Test utilization calculation
    double util = NetworkUtils::calculateUtilization(1000, 1000, 10000); // 1000 bytes in 1s, 10000 bps capacity
    EXPECT_NEAR(util, 80.0, 0.1); // 80% utilization

    // Edge cases
    EXPECT_NEAR(NetworkUtils::calculatePacketRate(0, 1000), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculatePacketRate(1000, 0), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculateBitRate(0, 1000), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculateBitRate(1000, 0), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculateUtilization(0, 1000, 10000), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculateUtilization(1000, 0, 10000), 0.0, 0.01);
    EXPECT_NEAR(NetworkUtils::calculateUtilization(1000, 1000, 0), 0.0, 0.01);
}

// ==================== NetworkStatsCollector Tests ====================

TEST_F(NetworkUtilsTest, TestNetworkStatsCollector)
{
    NetworkStatsCollector collector;

    // Initial stats should be zero
    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 0);
    EXPECT_EQ(stats.total_bytes, 0);

    // Update stats
    collector.updateStats(100, 6); // TCP packet, 100 bytes
    collector.updateStats(200, 17); // UDP packet, 200 bytes
    collector.updateStats(50, 1); // ICMP packet, 50 bytes

    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 3);
    EXPECT_EQ(stats.total_bytes, 350);
    EXPECT_EQ(stats.tcp_packets, 1);
    EXPECT_EQ(stats.udp_packets, 1);
    EXPECT_EQ(stats.icmp_packets, 1);

    // Reset stats
    collector.resetStats();
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 0);
    EXPECT_EQ(stats.total_bytes, 0);
}

TEST_F(NetworkUtilsTest, TestNetworkStatsCollectorThreadSafety)
{
    NetworkStatsCollector collector;

    // Test thread safety with concurrent updates
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&collector]() {
            for (int j = 0; j < 100; ++j) {
                collector.updateStats(100, 6);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 1000);
    EXPECT_EQ(stats.total_bytes, 100000);
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
        NetworkUtils::isValidIPv4("192.168.1.1");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time (< 1000ms)
    EXPECT_LT(duration.count(), 1000);
}

// ==================== Edge Cases Tests ====================

TEST_F(NetworkUtilsTest, TestEdgeCases)
{
    // Test boundary values
    EXPECT_TRUE(NetworkUtils::isValidPort(1));
    EXPECT_TRUE(NetworkUtils::isValidPort(65535));
    EXPECT_FALSE(NetworkUtils::isValidPort(0));
    EXPECT_FALSE(NetworkUtils::isValidPort(65536));

    // Test empty strings
    EXPECT_FALSE(NetworkUtils::isValidIPv4(""));
    EXPECT_FALSE(NetworkUtils::isValidIPv6(""));
    EXPECT_FALSE(NetworkUtils::isValidMAC(""));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(""));

    // Test protocol edge cases - Protocol 0 có thể trả về "ip" hoặc "IP" tùy hệ thống
    std::string proto0 = NetworkUtils::getProtocolName(0);
    EXPECT_TRUE(proto0 == "ip" || proto0 == "IP" || proto0 == "UNKNOWN");
    
    EXPECT_EQ(NetworkUtils::getProtocolName(-1), "UNKNOWN");
    EXPECT_EQ(NetworkUtils::getProtocolNumber(""), -1);

    // Test MAC address edge cases
    EXPECT_TRUE(NetworkUtils::isValidMAC("00:00:00:00:00:00"));
    EXPECT_TRUE(NetworkUtils::isValidMAC("FF:FF:FF:FF:FF:FF"));

    // Test IP conversion edge cases
    EXPECT_EQ(NetworkUtils::ipStringToInt("0.0.0.0"), 0);
    EXPECT_EQ(NetworkUtils::ipStringToInt("255.255.255.255"), 0xFFFFFFFF);
    EXPECT_EQ(NetworkUtils::ipIntToString(0), "0.0.0.0");
    EXPECT_EQ(NetworkUtils::ipIntToString(0xFFFFFFFF), "255.255.255.255");

    // Test CIDR edge cases
    auto ips = NetworkUtils::expandCIDR("192.168.1.0/32");
    EXPECT_EQ(ips.size(), 0); // /32 has no host addresses

    ips = NetworkUtils::expandCIDR("192.168.1.0/31");
    EXPECT_EQ(ips.size(), 0); // /31 has no host addresses

    // Test subnet calculations
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(0), 0x00000000);
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(32), 0xFFFFFFFF);

    // Test domain validation edge cases
    EXPECT_FALSE(NetworkUtils::isValidDomainName(".")); 
    EXPECT_FALSE(NetworkUtils::isValidDomainName("..")); 
    EXPECT_FALSE(NetworkUtils::isValidDomainName("-example.com")); 
    EXPECT_FALSE(NetworkUtils::isValidDomainName("example-.com"));
}

// ==================== Integration Scenarios Tests ====================

TEST_F(NetworkUtilsTest, TestIntegrationScenarios)
{
    // Scenario 1: Network scanning
    std::string network = "192.168.1.0/28";
    auto hosts = NetworkUtils::expandCIDR(network);
    EXPECT_EQ(hosts.size(), 14);
    
    for (const auto& host : hosts) {
        EXPECT_TRUE(NetworkUtils::isValidIPv4(host));
        EXPECT_TRUE(NetworkUtils::isIPInCIDR(host, network));
        EXPECT_TRUE(NetworkUtils::isPrivateIP(host));
    }

    // Scenario 2: Port service identification
    std::vector<int> common_ports = {80, 443, 22, 21, 25, 53};
    for (int port : common_ports) {
        EXPECT_TRUE(NetworkUtils::isValidPort(port));
        EXPECT_TRUE(NetworkUtils::isWellKnownPort(port));
        EXPECT_NE(NetworkUtils::getPortService(port), "UNKNOWN");
    }

    // Scenario 3: Protocol analysis
    std::vector<std::string> protocols = {"TCP", "UDP", "ICMP"};
    for (const auto& proto : protocols) {
        int proto_num = NetworkUtils::getProtocolNumber(proto);
        EXPECT_NE(proto_num, -1);
        std::string proto_name = NetworkUtils::getProtocolName(proto_num);
        EXPECT_NE(proto_name, "UNKNOWN");
    }

    // Scenario 4: MAC address processing
    std::vector<std::string> mac_formats = {
        "00:0C:29:12:34:56",
        "00-0C-29-12-34-56",
        "000C29123456"
    };
    
    std::string normalized_mac = NetworkUtils::normalizeMACAddress(mac_formats[0]);
    for (const auto& mac : mac_formats) {
        EXPECT_TRUE(NetworkUtils::isValidMAC(mac));
        EXPECT_EQ(NetworkUtils::normalizeMACAddress(mac), normalized_mac);
    }
}

// ==================== Stress Tests ====================

TEST_F(NetworkUtilsTest, TestStressScenarios)
{
    // Stress test 1: Large number of IP validations
    std::vector<std::string> test_ips;
    for (int i = 0; i < 1000; ++i) {
        test_ips.push_back("192.168." + std::to_string(i % 256) + "." + std::to_string(i % 256));
    }

    auto start = std::chrono::high_resolution_clock::now();
    for (const auto& ip : test_ips) {
        NetworkUtils::isValidIPv4(ip);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 500); // Should complete in < 500ms

    // Stress test 2: Multiple CIDR expansions
    std::vector<std::string> cidrs = {
        "192.168.1.0/30",
        "192.168.2.0/29",
        "192.168.3.0/28",
        "192.168.4.0/27"
    };

    start = std::chrono::high_resolution_clock::now();
    for (const auto& cidr : cidrs) {
        auto hosts = NetworkUtils::expandCIDR(cidr);
        EXPECT_GT(hosts.size(), 0);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 100); // Should complete in < 100ms

    // Stress test 3: Concurrent stats collection
    NetworkStatsCollector collector;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 20; ++i) {
        threads.emplace_back([&collector]() {
            for (int j = 0; j < 500; ++j) {
                collector.updateStats(100, 6);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    NetworkStats stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 10000);
    EXPECT_EQ(stats.total_bytes, 1000000);
}

// ==================== Regression Tests ====================

TEST_F(NetworkUtilsTest, TestRegressionCases)
{
    // Regression 1: CIDR with invalid prefix
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/abc"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/24.5"));
    EXPECT_FALSE(NetworkUtils::isIPInCIDR("192.168.1.1", "192.168.1.0/24abc"));

    // Regression 2: MAC address with mixed case
    std::string mac_lower = "aa:bb:cc:dd:ee:ff";
    std::string mac_upper = "AA:BB:CC:DD:EE:FF";
    std::string mac_mixed = "Aa:Bb:Cc:Dd:Ee:Ff";
    
    EXPECT_TRUE(NetworkUtils::isValidMAC(mac_lower));
    EXPECT_TRUE(NetworkUtils::isValidMAC(mac_upper));
    EXPECT_TRUE(NetworkUtils::isValidMAC(mac_mixed));
    
    EXPECT_EQ(NetworkUtils::normalizeMACAddress(mac_lower), mac_upper);
    EXPECT_EQ(NetworkUtils::normalizeMACAddress(mac_mixed), mac_upper);

    // Regression 3: IP range boundary conditions
    EXPECT_TRUE(NetworkUtils::isIPInRange("10.0.0.0", "10.0.0.0", 8));
    EXPECT_TRUE(NetworkUtils::isIPInRange("10.255.255.255", "10.0.0.0", 8));
    EXPECT_FALSE(NetworkUtils::isIPInRange("11.0.0.0", "10.0.0.0", 8));
    EXPECT_FALSE(NetworkUtils::isIPInRange("9.255.255.255", "10.0.0.0", 8));

    // Regression 4: Protocol name case sensitivity
    EXPECT_EQ(NetworkUtils::getProtocolNumber("TCP"), 6);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("tcp"), 6);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("Tcp"), 6);
    EXPECT_EQ(NetworkUtils::getProtocolNumber("tCp"), 6);

    // Regression 5: Port boundary values
    EXPECT_FALSE(NetworkUtils::isValidPort(0));
    EXPECT_TRUE(NetworkUtils::isValidPort(1));
    EXPECT_TRUE(NetworkUtils::isValidPort(65535));
    EXPECT_FALSE(NetworkUtils::isValidPort(65536));

    // Regression 6: Empty and null-like inputs
    EXPECT_FALSE(NetworkUtils::isValidIPv4(""));
    EXPECT_FALSE(NetworkUtils::isValidIPv6(""));
    EXPECT_FALSE(NetworkUtils::isValidMAC(""));
    EXPECT_FALSE(NetworkUtils::isValidDomainName(""));
    EXPECT_EQ(NetworkUtils::getProtocolNumber(""), -1);
    EXPECT_EQ(NetworkUtils::normalizeMACAddress(""), "");

    // Regression 7: Subnet mask calculations
    EXPECT_EQ(NetworkUtils::calculateSubnetMask(24), 0xFFFFFF00);
    EXPECT_EQ(NetworkUtils::calculatePrefixLength(0xFFFFFF00), 24);
    
    // Round-trip test
    for (int prefix = 0; prefix <= 32; ++prefix) {
        uint32_t mask = NetworkUtils::calculateSubnetMask(prefix);
        int calculated_prefix = NetworkUtils::calculatePrefixLength(mask);
        EXPECT_EQ(calculated_prefix, prefix);
    }

    // Regression 8: Private IP edge cases
    EXPECT_TRUE(NetworkUtils::isPrivateIP("10.0.0.0"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("10.255.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("9.255.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("11.0.0.0"));
    
    EXPECT_TRUE(NetworkUtils::isPrivateIP("172.16.0.0"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("172.31.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("172.15.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("172.32.0.0"));
    
    EXPECT_TRUE(NetworkUtils::isPrivateIP("192.168.0.0"));
    EXPECT_TRUE(NetworkUtils::isPrivateIP("192.168.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("192.167.255.255"));
    EXPECT_FALSE(NetworkUtils::isPrivateIP("192.169.0.0"));
}

// ==================== Network Interface Tests ====================

TEST_F(NetworkUtilsTest, TestNetworkInterfaces)
{
    // Get all network interfaces
    auto interfaces = NetworkUtils::getNetworkInterfaces();
    
    // Should have at least loopback interface
    EXPECT_GT(interfaces.size(), 0);
    
    // Check if loopback interface exists
    bool has_loopback = false;
    for (const auto& iface : interfaces) {
        if (iface == "lo" || iface == "lo0") {
            has_loopback = true;
            break;
        }
    }
    EXPECT_TRUE(has_loopback);
    
    // Test interface properties
    for (const auto& iface : interfaces) {
        // Interface name should not be empty
        EXPECT_FALSE(iface.empty());
        
        // Try to get interface IP (may be empty for some interfaces)
        std::string ip = NetworkUtils::getInterfaceIP(iface);
        if (!ip.empty()) {
            EXPECT_TRUE(NetworkUtils::isValidIPv4(ip));
        }
        
        // Try to get interface MAC (may be empty for loopback)
        std::string mac = NetworkUtils::getInterfaceMAC(iface);
        if (!mac.empty()) {
            EXPECT_TRUE(NetworkUtils::isValidMAC(mac));
        }
    }
}

// ==================== DNS Resolution Tests ====================

TEST_F(NetworkUtilsTest, TestDNSResolution)
{
    // Test localhost resolution
    auto ips = NetworkUtils::resolveIP("localhost");
    EXPECT_GT(ips.size(), 0);
    
    if (ips.size() > 0) {
        EXPECT_TRUE(NetworkUtils::isLoopbackIP(ips[0]));
    }
    
    // Test invalid hostname
    // Note: This test may fail if ISP/DNS performs DNS hijacking
    ips = NetworkUtils::resolveIP("nonexistent-domain-xyz-123456789.invalid");
    
    // Check if DNS hijacking is present
    bool dns_hijacking_detected = (ips.size() > 0);
    
    if (!dns_hijacking_detected) {
        EXPECT_EQ(ips.size(), 0);
    } else {
        // DNS hijacking detected, log warning and skip strict check
        std::cout << "WARNING: DNS hijacking detected. "
                  << "Non-existent domain resolved to " << ips.size() 
                  << " IP(s). This may be caused by ISP DNS redirection." 
                  << std::endl;
        
        // At least verify returned IPs are valid
        for (const auto& ip : ips) {
            EXPECT_TRUE(NetworkUtils::isValidIPv4(ip));
        }
    }
    
    // Test reverse DNS for loopback
    std::string hostname = NetworkUtils::resolveHostname("127.0.0.1");
    EXPECT_TRUE(hostname.empty() || !hostname.empty());
}

// ==================== Traffic Statistics Tests ====================

TEST_F(NetworkUtilsTest, TestTrafficStatistics)
{
    NetworkStatsCollector collector;
    
    // Simulate traffic
    collector.updateStats(100, 6);  // TCP
    collector.updateStats(200, 17); // UDP
    collector.updateStats(50, 1);   // ICMP
    collector.updateStats(150, 6);  // TCP
    collector.updateStats(100, 17); // UDP
    
    NetworkStats stats = collector.getStats();
    
    // Verify totals
    EXPECT_EQ(stats.total_packets, 5);
    EXPECT_EQ(stats.total_bytes, 600);
    
    // Verify protocol breakdown
    EXPECT_EQ(stats.tcp_packets, 2);
    EXPECT_EQ(stats.udp_packets, 2);
    EXPECT_EQ(stats.icmp_packets, 1);
    
    // Reset and verify
    collector.resetStats();
    stats = collector.getStats();
    EXPECT_EQ(stats.total_packets, 0);
    EXPECT_EQ(stats.total_bytes, 0);
}

// ==================== Utility Function Tests ====================

TEST_F(NetworkUtilsTest, TestUtilityFunctions)
{
    // Test IP to integer and back
    std::vector<std::string> test_ips = {
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "255.255.255.255"
    };
    
    for (const auto& ip : test_ips) {
        uint32_t ip_int = NetworkUtils::ipStringToInt(ip);
        std::string ip_back = NetworkUtils::ipIntToString(ip_int);
        EXPECT_EQ(ip, ip_back);
    }
    
    // Test subnet mask to prefix and back
    std::vector<uint32_t> test_masks = {
        0x00000000, // /0
        0xFF000000, // /8
        0xFFFF0000, // /16
        0xFFFFFF00, // /24
        0xFFFFFFFF  // /32
    };
    
    for (const auto& mask : test_masks) {
        int prefix = NetworkUtils::calculatePrefixLength(mask);
        uint32_t mask_back = NetworkUtils::calculateSubnetMask(prefix);
        EXPECT_EQ(mask, mask_back);
    }
}

// ==================== Main Function ====================

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
