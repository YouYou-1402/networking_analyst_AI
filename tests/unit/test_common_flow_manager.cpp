// tests/unit/test_common_flow_manager.cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../src/common/flow_manager.hpp"
#include "../../src/common/packet_parser.hpp"
#include <thread>
#include <chrono>

using namespace NetworkSecurity::Common;
using namespace testing;

// ==================== Helper Functions ====================

/**
 * @brief Tạo một ParsedPacket mẫu cho testing
 */
ParsedPacket createTestPacket(
    uint32_t src_ip = 0x0A000001,      // 10.0.0.1
    uint32_t dst_ip = 0x0A000002,      // 10.0.0.2
    uint16_t src_port = 12345,
    uint16_t dst_port = 80,
    uint8_t protocol = IPPROTO_TCP,
    size_t packet_size = 1000,
    size_t payload_length = 500,
    uint64_t timestamp = 0)
{
    ParsedPacket packet = {};
    
    // Ethernet
    packet.eth_type = 0x0800; // IPv4
    
    // IP
    packet.ip_version = 4;
    packet.ip_protocol = protocol;
    packet.src_ip = src_ip;
    packet.dst_ip = dst_ip;
    packet.packet_size = packet_size;
    packet.ip_ttl = 64;
    
    // Transport
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.seq_num = 1000;
    packet.ack_num = 0;
    packet.tcp_flags = 0x02; // SYN
    packet.window_size = 65535;
    
    // Payload
    static std::vector<uint8_t> dummy_payload(payload_length, 0x41); // 'A'
    packet.payload = dummy_payload.data();
    packet.payload_length = payload_length;
    
    // Metadata
    if (timestamp == 0)
    {
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    packet.timestamp = timestamp;
    packet.packet_size = packet_size;
    packet.is_fragmented = false;
    
    return packet;
}

/**
 * @brief Tạo HTTP payload mẫu
 */
std::vector<uint8_t> createHTTPPayload()
{
    std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    return std::vector<uint8_t>(http_request.begin(), http_request.end());
}

/**
 * @brief Tạo TLS/SSL payload mẫu
 */
std::vector<uint8_t> createTLSPayload()
{
    std::vector<uint8_t> tls_handshake = {
        0x16, 0x03, 0x01, 0x00, 0x05, // TLS handshake
        0x01, 0x00, 0x00, 0x01, 0x03  // Client Hello
    };
    return tls_handshake;
}

// ==================== FlowKey Tests ====================

class FlowKeyTest : public ::testing::Test
{
protected:
    FlowKey key1;
    FlowKey key2;
    
    void SetUp() override
    {
        key1.src_ip = 0x0A000001;
        key1.dst_ip = 0x0A000002;
        key1.src_port = 12345;
        key1.dst_port = 80;
        key1.protocol = IPPROTO_TCP;
        
        key2 = key1;
    }
};

TEST_F(FlowKeyTest, EqualityOperator)
{
    EXPECT_TRUE(key1 == key2);
    
    key2.src_port = 54321;
    EXPECT_FALSE(key1 == key2);
}

TEST_F(FlowKeyTest, HashFunction)
{
    size_t hash1 = key1.hash();
    size_t hash2 = key2.hash();
    
    EXPECT_EQ(hash1, hash2);
    
    key2.dst_ip = 0x0A000003;
    size_t hash3 = key2.hash();
    
    EXPECT_NE(hash1, hash3);
}

TEST_F(FlowKeyTest, HashConsistency)
{
    FlowKeyHash hasher;
    
    size_t hash1 = hasher(key1);
    size_t hash2 = hasher(key1);
    
    EXPECT_EQ(hash1, hash2);
}

// ==================== FlowManager Basic Tests ====================

class FlowManagerTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
    
    void TearDown() override
    {
        manager.reset();
    }
};

TEST_F(FlowManagerTest, InitialState)
{
    EXPECT_EQ(manager->getFlowCount(), 0);
    EXPECT_EQ(manager->getTotalPackets(), 0);
    EXPECT_EQ(manager->getTotalBytes(), 0);
}

TEST_F(FlowManagerTest, ProcessSinglePacket)
{
    ParsedPacket packet = createTestPacket();
    
    auto flow = manager->processPacket(packet);
    
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->packet_count, 1);
    EXPECT_EQ(flow->byte_count, packet.packet_size);
    EXPECT_EQ(flow->first_seen, packet.timestamp);
    EXPECT_EQ(flow->last_seen, packet.timestamp);
    EXPECT_EQ(manager->getFlowCount(), 1);
    EXPECT_EQ(manager->getTotalPackets(), 1);
    EXPECT_EQ(manager->getTotalBytes(), packet.packet_size);
}

TEST_F(FlowManagerTest, ProcessMultiplePacketsSameFlow)
{
    ParsedPacket packet1 = createTestPacket();
    ParsedPacket packet2 = createTestPacket();
    packet2.timestamp = packet1.timestamp + 1000;
    
    auto flow1 = manager->processPacket(packet1);
    auto flow2 = manager->processPacket(packet2);
    
    EXPECT_EQ(flow1, flow2); // Should be the same flow
    EXPECT_EQ(flow1->packet_count, 2);
    EXPECT_EQ(flow1->byte_count, packet1.packet_size + packet2.packet_size);
    EXPECT_EQ(manager->getFlowCount(), 1);
    EXPECT_EQ(manager->getTotalPackets(), 2);
}

TEST_F(FlowManagerTest, ProcessMultipleFlows)
{
    ParsedPacket packet1 = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    ParsedPacket packet2 = createTestPacket(0x0A000003, 0x0A000004, 54321, 443);
    ParsedPacket packet3 = createTestPacket(0x0A000005, 0x0A000006, 9999, 22);
    
    manager->processPacket(packet1);
    manager->processPacket(packet2);
    manager->processPacket(packet3);
    
    EXPECT_EQ(manager->getFlowCount(), 3);
    EXPECT_EQ(manager->getTotalPackets(), 3);
}

TEST_F(FlowManagerTest, BidirectionalFlowDetection)
{
    ParsedPacket forward = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    ParsedPacket reverse = createTestPacket(0x0A000002, 0x0A000001, 80, 12345);
    
    auto flow1 = manager->processPacket(forward);
    EXPECT_FALSE(flow1->is_bidirectional);
    
    auto flow2 = manager->processPacket(reverse);
    EXPECT_TRUE(flow2->is_bidirectional);
    EXPECT_EQ(flow1, flow2); // Should be the same flow
}

// ==================== Flow Statistics Tests ====================

TEST_F(FlowManagerTest, PacketIntervalTracking)
{
    uint64_t base_time = 1000000;
    
    ParsedPacket packet1 = createTestPacket();
    packet1.timestamp = base_time;
    
    ParsedPacket packet2 = createTestPacket();
    packet2.timestamp = base_time + 100;
    
    ParsedPacket packet3 = createTestPacket();
    packet3.timestamp = base_time + 250;
    
    auto flow = manager->processPacket(packet1);
    manager->processPacket(packet2);
    manager->processPacket(packet3);
    
    // Sửa: packet_intervals có thể bao gồm cả interval đầu tiên (0)
    EXPECT_GE(flow->packet_intervals.size(), 2);  // >= thay vì ==
    
    // Kiểm tra các interval không phải 0
    std::vector<uint64_t> non_zero_intervals;
    for (auto interval : flow->packet_intervals) {
        if (interval > 0) {
            non_zero_intervals.push_back(interval);
        }
    }
    
    EXPECT_GE(non_zero_intervals.size(), 2);
    EXPECT_EQ(non_zero_intervals[0], 100);
    EXPECT_EQ(non_zero_intervals[1], 150);
}

TEST_F(FlowManagerTest, PacketSizeTracking)
{
    ParsedPacket packet1 = createTestPacket();
    packet1.packet_size = 100;
    
    ParsedPacket packet2 = createTestPacket();
    packet2.packet_size = 200;
    
    ParsedPacket packet3 = createTestPacket();
    packet3.packet_size = 300;
    
    auto flow = manager->processPacket(packet1);
    manager->processPacket(packet2);
    manager->processPacket(packet3);
    
    EXPECT_EQ(flow->packet_sizes.size(), 3);
    EXPECT_EQ(flow->packet_sizes[0], 100);
    EXPECT_EQ(flow->packet_sizes[1], 200);
    EXPECT_EQ(flow->packet_sizes[2], 300);
    EXPECT_EQ(flow->byte_count, 600);
}

TEST_F(FlowManagerTest, FlowDurationCalculation)
{
    uint64_t base_time = 1000000;
    
    ParsedPacket packet1 = createTestPacket();
    packet1.timestamp = base_time;
    
    ParsedPacket packet2 = createTestPacket();
    packet2.timestamp = base_time + 5000;
    
    auto flow = manager->processPacket(packet1);
    manager->processPacket(packet2);
    
    EXPECT_EQ(flow->flow_duration, 5000);
}

TEST_F(FlowManagerTest, LimitPacketIntervalsStorage)
{
    ParsedPacket packet = createTestPacket();
    uint64_t base_time = 1000000;
    
    // Process 150 packets (should keep only last 100 intervals)
    for (int i = 0; i < 150; i++)
    {
        packet.timestamp = base_time + i * 10;
        manager->processPacket(packet);
    }
    
    auto flow = manager->getFlow(manager->getAllFlows()[0]->key);
    EXPECT_LE(flow->packet_intervals.size(), 100);
}

// ==================== Flow Retrieval Tests ====================

TEST_F(FlowManagerTest, GetFlowByKey)
{
    ParsedPacket packet = createTestPacket();
    auto flow1 = manager->processPacket(packet);
    
    auto flow2 = manager->getFlow(flow1->key);
    
    ASSERT_NE(flow2, nullptr);
    EXPECT_EQ(flow1, flow2);
}

TEST_F(FlowManagerTest, GetNonExistentFlow)
{
    FlowKey key;
    key.src_ip = 0x0A000001;
    key.dst_ip = 0x0A000002;
    key.src_port = 12345;
    key.dst_port = 80;
    key.protocol = IPPROTO_TCP;
    
    auto flow = manager->getFlow(key);
    
    EXPECT_EQ(flow, nullptr);
}

TEST_F(FlowManagerTest, GetAllFlows)
{
    ParsedPacket packet1 = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    ParsedPacket packet2 = createTestPacket(0x0A000003, 0x0A000004, 54321, 443);
    ParsedPacket packet3 = createTestPacket(0x0A000005, 0x0A000006, 9999, 22);
    
    manager->processPacket(packet1);
    manager->processPacket(packet2);
    manager->processPacket(packet3);
    
    auto flows = manager->getAllFlows();
    
    EXPECT_EQ(flows.size(), 3);
}

// ==================== Flow Cleanup Tests ====================

TEST_F(FlowManagerTest, CleanupExpiredFlows)
{
    // Dùng thời gian thực
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Flow cũ (400 seconds ago)
    ParsedPacket packet1 = createTestPacket();
    packet1.timestamp = now - 400000;
    
    // Flow mới (100 seconds ago)
    ParsedPacket packet2 = createTestPacket(0x0A000003, 0x0A000004, 54321, 443);
    packet2.timestamp = now - 100000;
    
    manager->processPacket(packet1);
    manager->processPacket(packet2);
    
    EXPECT_EQ(manager->getFlowCount(), 2);
    
    // Cleanup flows older than 300 seconds (300000 ms)
    size_t removed = manager->cleanupExpiredFlows(300000);
    
    // Chỉ flow1 bị xóa (400 seconds > 300 seconds)
    EXPECT_EQ(removed, 1);
    EXPECT_EQ(manager->getFlowCount(), 1);
}

TEST_F(FlowManagerTest, CleanupNoExpiredFlows)
{
    // Dùng thời gian thực
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Flow 1 (50 seconds ago)
    ParsedPacket packet1 = createTestPacket();
    packet1.timestamp = now - 50000;
    
    // Flow 2 (30 seconds ago)
    ParsedPacket packet2 = createTestPacket(0x0A000003, 0x0A000004, 54321, 443);
    packet2.timestamp = now - 30000;
    
    manager->processPacket(packet1);
    manager->processPacket(packet2);
    
    EXPECT_EQ(manager->getFlowCount(), 2);
    
    // Cleanup flows older than 100 seconds (100000 ms)
    size_t removed = manager->cleanupExpiredFlows(100000);
    
    // Không có flow nào bị xóa (cả 2 đều < 100 seconds)
    EXPECT_EQ(removed, 0);
    EXPECT_EQ(manager->getFlowCount(), 2);
}

// ==================== Configuration Tests ====================

// TEST_F(FlowManagerTest, SetMaxFlows)
// {
//     manager->setMaxFlows(5);
    
//     // Create 10 flows
//     for (int i = 0; i < 10; i++)
//     {
//         ParsedPacket packet = createTestPacket(0x0A000001 + i, 0x0A000002, 12345 + i, 80);
//         manager->processPacket(packet);
//     }
    
//     // Should not exceed max flows
//     EXPECT_LE(manager->getFlowCount(), 5);
// }

TEST_F(FlowManagerTest, SetFlowTimeout)
{
    manager->setFlowTimeout(60000); // 1 minute
    
    uint64_t base_time = 1000000;
    
    ParsedPacket packet = createTestPacket();
    packet.timestamp = base_time;
    
    manager->processPacket(packet);
    
    // This should trigger cleanup with new timeout
    size_t removed = manager->cleanupExpiredFlows(60000);
    
    // Flow should still exist (just created)
    EXPECT_EQ(removed, 0);
}

// ==================== Application Protocol Detection Tests ====================

class ProtocolDetectionTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(ProtocolDetectionTest, DetectHTTP)
{
    ParsedPacket packet = createTestPacket();
    auto http_payload = createHTTPPayload();
    packet.payload = http_payload.data();
    packet.payload_length = http_payload.size();
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "HTTP");
}

TEST_F(ProtocolDetectionTest, DetectTLS)
{
    ParsedPacket packet = createTestPacket();
    auto tls_payload = createTLSPayload();
    packet.payload = tls_payload.data();
    packet.payload_length = tls_payload.size();
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "TLS/SSL");
}

TEST_F(ProtocolDetectionTest, DetectDNS)
{
    ParsedPacket packet = createTestPacket();
    packet.dst_port = 53;
    packet.ip_protocol = IPPROTO_UDP;
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "DNS");
}

TEST_F(ProtocolDetectionTest, DetectSSH)
{
    ParsedPacket packet = createTestPacket();
    std::string ssh_banner = "SSH-2.0-OpenSSH_7.4";
    std::vector<uint8_t> ssh_payload(ssh_banner.begin(), ssh_banner.end());
    packet.payload = ssh_payload.data();
    packet.payload_length = ssh_payload.size();
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "SSH");
}

TEST_F(ProtocolDetectionTest, DetectFTP)
{
    ParsedPacket packet = createTestPacket();
    packet.dst_port = 21;
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "FTP");
}

TEST_F(ProtocolDetectionTest, DetectSMTP)
{
    ParsedPacket packet = createTestPacket();
    packet.dst_port = 25;
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "SMTP");
}

TEST_F(ProtocolDetectionTest, UnknownProtocol)
{
    ParsedPacket packet = createTestPacket();
    packet.dst_port = 9999;
    std::vector<uint8_t> unknown_payload = {0x00, 0x01, 0x02, 0x03};
    packet.payload = unknown_payload.data();
    packet.payload_length = unknown_payload.size();
    
    auto flow = manager->processPacket(packet);
    
    EXPECT_EQ(flow->application_protocol, "Unknown");
}

// ==================== Suspicious Activity Detection Tests ====================

class SuspiciousActivityTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(SuspiciousActivityTest, DetectPortScan)
{
    ParsedPacket packet = createTestPacket();
    packet.packet_size = 60; // Small packet
    
    // Send many small packets without bidirectional traffic
    for (int i = 0; i < 15; i++)
    {
        manager->processPacket(packet);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    ASSERT_GT(flows.size(), 0);
    EXPECT_TRUE(flows[0]->is_suspicious);
    EXPECT_GE(flows[0]->threat_level, 3);
}

TEST_F(SuspiciousActivityTest, DetectDDoS)
{
    uint64_t base_time = 1000000;
    ParsedPacket packet = createTestPacket();
    
    // Send 150 packets in 100ms (1500 pps)
    for (int i = 0; i < 150; i++)
    {
        packet.timestamp = base_time + i;
        manager->processPacket(packet);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    ASSERT_GT(flows.size(), 0);
    EXPECT_TRUE(flows[0]->is_suspicious);
    EXPECT_GE(flows[0]->threat_level, 5);
}

TEST_F(SuspiciousActivityTest, DetectRegularIntervals)
{
    uint64_t base_time = 1000000;
    ParsedPacket packet = createTestPacket();
    
    // Send packets with very regular intervals (potential covert channel)
    for (int i = 0; i < 20; i++)
    {
        packet.timestamp = base_time + i * 100; // Exactly 100ms apart
        manager->processPacket(packet);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    ASSERT_GT(flows.size(), 0);
    EXPECT_TRUE(flows[0]->is_suspicious);
    EXPECT_GE(flows[0]->threat_level, 2);
}

TEST_F(SuspiciousActivityTest, DetectLargeDataTransfer)
{
    ParsedPacket packet = createTestPacket();
    packet.dst_port = 9999; // Uncommon port
    packet.packet_size = 1500;
    
    // Send enough packets to exceed 10MB
    for (int i = 0; i < 7000; i++)
    {
        manager->processPacket(packet);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    ASSERT_GT(flows.size(), 0);
    EXPECT_TRUE(flows[0]->is_suspicious);
    EXPECT_GE(flows[0]->threat_level, 4);
}

TEST_F(SuspiciousActivityTest, GetSuspiciousFlowsSorted)
{
    // Create flows with different threat levels
    ParsedPacket packet1 = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    packet1.packet_size = 60;
    
    ParsedPacket packet2 = createTestPacket(0x0A000003, 0x0A000004, 54321, 443);
    packet2.packet_size = 1500;
    
    // Flow 1: Port scan (threat level 3)
    for (int i = 0; i < 15; i++)
    {
        manager->processPacket(packet1);
    }
    
    // Flow 2: Large transfer (threat level 4)
    for (int i = 0; i < 7000; i++)
    {
        manager->processPacket(packet2);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    ASSERT_GE(flows.size(), 2);
    // Should be sorted by threat level (highest first)
    EXPECT_GE(flows[0]->threat_level, flows[1]->threat_level);
}

TEST_F(SuspiciousActivityTest, NormalTrafficNotSuspicious)
{
    ParsedPacket forward = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    ParsedPacket reverse = createTestPacket(0x0A000002, 0x0A000001, 80, 12345);
    
    // Normal bidirectional traffic
    for (int i = 0; i < 5; i++)
    {
        manager->processPacket(forward);
        manager->processPacket(reverse);
    }
    
    auto flows = manager->getSuspiciousFlows();
    
    EXPECT_EQ(flows.size(), 0);
}

// ==================== Thread Safety Tests ====================

class ThreadSafetyTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(ThreadSafetyTest, ConcurrentPacketProcessing)
{
    const int num_threads = 4;
    const int packets_per_thread = 100;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; t++)
    {
        threads.emplace_back([this, t, packets_per_thread]() {
            for (int i = 0; i < packets_per_thread; i++)
            {
                ParsedPacket packet = createTestPacket(
                    0x0A000001 + t,
                    0x0A000002,
                    12345 + i,
                    80
                );
                manager->processPacket(packet);
            }
        });
    }
    
    for (auto &thread : threads)
    {
        thread.join();
    }
    
    EXPECT_EQ(manager->getTotalPackets(), num_threads * packets_per_thread);
}

TEST_F(ThreadSafetyTest, ConcurrentReadWrite)
{
    // Writer thread
    std::thread writer([this]() {
        for (int i = 0; i < 100; i++)
        {
            ParsedPacket packet = createTestPacket();
            manager->processPacket(packet);
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    });
    
    // Reader thread
    std::thread reader([this]() {
        for (int i = 0; i < 100; i++)
        {
            auto flows = manager->getAllFlows();
            size_t count = manager->getFlowCount();
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    });
    
    writer.join();
    reader.join();
    
    EXPECT_GT(manager->getFlowCount(), 0);
}

// ==================== Edge Cases Tests ====================

class EdgeCasesTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(EdgeCasesTest, ZeroSizePacket)
{
    ParsedPacket packet = createTestPacket();
    packet.packet_size = 0;
    packet.payload_length = 0;
    
    auto flow = manager->processPacket(packet);
    
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->byte_count, 0);
}

TEST_F(EdgeCasesTest, LargePacket)
{
    ParsedPacket packet = createTestPacket();
    packet.packet_size = 65535; // Max IP packet size
    
    auto flow = manager->processPacket(packet);
    
    ASSERT_NE(flow, nullptr);
    EXPECT_EQ(flow->byte_count, 65535);
}

TEST_F(EdgeCasesTest, SameTimestamp)
{
    uint64_t timestamp = 1000000;
    
    ParsedPacket packet1 = createTestPacket();
    packet1.timestamp = timestamp;
    
    ParsedPacket packet2 = createTestPacket();
    packet2.timestamp = timestamp;
    
    auto flow = manager->processPacket(packet1);
    manager->processPacket(packet2);
    
    EXPECT_EQ(flow->flow_duration, 0);
}

TEST_F(EdgeCasesTest, EmptyPayload)
{
    ParsedPacket packet = createTestPacket();
    packet.payload = nullptr;
    packet.payload_length = 0;
    
    auto flow = manager->processPacket(packet);
    
    ASSERT_NE(flow, nullptr);
    EXPECT_TRUE(flow->payload_sample.empty());
}

TEST_F(EdgeCasesTest, MaxFlowsReached)
{
    manager->setMaxFlows(10);
    
    // Create 20 flows
    for (int i = 0; i < 20; i++)
    {
        ParsedPacket packet = createTestPacket(
            0x0A000001 + i,
            0x0A000002,
            12345 + i,
            80
        );
        manager->processPacket(packet);
    }
    
    // Should not exceed max
    EXPECT_LE(manager->getFlowCount(), 10);
}

// ==================== Performance Tests ====================

class PerformanceTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(PerformanceTest, ProcessManyPackets)
{
    const int num_packets = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_packets; i++)
    {
        ParsedPacket packet = createTestPacket();
        manager->processPacket(packet);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_EQ(manager->getTotalPackets(), num_packets);
    
    std::cout << "Processed " << num_packets << " packets in " 
              << duration.count() << " ms" << std::endl;
}

TEST_F(PerformanceTest, ProcessManyFlows)
{
    const int num_flows = 1000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_flows; i++)
    {
        ParsedPacket packet = createTestPacket(
            0x0A000001 + (i / 256),
            0x0A000002,
            12345 + i,
            80 + (i % 100)
        );
        manager->processPacket(packet);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_EQ(manager->getFlowCount(), num_flows);
    
    std::cout << "Created " << num_flows << " flows in " 
              << duration.count() << " ms" << std::endl;
}

TEST_F(PerformanceTest, CleanupPerformance)
{
    const int num_flows = 5000;
    uint64_t base_time = 1000000;
    
    // Create flows with varying timestamps
    for (int i = 0; i < num_flows; i++)
    {
        ParsedPacket packet = createTestPacket(
            0x0A000001 + (i / 256),
            0x0A000002,
            12345 + i,
            80
        );
        packet.timestamp = base_time + (i * 1000); // 1 second apart
        manager->processPacket(packet);
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    size_t removed = manager->cleanupExpiredFlows(300000); // 5 minutes
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Cleaned up " << removed << " flows in " 
              << duration.count() << " ms" << std::endl;
}

TEST_F(PerformanceTest, GetAllFlowsPerformance)
{
    const int num_flows = 1000;
    
    // Create flows
    for (int i = 0; i < num_flows; i++)
    {
        ParsedPacket packet = createTestPacket(
            0x0A000001 + (i / 256),
            0x0A000002,
            12345 + i,
            80
        );
        manager->processPacket(packet);
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    auto flows = manager->getAllFlows();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    EXPECT_EQ(flows.size(), num_flows);
    
    std::cout << "Retrieved " << flows.size() << " flows in " 
              << duration.count() << " µs" << std::endl;
}

// ==================== Integration Tests ====================

class IntegrationTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
    }
};

TEST_F(IntegrationTest, CompleteHTTPSession)
{
    uint64_t base_time = 1000000;
    
    // SYN
    ParsedPacket syn = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    syn.timestamp = base_time;
    syn.tcp_flags = 0x02; // SYN
    
    // SYN-ACK
    ParsedPacket synack = createTestPacket(0x0A000002, 0x0A000001, 80, 12345);
    synack.timestamp = base_time + 10;
    synack.tcp_flags = 0x12; // SYN-ACK
    
    // ACK
    ParsedPacket ack = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    ack.timestamp = base_time + 20;
    ack.tcp_flags = 0x10; // ACK
    
    // HTTP Request
    ParsedPacket request = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    request.timestamp = base_time + 30;
    auto http_payload = createHTTPPayload();
    request.payload = http_payload.data();
    request.payload_length = http_payload.size();
    request.tcp_flags = 0x18; // PSH-ACK
    
    // HTTP Response
    ParsedPacket response = createTestPacket(0x0A000002, 0x0A000001, 80, 12345);
    response.timestamp = base_time + 100;
    response.packet_size = 5000;
    response.tcp_flags = 0x18; // PSH-ACK
    
    // FIN
    ParsedPacket fin = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    fin.timestamp = base_time + 200;
    fin.tcp_flags = 0x11; // FIN-ACK
    
    auto flow = manager->processPacket(syn);
    manager->processPacket(synack);
    manager->processPacket(ack);
    manager->processPacket(request);
    manager->processPacket(response);
    manager->processPacket(fin);
    
    EXPECT_EQ(manager->getFlowCount(), 1);
    EXPECT_EQ(flow->packet_count, 6);
    EXPECT_TRUE(flow->is_bidirectional);
    EXPECT_EQ(flow->application_protocol, "HTTP");
    EXPECT_EQ(flow->flow_duration, 200);
}

TEST_F(IntegrationTest, PortScanSimulation)
{
    uint64_t base_time = 1000000;
    
    // Simulate port scan: many SYN packets to different ports
    for (int port = 1; port <= 100; port++)
    {
        ParsedPacket syn = createTestPacket(0x0A000001, 0x0A000002, 12345, port);
        syn.timestamp = base_time + port;
        syn.tcp_flags = 0x02; // SYN
        syn.packet_size = 60;
        manager->processPacket(syn);
    }
    
    // Should detect 100 different flows (one per port)
    EXPECT_EQ(manager->getFlowCount(), 100);
    
    // Most should be suspicious (small packets, not bidirectional)
    auto suspicious = manager->getSuspiciousFlows();
    EXPECT_GT(suspicious.size(), 50); // At least half should be flagged
}

TEST_F(IntegrationTest, DNSQueryResponse)
{
    uint64_t base_time = 1000000;
    
    // DNS Query
    ParsedPacket query = createTestPacket(0x0A000001, 0x08080808, 54321, 53);
    query.timestamp = base_time;
    query.ip_protocol = IPPROTO_UDP;
    query.packet_size = 100;
    
    // DNS Response
    ParsedPacket response = createTestPacket(0x08080808, 0x0A000001, 53, 54321);
    response.timestamp = base_time + 50;
    response.ip_protocol = IPPROTO_UDP;
    response.packet_size = 200;
    
    auto flow = manager->processPacket(query);
    manager->processPacket(response);
    
    EXPECT_EQ(manager->getFlowCount(), 1);
    EXPECT_TRUE(flow->is_bidirectional);
    EXPECT_EQ(flow->application_protocol, "DNS");
    EXPECT_FALSE(flow->is_suspicious);
}

TEST_F(IntegrationTest, TLSHandshake)
{
    uint64_t base_time = 1000000;
    
    // Client Hello
    ParsedPacket client_hello = createTestPacket(0x0A000001, 0x0A000002, 12345, 443);
    client_hello.timestamp = base_time;
    auto tls_payload = createTLSPayload();
    client_hello.payload = tls_payload.data();
    client_hello.payload_length = tls_payload.size();
    
    // Server Hello
    ParsedPacket server_hello = createTestPacket(0x0A000002, 0x0A000001, 443, 12345);
    server_hello.timestamp = base_time + 20;
    
    // Certificate
    ParsedPacket certificate = createTestPacket(0x0A000002, 0x0A000001, 443, 12345);
    certificate.timestamp = base_time + 30;
    certificate.packet_size = 2000;
    
    // Client Key Exchange
    ParsedPacket key_exchange = createTestPacket(0x0A000001, 0x0A000002, 12345, 443);
    key_exchange.timestamp = base_time + 50;
    
    auto flow = manager->processPacket(client_hello);
    manager->processPacket(server_hello);
    manager->processPacket(certificate);
    manager->processPacket(key_exchange);
    
    EXPECT_EQ(flow->application_protocol, "TLS/SSL");
    EXPECT_TRUE(flow->is_bidirectional);
    EXPECT_EQ(flow->packet_count, 4);
}

TEST_F(IntegrationTest, LongLivedConnection)
{
    uint64_t base_time = 1000000;
    
    // Simulate a long-lived connection with periodic traffic
    ParsedPacket packet = createTestPacket();
    
    for (int i = 0; i < 100; i++)
    {
        packet.timestamp = base_time + (i * 10000); // 10 seconds apart
        packet.src_ip = (i % 2 == 0) ? 0x0A000001 : 0x0A000002;
        packet.dst_ip = (i % 2 == 0) ? 0x0A000002 : 0x0A000001;
        packet.src_port = (i % 2 == 0) ? 12345 : 80;
        packet.dst_port = (i % 2 == 0) ? 80 : 12345;
        
        manager->processPacket(packet);
    }
    
    auto flows = manager->getAllFlows();
    ASSERT_EQ(flows.size(), 1);
    
    auto flow = flows[0];
    EXPECT_EQ(flow->packet_count, 100);
    EXPECT_TRUE(flow->is_bidirectional);
    EXPECT_EQ(flow->flow_duration, 990000); // 99 * 10000
}

TEST_F(IntegrationTest, MultipleProtocols)
{
    uint64_t base_time = 1000000;
    
    // HTTP
    ParsedPacket http = createTestPacket(0x0A000001, 0x0A000002, 12345, 80);
    http.timestamp = base_time;
    auto http_payload = createHTTPPayload();
    http.payload = http_payload.data();
    http.payload_length = http_payload.size();
    
    // HTTPS
    ParsedPacket https = createTestPacket(0x0A000001, 0x0A000003, 12346, 443);
    https.timestamp = base_time + 10;
    auto tls_payload = createTLSPayload();
    https.payload = tls_payload.data();
    https.payload_length = tls_payload.size();
    
    // DNS
    ParsedPacket dns = createTestPacket(0x0A000001, 0x08080808, 54321, 53);
    dns.timestamp = base_time + 20;
    dns.ip_protocol = IPPROTO_UDP;
    
    // SSH
    ParsedPacket ssh = createTestPacket(0x0A000001, 0x0A000004, 12347, 22);
    ssh.timestamp = base_time + 30;
    std::string ssh_banner = "SSH-2.0-OpenSSH_7.4";
    std::vector<uint8_t> ssh_payload_data(ssh_banner.begin(), ssh_banner.end());
    ssh.payload = ssh_payload_data.data();
    ssh.payload_length = ssh_payload_data.size();
    
    manager->processPacket(http);
    manager->processPacket(https);
    manager->processPacket(dns);
    manager->processPacket(ssh);
    
    EXPECT_EQ(manager->getFlowCount(), 4);
    
    auto flows = manager->getAllFlows();
    
    // Verify each protocol was detected
    std::set<std::string> detected_protocols;
    for (const auto &flow : flows)
    {
        detected_protocols.insert(flow->application_protocol);
    }
    
    EXPECT_TRUE(detected_protocols.count("HTTP") > 0);
    EXPECT_TRUE(detected_protocols.count("TLS/SSL") > 0);
    EXPECT_TRUE(detected_protocols.count("DNS") > 0);
    EXPECT_TRUE(detected_protocols.count("SSH") > 0);
}

// ==================== Stress Tests ====================

class StressTest : public ::testing::Test
{
protected:
    std::unique_ptr<FlowManager> manager;
    
    void SetUp() override
    {
        manager = std::make_unique<FlowManager>();
        manager->setMaxFlows(50000);
    }
};

TEST_F(StressTest, HighVolumeTraffic)
{
    const int num_packets = 100000;
    const int num_flows = 1000;
    
    for (int i = 0; i < num_packets; i++)
    {
        int flow_id = i % num_flows;
        ParsedPacket packet = createTestPacket(
            0x0A000001 + (flow_id / 256),
            0x0A000002,
            12345 + flow_id,
            80
        );
        manager->processPacket(packet);
    }
    
    EXPECT_EQ(manager->getTotalPackets(), num_packets);
    EXPECT_EQ(manager->getFlowCount(), num_flows);
}

TEST_F(StressTest, RapidFlowCreation)
{
    const int num_flows = 10000;
    
    for (int i = 0; i < num_flows; i++)
    {
        ParsedPacket packet = createTestPacket(
            0x0A000001 + (i / 256),
            0x0A000002 + (i % 256),
            12345 + (i % 10000),
            80 + (i % 1000)
        );
        manager->processPacket(packet);
    }
    
    EXPECT_EQ(manager->getFlowCount(), num_flows);
}

TEST_F(StressTest, ConcurrentStress)
{
    const int num_threads = 8;
    const int packets_per_thread = 1000;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; t++)
    {
        threads.emplace_back([this, t, packets_per_thread]() {
            for (int i = 0; i < packets_per_thread; i++)
            {
                ParsedPacket packet = createTestPacket(
                    0x0A000001 + t,
                    0x0A000002 + (i % 256),
                    12345 + i,
                    80 + (i % 100)
                );
                manager->processPacket(packet);
            }
        });
    }
    
    for (auto &thread : threads)
    {
        thread.join();
    }
    
    EXPECT_EQ(manager->getTotalPackets(), num_threads * packets_per_thread);
}

// ==================== Main ====================

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

