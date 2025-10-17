// tests/unit/test_common_packet_parser.cpp
#include <gtest/gtest.h>
#include "../../src/common/packet_parser.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

using namespace NetworkSecurity::Common;

class PacketParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        parser = std::make_unique<PacketParser>();
    }

    void TearDown() override {
        parser.reset();
    }

    std::unique_ptr<PacketParser> parser;

    // Helper function để tạo Ethernet header
    void createEthernetHeader(uint8_t* buffer, const uint8_t* src_mac, 
                             const uint8_t* dst_mac, uint16_t eth_type) {
        struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(buffer);
        memcpy(eth->h_source, src_mac, 6);
        memcpy(eth->h_dest, dst_mac, 6);
        eth->h_proto = htons(eth_type);
    }

    // Helper function để tạo IP header
    void createIPHeader(uint8_t* buffer, uint32_t src_ip, uint32_t dst_ip, 
                       uint8_t protocol, uint16_t total_len = 20, uint8_t ttl = 64) {
        struct iphdr* ip = reinterpret_cast<struct iphdr*>(buffer);
        memset(ip, 0, sizeof(struct iphdr));
        ip->version = 4;
        ip->ihl = 5; // 20 bytes header
        ip->tot_len = htons(total_len);
        ip->id = htons(12345);
        ip->ttl = ttl;
        ip->protocol = protocol;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;
        // Checksum sẽ được tính sau nếu cần
        ip->check = 0;
    }

    // Helper function để tạo TCP header
    void createTCPHeader(uint8_t* buffer, uint16_t src_port, uint16_t dst_port,
                        uint32_t seq, uint32_t ack, uint16_t flags, uint16_t window = 8192) {
        struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(buffer);
        memset(tcp, 0, sizeof(struct tcphdr));
        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
        tcp->seq = htonl(seq);
        tcp->ack_seq = htonl(ack);
        tcp->doff = 5; // 20 bytes header
        tcp->window = htons(window);
        
        // Set flags
        tcp->fin = (flags & 0x01) ? 1 : 0;
        tcp->syn = (flags & 0x02) ? 1 : 0;
        tcp->rst = (flags & 0x04) ? 1 : 0;
        tcp->psh = (flags & 0x08) ? 1 : 0;
        tcp->ack = (flags & 0x10) ? 1 : 0;
        tcp->urg = (flags & 0x20) ? 1 : 0;
    }

    // Helper function để tạo UDP header
    void createUDPHeader(uint8_t* buffer, uint16_t src_port, uint16_t dst_port, uint16_t len) {
        struct udphdr* udp = reinterpret_cast<struct udphdr*>(buffer);
        udp->source = htons(src_port);
        udp->dest = htons(dst_port);
        udp->len = htons(len);
        udp->check = 0; // Checksum optional for IPv4
    }
};

// Test constructor và destructor
TEST_F(PacketParserTest, ConstructorDestructor) {
    EXPECT_NE(parser, nullptr);
}

// Test parsePacket với dữ liệu null hoặc rỗng
TEST_F(PacketParserTest, ParsePacketNullData) {
    ParsedPacket parsed;
    
    // Test với data null
    EXPECT_FALSE(parser->parsePacket(nullptr, 100, parsed));
    
    // Test với length = 0
    uint8_t dummy_data[100];
    EXPECT_FALSE(parser->parsePacket(dummy_data, 0, parsed));
}

// Test parseEthernet
TEST_F(PacketParserTest, ParseEthernetValid) {
    uint8_t buffer[sizeof(struct ethhdr)];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    createEthernetHeader(buffer, src_mac, dst_mac, ETH_P_IP);
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseEthernet(buffer, sizeof(buffer), parsed));
    
    EXPECT_EQ(memcmp(parsed.src_mac, src_mac, 6), 0);
    EXPECT_EQ(memcmp(parsed.dst_mac, dst_mac, 6), 0);
    EXPECT_EQ(ntohs(parsed.eth_type), ETH_P_IP);
}

TEST_F(PacketParserTest, ParseEthernetInvalidLength) {
    uint8_t buffer[10]; // Smaller than ethernet header
    ParsedPacket parsed;
    
    EXPECT_FALSE(parser->parseEthernet(buffer, sizeof(buffer), parsed));
}

// Test parseIP
TEST_F(PacketParserTest, ParseIPValid) {
    uint8_t buffer[sizeof(struct iphdr)];
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    createIPHeader(buffer, src_ip, dst_ip, IPPROTO_TCP);
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseIP(buffer, sizeof(buffer), parsed));
    
    EXPECT_EQ(parsed.ip_version, 4);
    EXPECT_EQ(parsed.ip_protocol, IPPROTO_TCP);
    EXPECT_EQ(parsed.src_ip, src_ip);
    EXPECT_EQ(parsed.dst_ip, dst_ip);
    EXPECT_EQ(parsed.ip_ttl, 64);
    EXPECT_FALSE(parsed.is_fragmented);
}

TEST_F(PacketParserTest, ParseIPInvalidVersion) {
    uint8_t buffer[sizeof(struct iphdr)];
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(buffer);
    memset(ip, 0, sizeof(struct iphdr));
    ip->version = 6; // Invalid version for this test
    ip->ihl = 5;
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseIP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseIPFragmented) {
    uint8_t buffer[sizeof(struct iphdr)];
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    createIPHeader(buffer, src_ip, dst_ip, IPPROTO_TCP);
    
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(buffer);
    ip->frag_off = htons(0x2000); // More fragments flag
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseIP(buffer, sizeof(buffer), parsed));
    EXPECT_TRUE(parsed.is_fragmented);
}

TEST_F(PacketParserTest, ParseIPInvalidTTL) {
    uint8_t buffer[sizeof(struct iphdr)];
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    createIPHeader(buffer, src_ip, dst_ip, IPPROTO_TCP, 20, 0); // TTL = 0
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseIP(buffer, sizeof(buffer), parsed));
}

// Test parseTCP
TEST_F(PacketParserTest, ParseTCPValid) {
    uint8_t buffer[sizeof(struct tcphdr)];
    createTCPHeader(buffer, 80, 8080, 1000, 2000, 0x18); // PSH+ACK flags
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseTCP(buffer, sizeof(buffer), parsed));
    
    EXPECT_EQ(parsed.src_port, 80);
    EXPECT_EQ(parsed.dst_port, 8080);
    EXPECT_EQ(parsed.seq_num, 1000);
    EXPECT_EQ(parsed.ack_num, 2000);
    EXPECT_EQ(parsed.tcp_flags, 0x18);
    EXPECT_EQ(parsed.window_size, 8192);
}

TEST_F(PacketParserTest, ParseTCPInvalidSourcePort) {
    uint8_t buffer[sizeof(struct tcphdr)];
    createTCPHeader(buffer, 0, 8080, 1000, 2000, 0x02); // Invalid source port
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseTCP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseTCPInvalidDestPort) {
    uint8_t buffer[sizeof(struct tcphdr)];
    createTCPHeader(buffer, 80, 0, 1000, 2000, 0x02); // Invalid dest port
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseTCP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseTCPInvalidFlagsSynRst) {
    uint8_t buffer[sizeof(struct tcphdr)];
    createTCPHeader(buffer, 80, 8080, 1000, 2000, 0x06); // SYN+RST (invalid combination)
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseTCP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseTCPInvalidFlagsSynFin) {
    uint8_t buffer[sizeof(struct tcphdr)];
    createTCPHeader(buffer, 80, 8080, 1000, 2000, 0x03); // SYN+FIN (invalid combination)
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseTCP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseTCPInvalidLength) {
    uint8_t buffer[10]; // Smaller than TCP header
    ParsedPacket parsed;
    
    EXPECT_FALSE(parser->parseTCP(buffer, sizeof(buffer), parsed));
}

// Test parseUDP
TEST_F(PacketParserTest, ParseUDPValid) {
    uint8_t buffer[sizeof(struct udphdr)];
    createUDPHeader(buffer, 53, 5353, sizeof(struct udphdr));
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseUDP(buffer, sizeof(buffer), parsed));
    
    EXPECT_EQ(parsed.src_port, 53);
    EXPECT_EQ(parsed.dst_port, 5353);
    EXPECT_EQ(parsed.seq_num, 0); // UDP doesn't have sequence numbers
    EXPECT_EQ(parsed.ack_num, 0);
    EXPECT_EQ(parsed.tcp_flags, 0);
    EXPECT_EQ(parsed.window_size, 0);
}

TEST_F(PacketParserTest, ParseUDPInvalidDestPort) {
    uint8_t buffer[sizeof(struct udphdr)];
    createUDPHeader(buffer, 53, 0, sizeof(struct udphdr)); // Invalid dest port
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parseUDP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseUDPInvalidLength) {
    uint8_t buffer[6]; // Smaller than UDP header
    ParsedPacket parsed;
    
    EXPECT_FALSE(parser->parseUDP(buffer, sizeof(buffer), parsed));
}

TEST_F(PacketParserTest, ParseUDPValidSourcePortZero) {
    uint8_t buffer[sizeof(struct udphdr)];
    createUDPHeader(buffer, 0, 5353, sizeof(struct udphdr)); // Source port 0 is allowed for UDP
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parseUDP(buffer, sizeof(buffer), parsed));
    
    EXPECT_EQ(parsed.src_port, 0);
    EXPECT_EQ(parsed.dst_port, 5353);
}

// Test complete packet parsing - TCP
TEST_F(PacketParserTest, ParseCompletePacketTCP) {
    const size_t packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 10; // 10 bytes payload
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    // Create Ethernet header
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);
    
    // Create IP header
    createIPHeader(packet + sizeof(struct ethhdr), src_ip, dst_ip, IPPROTO_TCP, 
                   sizeof(struct iphdr) + sizeof(struct tcphdr) + 10);
    
    // Create TCP header
    createTCPHeader(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), 
                    80, 8080, 1000, 2000, 0x18);
    
    // Add payload
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr),
           "HelloWorld", 10);
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parsePacket(packet, packet_size, parsed));
    
    // Verify all fields
    EXPECT_EQ(memcmp(parsed.src_mac, src_mac, 6), 0);
    EXPECT_EQ(memcmp(parsed.dst_mac, dst_mac, 6), 0);
    EXPECT_EQ(ntohs(parsed.eth_type), ETH_P_IP);
    EXPECT_EQ(parsed.ip_version, 4);
    EXPECT_EQ(parsed.ip_protocol, IPPROTO_TCP);
    EXPECT_EQ(parsed.src_ip, src_ip);
    EXPECT_EQ(parsed.dst_ip, dst_ip);
    EXPECT_EQ(parsed.src_port, 80);
    EXPECT_EQ(parsed.dst_port, 8080);
    EXPECT_EQ(parsed.payload_length, 10);
    EXPECT_EQ(memcmp(parsed.payload, "HelloWorld", 10), 0);
    EXPECT_GT(parsed.timestamp, 0); // Timestamp should be set
    EXPECT_EQ(parsed.packet_size, packet_size);
}

// Test complete packet parsing - UDP
TEST_F(PacketParserTest, ParseCompletePacketUDP) {
    const size_t packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 5; // 5 bytes payload
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    // Create Ethernet header
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);
    
    // Create IP header
    createIPHeader(packet + sizeof(struct ethhdr), src_ip, dst_ip, IPPROTO_UDP,
                   sizeof(struct iphdr) + sizeof(struct udphdr) + 5);
    
    // Create UDP header
    createUDPHeader(packet + sizeof(struct ethhdr) + sizeof(struct iphdr),
                    53, 5353, sizeof(struct udphdr) + 5);
    
    // Add payload
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
           "Hello", 5);
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parsePacket(packet, packet_size, parsed));
    
    // Verify fields
    EXPECT_EQ(parsed.ip_protocol, IPPROTO_UDP);
    EXPECT_EQ(parsed.src_port, 53);
    EXPECT_EQ(parsed.dst_port, 5353);
    EXPECT_EQ(parsed.payload_length, 5);
    EXPECT_EQ(memcmp(parsed.payload, "Hello", 5), 0);
}

// Test utility functions
TEST_F(PacketParserTest, IPToString) {
    uint32_t ip = inet_addr("192.168.1.1");
    std::string ip_str = PacketParser::ipToString(ip);
    EXPECT_EQ(ip_str, "192.168.1.1");
}

TEST_F(PacketParserTest, IPToStringLocalhost) {
    uint32_t ip = inet_addr("127.0.0.1");
    std::string ip_str = PacketParser::ipToString(ip);
    EXPECT_EQ(ip_str, "127.0.0.1");
}

TEST_F(PacketParserTest, MACToString) {
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::string mac_str = PacketParser::macToString(mac);
    EXPECT_EQ(mac_str, "00:11:22:33:44:55");
}

TEST_F(PacketParserTest, MACToStringAllFF) {
    uint8_t mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    std::string mac_str = PacketParser::macToString(mac);
    EXPECT_EQ(mac_str, "ff:ff:ff:ff:ff:ff");
}

TEST_F(PacketParserTest, MACToStringNull) {
    // Test với null pointer
    std::string null_mac = PacketParser::macToString(nullptr);
    EXPECT_EQ(null_mac, "00:00:00:00:00:00");
}

TEST_F(PacketParserTest, ProtocolToString) {
    EXPECT_EQ(PacketParser::protocolToString(IPPROTO_TCP), "TCP");
    EXPECT_EQ(PacketParser::protocolToString(IPPROTO_UDP), "UDP");
    EXPECT_EQ(PacketParser::protocolToString(IPPROTO_ICMP), "ICMP");
    EXPECT_EQ(PacketParser::protocolToString(IPPROTO_ESP), "ESP");
    EXPECT_EQ(PacketParser::protocolToString(IPPROTO_AH), "AH");
    EXPECT_EQ(PacketParser::protocolToString(255), "Protocol-255");
}

TEST_F(PacketParserTest, TCPFlagsToString) {
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x02), "SYN");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x10), "ACK");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x18), "PSH|ACK");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x01), "FIN");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x04), "RST");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x20), "URG");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x00), "NONE");
    EXPECT_EQ(PacketParser::tcpFlagsToString(0x3F), "FIN|SYN|RST|PSH|ACK|URG");
}

// Test unsupported protocols
TEST_F(PacketParserTest, ParsePacketUnsupportedEthTypeIPv6) {
    const size_t packet_size = sizeof(struct ethhdr);
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    // Create Ethernet header with IPv6 (not implemented)
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IPV6);
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parsePacket(packet, packet_size, parsed));
}

TEST_F(PacketParserTest, ParsePacketUnsupportedEthTypeARP) {
    const size_t packet_size = sizeof(struct ethhdr);
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    // Create Ethernet header with ARP (not implemented)
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_ARP);
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parsePacket(packet, packet_size, parsed));
}

// Test edge cases
TEST_F(PacketParserTest, ParsePacketMinimumSize) {
    const size_t packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr);
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);
    createIPHeader(packet + sizeof(struct ethhdr), src_ip, dst_ip, IPPROTO_ICMP, sizeof(struct iphdr));
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parsePacket(packet, packet_size, parsed));
    
    EXPECT_EQ(parsed.payload_length, 0);
    EXPECT_EQ(parsed.payload, nullptr);
}

TEST_F(PacketParserTest, ParsePacketTooSmall) {
    const size_t packet_size = sizeof(struct ethhdr) - 1; // Smaller than ethernet header
    uint8_t packet[packet_size];
    
    ParsedPacket parsed;
    EXPECT_FALSE(parser->parsePacket(packet, packet_size, parsed));
}

TEST_F(PacketParserTest, ParsePacketUnknownIPProtocol) {
    const size_t packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + 10;
    uint8_t packet[packet_size];
    
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.1");
    uint32_t dst_ip = inet_addr("192.168.1.2");
    
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);
    createIPHeader(packet + sizeof(struct ethhdr), src_ip, dst_ip, 255, sizeof(struct iphdr) + 10); // Unknown protocol
    
    // Add some payload
    memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), "TestData12", 10);
    
    ParsedPacket parsed;
    EXPECT_TRUE(parser->parsePacket(packet, packet_size, parsed));
    
    EXPECT_EQ(parsed.ip_protocol, 255);
    EXPECT_EQ(parsed.payload_length, 10);
    EXPECT_EQ(memcmp(parsed.payload, "TestData12", 10), 0);
}

// Test main function
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
