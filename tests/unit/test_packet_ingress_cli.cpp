// tests/unit/test_common_packet_parser.cpp
#include <gtest/gtest.h>
#include "../../src/common/packet_parser.hpp"
#include "../../src/common/utils.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>

using namespace NetworkSecurity::Common;

class PacketParserTest : public ::testing::Test
{
protected:
    PacketParser parser;
    ParsedPacket parsed;

    void SetUp() override
    {
        // Initialize parser and parsed packet
        parsed = ParsedPacket();
    }

    void TearDown() override
    {
        // Cleanup if needed
    }

    // Helper function to create Ethernet header
    void createEthernetHeader(uint8_t *buffer, const uint8_t *src_mac, const uint8_t *dst_mac, uint16_t ether_type)
    {
        struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(buffer);
        std::memcpy(eth->h_source, src_mac, 6);
        std::memcpy(eth->h_dest, dst_mac, 6);
        eth->h_proto = htons(ether_type);
    }

    // Helper function to create IPv4 header
    size_t createIPv4Header(uint8_t *buffer, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint16_t total_len)
    {
        struct iphdr *ip = reinterpret_cast<struct iphdr *>(buffer);
        std::memset(ip, 0, sizeof(struct iphdr));

        ip->version = 4;
        ip->ihl = 5; // 20 bytes
        ip->tos = 0;
        ip->tot_len = htons(total_len);
        ip->id = htons(12345);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = protocol;
        ip->check = 0;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;

        return sizeof(struct iphdr);
    }

    // Helper function to create IPv6 header
    size_t createIPv6Header(uint8_t *buffer, const uint8_t *src_ip, const uint8_t *dst_ip, uint8_t next_header, uint16_t payload_len)
    {
        struct ip6_hdr *ip6 = reinterpret_cast<struct ip6_hdr *>(buffer);
        std::memset(ip6, 0, sizeof(struct ip6_hdr));

        uint32_t vtf = (6 << 28); // Version 6
        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(vtf);
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(payload_len);
        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = next_header;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;

        std::memcpy(&ip6->ip6_src, src_ip, 16);
        std::memcpy(&ip6->ip6_dst, dst_ip, 16);

        return sizeof(struct ip6_hdr);
    }

    // Helper function to create TCP header
    size_t createTCPHeader(uint8_t *buffer, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags)
    {
        struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(buffer);
        std::memset(tcp, 0, sizeof(struct tcphdr));

        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
        tcp->seq = htonl(seq);
        tcp->ack_seq = htonl(ack);
        tcp->doff = 5; // 20 bytes
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        // Set flags using bit fields
        tcp->fin = (flags & 0x01) != 0;
        tcp->syn = (flags & 0x02) != 0;
        tcp->rst = (flags & 0x04) != 0;
        tcp->psh = (flags & 0x08) != 0;
        tcp->ack = (flags & 0x10) != 0;
        tcp->urg = (flags & 0x20) != 0;

        // Set ECE and CWR in raw bytes (byte 13)
        uint8_t *tcp_bytes = reinterpret_cast<uint8_t *>(tcp);
        if (flags & 0x40)
            tcp_bytes[13] |= 0x40; // ECE
        if (flags & 0x80)
            tcp_bytes[13] |= 0x80; // CWR

        return sizeof(struct tcphdr);
    }

    // Helper function to create UDP header
    size_t createUDPHeader(uint8_t *buffer, uint16_t src_port, uint16_t dst_port, uint16_t length)
    {
        struct udphdr *udp = reinterpret_cast<struct udphdr *>(buffer);
        std::memset(udp, 0, sizeof(struct udphdr));

        udp->source = htons(src_port);
        udp->dest = htons(dst_port);
        udp->len = htons(length);
        udp->check = 0;

        return sizeof(struct udphdr);
    }

    // Helper function to create ICMP header
    size_t createICMPHeader(uint8_t *buffer, uint8_t type, uint8_t code, uint16_t id, uint16_t seq)
    {
        struct icmphdr *icmp = reinterpret_cast<struct icmphdr *>(buffer);
        std::memset(icmp, 0, sizeof(struct icmphdr));

        icmp->type = type;
        icmp->code = code;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(seq);

        return sizeof(struct icmphdr);
    }

    // Helper function to create ICMPv6 header
    size_t createICMPv6Header(uint8_t *buffer, uint8_t type, uint8_t code)
    {
        struct icmp6_hdr *icmp6 = reinterpret_cast<struct icmp6_hdr *>(buffer);
        std::memset(icmp6, 0, sizeof(struct icmp6_hdr));

        icmp6->icmp6_type = type;
        icmp6->icmp6_code = code;
        icmp6->icmp6_cksum = 0;

        return sizeof(struct icmp6_hdr);
    }

    // Helper function to create ARP packet
    size_t createARPPacket(uint8_t *buffer, uint16_t opcode, const uint8_t *sender_mac, uint32_t sender_ip,
                           const uint8_t *target_mac, uint32_t target_ip)
    {
        struct arp_packet
        {
            uint16_t hardware_type;
            uint16_t protocol_type;
            uint8_t hardware_size;
            uint8_t protocol_size;
            uint16_t opcode;
            uint8_t sender_mac[6];
            uint32_t sender_ip;
            uint8_t target_mac[6];
            uint32_t target_ip;
        } __attribute__((packed));

        arp_packet *arp = reinterpret_cast<arp_packet *>(buffer);
        arp->hardware_type = htons(1); // Ethernet
        arp->protocol_type = htons(ETH_P_IP);
        arp->hardware_size = 6;
        arp->protocol_size = 4;
        arp->opcode = htons(opcode);
        std::memcpy(arp->sender_mac, sender_mac, 6);
        arp->sender_ip = sender_ip;
        std::memcpy(arp->target_mac, target_mac, 6);
        arp->target_ip = target_ip;

        return sizeof(arp_packet);
    }
};

// ==================== Test Ethernet Parsing ====================

TEST_F(PacketParserTest, ParseEthernetHeader_ValidPacket)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);

    size_t offset = 0;
    ASSERT_TRUE(parser.parseEthernet(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_EQ(0, std::memcmp(parsed.ethernet.src_mac, src_mac, 6));
    EXPECT_EQ(0, std::memcmp(parsed.ethernet.dst_mac, dst_mac, 6));
    EXPECT_EQ(htons(ETH_P_IP), parsed.ethernet.ether_type);
    EXPECT_EQ(sizeof(struct ethhdr), offset);
}

TEST_F(PacketParserTest, ParseEthernetHeader_TooShort)
{
    uint8_t packet[10]; // Too short for Ethernet header
    size_t offset = 0;

    EXPECT_FALSE(parser.parseEthernet(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, ParseEthernetHeader_WithVLAN)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // Create Ethernet header with VLAN tag
    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_8021Q);

    // Add VLAN tag
    uint16_t *vlan_tag = reinterpret_cast<uint16_t *>(packet + sizeof(struct ethhdr));
    vlan_tag[0] = htons((3 << 13) | 100); // Priority 3, VLAN ID 100
    vlan_tag[1] = htons(ETH_P_IP);        // Real EtherType

    size_t offset = 0;
    ASSERT_TRUE(parser.parseEthernet(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.ethernet.has_vlan);
    EXPECT_EQ(3, parsed.ethernet.vlan_priority);
    EXPECT_EQ(100, parsed.ethernet.vlan_id);
    EXPECT_EQ(htons(ETH_P_IP), parsed.ethernet.ether_type);
}

// ==================== Test IPv4 Parsing ====================

TEST_F(PacketParserTest, ParseIPv4Header_ValidPacket)
{
    uint8_t packet[1500];
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("10.0.0.1");

    size_t offset = 0;
    createIPv4Header(packet, src_ip, dst_ip, IPPROTO_TCP, 40);

    ASSERT_TRUE(parser.parseIPv4(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_ipv4);
    EXPECT_EQ(4, parsed.ipv4.version);
    EXPECT_EQ(5, parsed.ipv4.ihl);
    EXPECT_EQ(IPPROTO_TCP, parsed.ipv4.protocol);
    EXPECT_EQ(src_ip, parsed.ipv4.src_ip);
    EXPECT_EQ(dst_ip, parsed.ipv4.dst_ip);
    EXPECT_EQ(64, parsed.ipv4.ttl);
    EXPECT_EQ(40, parsed.ipv4.total_length);
}

TEST_F(PacketParserTest, ParseIPv4Header_WithFragmentation)
{
    uint8_t packet[1500];
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("10.0.0.1");

    struct iphdr *ip = reinterpret_cast<struct iphdr *>(packet);
    std::memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(100);
    ip->id = htons(12345);
    ip->frag_off = htons(0x2000 | 100); // More fragments + offset 100
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;

    size_t offset = 0;
    ASSERT_TRUE(parser.parseIPv4(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_ipv4);
    EXPECT_TRUE(parsed.ipv4.is_fragmented);
    EXPECT_TRUE(parsed.ipv4.more_fragments);
    EXPECT_EQ(100, parsed.ipv4.fragment_offset);
}

TEST_F(PacketParserTest, ParseIPv4Header_InvalidVersion)
{
    uint8_t packet[1500];
    struct iphdr *ip = reinterpret_cast<struct iphdr *>(packet);
    std::memset(ip, 0, sizeof(struct iphdr));

    ip->version = 6; // Invalid for IPv4
    ip->ihl = 5;
    ip->tot_len = htons(20);
    ip->ttl = 64;

    size_t offset = 0;
    EXPECT_FALSE(parser.parseIPv4(packet, sizeof(packet), parsed, offset));
}

// ==================== Test IPv6 Parsing ====================

TEST_F(PacketParserTest, ParseIPv6Header_ValidPacket)
{
    uint8_t packet[1500];
    uint8_t src_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dst_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    size_t offset = 0;
    createIPv6Header(packet, src_ip, dst_ip, IPPROTO_TCP, 20);

    ASSERT_TRUE(parser.parseIPv6(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_ipv6);
    EXPECT_EQ(6, parsed.ipv6.version);
    EXPECT_EQ(IPPROTO_TCP, parsed.ipv6.next_header);
    EXPECT_EQ(20, parsed.ipv6.payload_length);
    EXPECT_EQ(64, parsed.ipv6.hop_limit);
}

// ==================== Test TCP Parsing ====================

TEST_F(PacketParserTest, ParseTCPHeader_ValidPacket)
{
    uint8_t packet[1500];
    size_t offset = 0;

    createTCPHeader(packet, 12345, 80, 1000, 2000, 0x12); // SYN + ACK

    ASSERT_TRUE(parser.parseTCP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_tcp);
    EXPECT_EQ(12345, parsed.tcp.src_port);
    EXPECT_EQ(80, parsed.tcp.dst_port);
    EXPECT_EQ(1000, parsed.tcp.seq_number);
    EXPECT_EQ(2000, parsed.tcp.ack_number);
    EXPECT_TRUE(parsed.tcp.flag_syn);
    EXPECT_TRUE(parsed.tcp.flag_ack);
    EXPECT_FALSE(parsed.tcp.flag_fin);
    EXPECT_EQ(0x12, parsed.tcp.flags);
}

TEST_F(PacketParserTest, ParseTCPHeader_AllFlags)
{
    uint8_t packet[1500];
    size_t offset = 0;

    // Test all flags including ECE and CWR
    createTCPHeader(packet, 12345, 80, 1000, 2000, 0xFF);

    ASSERT_TRUE(parser.parseTCP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.tcp.flag_fin);
    EXPECT_TRUE(parsed.tcp.flag_syn);
    EXPECT_TRUE(parsed.tcp.flag_rst);
    EXPECT_TRUE(parsed.tcp.flag_psh);
    EXPECT_TRUE(parsed.tcp.flag_ack);
    EXPECT_TRUE(parsed.tcp.flag_urg);
    EXPECT_TRUE(parsed.tcp.flag_ece);
    EXPECT_TRUE(parsed.tcp.flag_cwr);
    EXPECT_EQ(0xFF, parsed.tcp.flags);
}

TEST_F(PacketParserTest, ParseTCPHeader_InvalidPort)
{
    uint8_t packet[1500];
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(packet);
    std::memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = 0; // Invalid
    tcp->dest = htons(80);
    tcp->doff = 5;

    size_t offset = 0;
    EXPECT_FALSE(parser.parseTCP(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, ParseTCPHeader_WithOptions)
{
    uint8_t packet[1500];
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(packet);
    std::memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->seq = htonl(1000);
    tcp->ack_seq = htonl(2000);
    tcp->doff = 8; // 32 bytes (20 bytes header + 12 bytes options)
    tcp->syn = 1;
    tcp->window = htons(65535);

    // Add some dummy options
    uint8_t *options = packet + sizeof(struct tcphdr);
    options[0] = 2;  // MSS option
    options[1] = 4;  // Length
    options[2] = 0x05;
    options[3] = 0xB4; // MSS = 1460

    size_t offset = 0;
    ASSERT_TRUE(parser.parseTCP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.tcp.has_options);
    EXPECT_GT(parsed.tcp.options_length, 0);
}

// ==================== Test UDP Parsing ====================

TEST_F(PacketParserTest, ParseUDPHeader_ValidPacket)
{
    uint8_t packet[1500];
    size_t offset = 0;

    createUDPHeader(packet, 12345, 53, 100);

    ASSERT_TRUE(parser.parseUDP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_udp);
    EXPECT_EQ(12345, parsed.udp.src_port);
    EXPECT_EQ(53, parsed.udp.dst_port);
    EXPECT_EQ(100, parsed.udp.length);
}

TEST_F(PacketParserTest, ParseUDPHeader_InvalidDestPort)
{
    uint8_t packet[1500];
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(packet);
    std::memset(udp, 0, sizeof(struct udphdr));

    udp->source = htons(12345);
    udp->dest = 0; // Invalid
    udp->len = htons(8);

    size_t offset = 0;
    EXPECT_FALSE(parser.parseUDP(packet, sizeof(packet), parsed, offset));
}

// ==================== Test ICMP Parsing ====================

TEST_F(PacketParserTest, ParseICMPHeader_EchoRequest)
{
    uint8_t packet[1500];
    size_t offset = 0;

    createICMPHeader(packet, ICMP_ECHO, 0, 1234, 5678);

    ASSERT_TRUE(parser.parseICMP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_icmp);
    EXPECT_EQ(ICMP_ECHO, parsed.icmp.type);
    EXPECT_EQ(0, parsed.icmp.code);
    EXPECT_EQ(1234, parsed.icmp.identifier);
    EXPECT_EQ(5678, parsed.icmp.sequence);
}

TEST_F(PacketParserTest, ParseICMPHeader_EchoReply)
{
    uint8_t packet[1500];
    size_t offset = 0;

    createICMPHeader(packet, ICMP_ECHOREPLY, 0, 1234, 5678);

    ASSERT_TRUE(parser.parseICMP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_icmp);
    EXPECT_EQ(ICMP_ECHOREPLY, parsed.icmp.type);
}

// ==================== Test ICMPv6 Parsing ====================

TEST_F(PacketParserTest, ParseICMPv6Header_EchoRequest)
{
    uint8_t packet[1500];
    size_t offset = 0;

    createICMPv6Header(packet, 128, 0); // Echo Request

    ASSERT_TRUE(parser.parseICMPv6(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_icmpv6);
    EXPECT_EQ(128, parsed.icmpv6.type);
    EXPECT_EQ(0, parsed.icmpv6.code);
}

// ==================== Test ARP Parsing ====================

TEST_F(PacketParserTest, ParseARPPacket_Request)
{
    uint8_t packet[1500];
    uint8_t sender_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t sender_ip = inet_addr("192.168.1.100");
    uint32_t target_ip = inet_addr("192.168.1.1");

    size_t offset = 0;
    createARPPacket(packet, 1, sender_mac, sender_ip, target_mac, target_ip);

    ASSERT_TRUE(parser.parseARP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_arp);
    EXPECT_EQ(1, parsed.arp.opcode); // ARP Request
    EXPECT_EQ(0, std::memcmp(parsed.arp.sender_mac, sender_mac, 6));
    EXPECT_EQ(sender_ip, parsed.arp.sender_ip);
    EXPECT_EQ(target_ip, parsed.arp.target_ip);
}

TEST_F(PacketParserTest, ParseARPPacket_Reply)
{
    uint8_t packet[1500];
    uint8_t sender_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t target_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint32_t sender_ip = inet_addr("192.168.1.1");
    uint32_t target_ip = inet_addr("192.168.1.100");

    size_t offset = 0;
    createARPPacket(packet, 2, sender_mac, sender_ip, target_mac, target_ip);

    ASSERT_TRUE(parser.parseARP(packet, sizeof(packet), parsed, offset));

    EXPECT_TRUE(parsed.has_arp);
    EXPECT_EQ(2, parsed.arp.opcode); // ARP Reply
}

// ==================== Test Full Packet Parsing ====================

TEST_F(PacketParserTest, ParseFullPacket_TCP_SYN)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("10.0.0.1");

    size_t offset = 0;

    // Ethernet header
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IP);
    offset += sizeof(struct ethhdr);

    // IPv4 header
    createIPv4Header(packet + offset, src_ip, dst_ip, IPPROTO_TCP, 40);
    offset += sizeof(struct iphdr);

    // TCP header
    createTCPHeader(packet + offset, 12345, 80, 1000, 0, 0x02); // SYN
    offset += sizeof(struct tcphdr);

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.has_ipv4);
    EXPECT_TRUE(parsed.has_tcp);
    EXPECT_EQ(ProtocolType::TCP, parsed.protocol_type);

    // Check quick access fields
    EXPECT_EQ(0, std::memcmp(parsed.src_mac, src_mac, 6));
    EXPECT_EQ(0, std::memcmp(parsed.dst_mac, dst_mac, 6));
    EXPECT_EQ(src_ip, parsed.src_ip);
    EXPECT_EQ(dst_ip, parsed.dst_ip);
    EXPECT_EQ(12345, parsed.src_port);
    EXPECT_EQ(80, parsed.dst_port);
    EXPECT_TRUE(parsed.tcp.flag_syn);
}

TEST_F(PacketParserTest, ParseFullPacket_UDP_DNS)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("8.8.8.8");

    size_t offset = 0;

    // Ethernet header
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IP);
    offset += sizeof(struct ethhdr);

    // IPv4 header
    createIPv4Header(packet + offset, src_ip, dst_ip, IPPROTO_UDP, 28);
    offset += sizeof(struct iphdr);

    // UDP header
    createUDPHeader(packet + offset, 54321, 53, 100);
    offset += sizeof(struct udphdr);

    // Add some payload
    const char *payload = "DNS Query Data";
    std::memcpy(packet + offset, payload, strlen(payload));
    offset += strlen(payload);

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.has_ipv4);
    EXPECT_TRUE(parsed.has_udp);
    EXPECT_EQ(ProtocolType::UDP, parsed.protocol_type);
    EXPECT_EQ(54321, parsed.udp.src_port);
    EXPECT_EQ(53, parsed.udp.dst_port);
    EXPECT_GT(parsed.payload_length, 0);
}

TEST_F(PacketParserTest, ParseFullPacket_ICMP_Ping)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("8.8.8.8");

    size_t offset = 0;

    // Ethernet header
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IP);
    offset += sizeof(struct ethhdr);

    // IPv4 header
    createIPv4Header(packet + offset, src_ip, dst_ip, IPPROTO_ICMP, 28);
    offset += sizeof(struct iphdr);

    // ICMP header
    createICMPHeader(packet + offset, ICMP_ECHO, 0, 1234, 1);
    offset += sizeof(struct icmphdr);

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.has_ipv4);
    EXPECT_TRUE(parsed.has_icmp);
    EXPECT_EQ(ProtocolType::ICMP, parsed.protocol_type);
    EXPECT_EQ(ICMP_ECHO, parsed.icmp.type);
}

TEST_F(PacketParserTest, ParseFullPacket_ARP)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t sender_ip = inet_addr("192.168.1.100");
    uint32_t target_ip = inet_addr("192.168.1.1");

    size_t offset = 0;

    // Ethernet header
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_ARP);
    offset += sizeof(struct ethhdr);

    // ARP packet
    createARPPacket(packet + offset, 1, src_mac, sender_ip, target_mac, target_ip);
    offset += 28; // ARP packet size

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.has_arp);
    EXPECT_EQ(ProtocolType::ARP, parsed.protocol_type);
    EXPECT_EQ(1, parsed.arp.opcode);
}

TEST_F(PacketParserTest, ParseFullPacket_IPv6_TCP)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t src_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dst_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    size_t offset = 0;

    // Ethernet header
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IPV6);
    offset += sizeof(struct ethhdr);

    // IPv6 header
    createIPv6Header(packet + offset, src_ip, dst_ip, IPPROTO_TCP, 20);
    offset += sizeof(struct ip6_hdr);

    // TCP header
    createTCPHeader(packet + offset, 12345, 80, 1000, 0, 0x02); // SYN
    offset += sizeof(struct tcphdr);

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    EXPECT_TRUE(parsed.has_ethernet);
    EXPECT_TRUE(parsed.has_ipv6);
    EXPECT_TRUE(parsed.has_tcp);
    EXPECT_EQ(ProtocolType::TCP, parsed.protocol_type);
}

// ==================== Test Utility Functions ====================

TEST_F(PacketParserTest, UtilityFunction_IPv4ToString)
{
    uint32_t ip = inet_addr("192.168.1.100");
    std::string ip_str = PacketParser::ipv4ToString(ip);
    EXPECT_EQ("192.168.1.100", ip_str);
}

TEST_F(PacketParserTest, UtilityFunction_IPv6ToString)
{
    uint8_t ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    std::string ip_str = PacketParser::ipv6ToString(ip);
    EXPECT_EQ("2001:db8::1", ip_str);
}

TEST_F(PacketParserTest, UtilityFunction_MACToString)
{
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::string mac_str = PacketParser::macToString(mac);
    EXPECT_EQ("00:11:22:33:44:55", mac_str);
}

TEST_F(PacketParserTest, UtilityFunction_MACToString_NullPointer)
{
    std::string mac_str = PacketParser::macToString(nullptr);
    EXPECT_EQ("00:00:00:00:00:00", mac_str);
}

TEST_F(PacketParserTest, UtilityFunction_ProtocolToString)
{
    EXPECT_EQ("TCP", PacketParser::protocolToString(IPPROTO_TCP));
    EXPECT_EQ("UDP", PacketParser::protocolToString(IPPROTO_UDP));
    EXPECT_EQ("ICMP", PacketParser::protocolToString(IPPROTO_ICMP));
    EXPECT_EQ("ICMPv6", PacketParser::protocolToString(IPPROTO_ICMPV6));
}

TEST_F(PacketParserTest, UtilityFunction_TCPFlagsToString)
{
    EXPECT_EQ("SYN", PacketParser::tcpFlagsToString(0x02));
    EXPECT_EQ("SYN|ACK", PacketParser::tcpFlagsToString(0x12));
    EXPECT_EQ("FIN|ACK", PacketParser::tcpFlagsToString(0x11));
    EXPECT_EQ("NONE", PacketParser::tcpFlagsToString(0x00));
    
    // Test all flags
    std::string all_flags = PacketParser::tcpFlagsToString(0xFF);
    EXPECT_NE(std::string::npos, all_flags.find("FIN"));
    EXPECT_NE(std::string::npos, all_flags.find("SYN"));
    EXPECT_NE(std::string::npos, all_flags.find("RST"));
    EXPECT_NE(std::string::npos, all_flags.find("PSH"));
    EXPECT_NE(std::string::npos, all_flags.find("ACK"));
    EXPECT_NE(std::string::npos, all_flags.find("URG"));
    EXPECT_NE(std::string::npos, all_flags.find("ECE"));
    EXPECT_NE(std::string::npos, all_flags.find("CWR"));
}

TEST_F(PacketParserTest, UtilityFunction_ICMPTypeToString)
{
    EXPECT_EQ("Echo Request", PacketParser::icmpTypeToString(ICMP_ECHO));
    EXPECT_EQ("Echo Reply", PacketParser::icmpTypeToString(ICMP_ECHOREPLY));
    EXPECT_EQ("Destination Unreachable", PacketParser::icmpTypeToString(ICMP_DEST_UNREACH));
    EXPECT_EQ("Time Exceeded", PacketParser::icmpTypeToString(ICMP_TIME_EXCEEDED));
}

TEST_F(PacketParserTest, UtilityFunction_ICMPv6TypeToString)
{
    EXPECT_EQ("Echo Request", PacketParser::icmpv6TypeToString(128));
    EXPECT_EQ("Echo Reply", PacketParser::icmpv6TypeToString(129));
    EXPECT_EQ("Destination Unreachable", PacketParser::icmpv6TypeToString(1));
    EXPECT_EQ("Neighbor Solicitation", PacketParser::icmpv6TypeToString(135));
}

TEST_F(PacketParserTest, UtilityFunction_ARPOpcodeToString)
{
    EXPECT_EQ("ARP Request", PacketParser::arpOpcodeToString(1));
    EXPECT_EQ("ARP Reply", PacketParser::arpOpcodeToString(2));
    EXPECT_EQ("RARP Request", PacketParser::arpOpcodeToString(3));
    EXPECT_EQ("RARP Reply", PacketParser::arpOpcodeToString(4));
}

TEST_F(PacketParserTest, UtilityFunction_GetProtocolTypeName)
{
    EXPECT_EQ("TCP", PacketParser::getProtocolTypeName(ProtocolType::TCP));
    EXPECT_EQ("UDP", PacketParser::getProtocolTypeName(ProtocolType::UDP));
    EXPECT_EQ("ARP", PacketParser::getProtocolTypeName(ProtocolType::ARP));
    EXPECT_EQ("IPv4", PacketParser::getProtocolTypeName(ProtocolType::IPV4));
    EXPECT_EQ("IPv6", PacketParser::getProtocolTypeName(ProtocolType::IPV6));
    EXPECT_EQ("ICMP", PacketParser::getProtocolTypeName(ProtocolType::ICMP));
    EXPECT_EQ("ICMPv6", PacketParser::getProtocolTypeName(ProtocolType::ICMPV6));
}

TEST_F(PacketParserTest, UtilityFunction_GetPacketSummary_TCP)
{
    // Create a full TCP packet
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("10.0.0.1");

    size_t offset = 0;
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IP);
    offset += sizeof(struct ethhdr);
    createIPv4Header(packet + offset, src_ip, dst_ip, IPPROTO_TCP, 40);
    offset += sizeof(struct iphdr);
    createTCPHeader(packet + offset, 12345, 80, 1000, 0, 0x02);
    offset += sizeof(struct tcphdr);

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    std::string summary = PacketParser::getPacketSummary(parsed);
    EXPECT_NE(std::string::npos, summary.find("TCP"));
    EXPECT_NE(std::string::npos, summary.find("192.168.1.100"));
    EXPECT_NE(std::string::npos, summary.find("10.0.0.1"));
    EXPECT_NE(std::string::npos, summary.find("12345"));
    EXPECT_NE(std::string::npos, summary.find("80"));
}

TEST_F(PacketParserTest, UtilityFunction_GetPacketSummary_ARP)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t sender_ip = inet_addr("192.168.1.100");
    uint32_t target_ip = inet_addr("192.168.1.1");

    size_t offset = 0;
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_ARP);
    offset += sizeof(struct ethhdr);
    createARPPacket(packet + offset, 1, src_mac, sender_ip, target_mac, target_ip);
    offset += 28;

    ASSERT_TRUE(parser.parsePacket(packet, offset, parsed));

    std::string summary = PacketParser::getPacketSummary(parsed);
    EXPECT_NE(std::string::npos, summary.find("ARP"));
    EXPECT_NE(std::string::npos, summary.find("192.168.1.100"));
    EXPECT_NE(std::string::npos, summary.find("192.168.1.1"));
}

// ==================== Test Edge Cases ====================

TEST_F(PacketParserTest, EdgeCase_NullPointer)
{
    EXPECT_FALSE(parser.parsePacket(nullptr, 100, parsed));
}

TEST_F(PacketParserTest, EdgeCase_ZeroLength)
{
    uint8_t packet[100];
    EXPECT_FALSE(parser.parsePacket(packet, 0, parsed));
}

TEST_F(PacketParserTest, EdgeCase_TruncatedPacket)
{
    uint8_t packet[20]; // Too short for full headers
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    createEthernetHeader(packet, src_mac, dst_mac, ETH_P_IP);

    EXPECT_FALSE(parser.parsePacket(packet, sizeof(packet), parsed));
}

TEST_F(PacketParserTest, EdgeCase_InvalidTCPFlagCombination_SYN_FIN)
{
    uint8_t packet[1500];
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(packet);
    std::memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->fin = 1; // Invalid: SYN + FIN

    size_t offset = 0;
    EXPECT_FALSE(parser.parseTCP(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, EdgeCase_InvalidTCPFlagCombination_RST_SYN)
{
    uint8_t packet[1500];
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(packet);
    std::memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5;
    tcp->rst = 1;
    tcp->syn = 1; // Invalid: RST + SYN

    size_t offset = 0;
    EXPECT_FALSE(parser.parseTCP(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, EdgeCase_IPv4WithZeroTTL)
{
    uint8_t packet[1500];
    struct iphdr *ip = reinterpret_cast<struct iphdr *>(packet);
    std::memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(20);
    ip->ttl = 0; // Invalid

    size_t offset = 0;
    EXPECT_FALSE(parser.parseIPv4(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, EdgeCase_IPv4WithInvalidHeaderLength)
{
    uint8_t packet[1500];
    struct iphdr *ip = reinterpret_cast<struct iphdr *>(packet);
    std::memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 3; // Invalid: less than minimum (5)
    ip->tot_len = htons(20);
    ip->ttl = 64;

    size_t offset = 0;
    EXPECT_FALSE(parser.parseIPv4(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, EdgeCase_TCPWithInvalidDataOffset)
{
    uint8_t packet[1500];
    struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(packet);
    std::memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 3; // Invalid: less than minimum (5)

    size_t offset = 0;
    EXPECT_FALSE(parser.parseTCP(packet, sizeof(packet), parsed, offset));
}

TEST_F(PacketParserTest, EdgeCase_UDPWithInvalidLength)
{
    uint8_t packet[1500];
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(packet);
    std::memset(udp, 0, sizeof(struct udphdr));

    udp->source = htons(12345);
    udp->dest = htons(53);
    udp->len = htons(4); // Invalid: less than header size (8)

    size_t offset = 0;
    EXPECT_FALSE(parser.parseUDP(packet, sizeof(packet), parsed, offset));
}

// ==================== Test Performance ====================

TEST_F(PacketParserTest, Performance_ParseManyPackets)
{
    uint8_t packet[1500];
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dst_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.100");
    uint32_t dst_ip = inet_addr("10.0.0.1");

    size_t offset = 0;
    createEthernetHeader(packet + offset, src_mac, dst_mac, ETH_P_IP);
    offset += sizeof(struct ethhdr);
    createIPv4Header(packet + offset, src_ip, dst_ip, IPPROTO_TCP, 40);
    offset += sizeof(struct iphdr);
    createTCPHeader(packet + offset, 12345, 80, 1000, 0, 0x02);
    offset += sizeof(struct tcphdr);

    // Parse 10000 packets
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; i++)
    {
        ParsedPacket temp_parsed;
        ASSERT_TRUE(parser.parsePacket(packet, offset, temp_parsed));
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Parsed 10000 packets in " << duration.count() << " ms" << std::endl;
}

// ==================== Main ====================

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
