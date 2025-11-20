// src/common/packet_parser.hpp
#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Enum cho các loại protocol
         */
        enum class ProtocolType
        {
            UNKNOWN = 0,
            ETHERNET,
            ARP,
            IPV4,
            IPV6,
            TCP,
            UDP,
            ICMP,
            ICMPV6,
            IGMP,
            ESP,
            AH,
            SCTP,
            GRE
        };

        /**
         * @brief Cấu trúc cho Ethernet header
         */
        struct EthernetHeader
        {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint16_t ether_type;
            bool has_vlan;
            uint16_t vlan_id;
            uint8_t vlan_priority;

            EthernetHeader()
            {
                std::memset(dst_mac, 0, 6);
                std::memset(src_mac, 0, 6);
                ether_type = 0;
                has_vlan = false;
                vlan_id = 0;
                vlan_priority = 0;
            }
        };

        /**
         * @brief Cấu trúc cho ARP header
         */
        struct ARPHeader
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

            ARPHeader()
            {
                hardware_type = 0;
                protocol_type = 0;
                hardware_size = 0;
                protocol_size = 0;
                opcode = 0;
                std::memset(sender_mac, 0, 6);
                sender_ip = 0;
                std::memset(target_mac, 0, 6);
                target_ip = 0;
            }
        };

        /**
         * @brief Cấu trúc cho IPv4 header
         */
        struct IPv4Header
        {
            uint8_t version;
            uint8_t ihl;
            uint8_t tos;
            uint16_t total_length;
            uint16_t identification;
            uint16_t flags;
            uint16_t fragment_offset;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t checksum;
            uint32_t src_ip;
            uint32_t dst_ip;
            bool is_fragmented;
            bool more_fragments;
            bool dont_fragment;

            IPv4Header()
            {
                version = 0;
                ihl = 0;
                tos = 0;
                total_length = 0;
                identification = 0;
                flags = 0;
                fragment_offset = 0;
                ttl = 0;
                protocol = 0;
                checksum = 0;
                src_ip = 0;
                dst_ip = 0;
                is_fragmented = false;
                more_fragments = false;
                dont_fragment = false;
            }
        };

        /**
         * @brief Cấu trúc cho IPv6 header
         */
        struct IPv6Header
        {
            uint8_t version;
            uint8_t traffic_class;
            uint32_t flow_label;
            uint16_t payload_length;
            uint8_t next_header;
            uint8_t hop_limit;
            uint8_t src_ip[16];
            uint8_t dst_ip[16];

            IPv6Header()
            {
                version = 0;
                traffic_class = 0;
                flow_label = 0;
                payload_length = 0;
                next_header = 0;
                hop_limit = 0;
                std::memset(src_ip, 0, 16);
                std::memset(dst_ip, 0, 16);
            }
        };

        /**
         * @brief Cấu trúc cho TCP header
         */
        struct TCPHeader
        {
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq_number;
            uint32_t ack_number;
            uint8_t data_offset;
            uint8_t reserved;
            uint8_t flags;
            uint16_t window_size;
            uint16_t checksum;
            uint16_t urgent_pointer;

            // TCP Flags
            bool flag_fin;
            bool flag_syn;
            bool flag_rst;
            bool flag_psh;
            bool flag_ack;
            bool flag_urg;
            bool flag_ece;
            bool flag_cwr;

            // TCP Options
            bool has_options;
            uint8_t options[40];
            size_t options_length;

            TCPHeader()
            {
                src_port = 0;
                dst_port = 0;
                seq_number = 0;
                ack_number = 0;
                data_offset = 0;
                reserved = 0;
                flags = 0;
                window_size = 0;
                checksum = 0;
                urgent_pointer = 0;
                flag_fin = false;
                flag_syn = false;
                flag_rst = false;
                flag_psh = false;
                flag_ack = false;
                flag_urg = false;
                flag_ece = false;
                flag_cwr = false;
                has_options = false;
                std::memset(options, 0, 40);
                options_length = 0;
            }
        };

        /**
         * @brief Cấu trúc cho UDP header
         */
        struct UDPHeader
        {
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t length;
            uint16_t checksum;

            UDPHeader()
            {
                src_port = 0;
                dst_port = 0;
                length = 0;
                checksum = 0;
            }
        };

        /**
         * @brief Cấu trúc cho ICMP header
         */
        struct ICMPHeader
        {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint32_t rest_of_header;

            // Echo request/reply specific
            uint16_t identifier;
            uint16_t sequence;

            ICMPHeader()
            {
                type = 0;
                code = 0;
                checksum = 0;
                rest_of_header = 0;
                identifier = 0;
                sequence = 0;
            }
        };

        /**
         * @brief Cấu trúc cho ICMPv6 header
         */
        struct ICMPv6Header
        {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint32_t reserved;

            ICMPv6Header()
            {
                type = 0;
                code = 0;
                checksum = 0;
                reserved = 0;
            }
        };

        /**
         * @brief Cấu trúc thông tin packet đã parse đầy đủ
         */
        struct ParsedPacket
        {
            // ==================== Metadata ====================
            uint64_t timestamp;          // Timestamp in microseconds
            size_t packet_size;          // Total packet size
            size_t captured_length;      // Captured length
            std::string interface_name;  // Interface name
            ProtocolType protocol_type;  // Highest protocol type detected

            // ==================== Layer 2 - Ethernet ====================
            bool has_ethernet;
            EthernetHeader ethernet;

            // ==================== Layer 2.5 - ARP ====================
            bool has_arp;
            ARPHeader arp;

            // ==================== Layer 3 - Network ====================
            bool has_ipv4;
            IPv4Header ipv4;

            bool has_ipv6;
            IPv6Header ipv6;

            // ==================== Layer 4 - Transport ====================
            bool has_tcp;
            TCPHeader tcp;

            bool has_udp;
            UDPHeader udp;

            bool has_icmp;
            ICMPHeader icmp;

            bool has_icmpv6;
            ICMPv6Header icmpv6;

            // ==================== Payload ====================
            const uint8_t *payload;
            size_t payload_length;

            // ==================== Additional Info ====================
            uint8_t ip_protocol;         // IP protocol number
            bool is_fragmented;          // Is packet fragmented
            bool is_truncated;           // Is packet truncated

            // ==================== Quick Access Fields ====================
            // For backward compatibility and quick access
            uint8_t src_mac[6];
            uint8_t dst_mac[6];
            uint16_t eth_type;
            uint32_t src_ip;             // IPv4 only
            uint32_t dst_ip;             // IPv4 only
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq_num;
            uint32_t ack_num;
            uint16_t tcp_flags;
            uint16_t window_size;
            uint8_t ip_ttl;
            uint8_t ip_version;

            // ==================== Constructor ====================
            ParsedPacket()
            {
                timestamp = 0;
                packet_size = 0;
                captured_length = 0;
                protocol_type = ProtocolType::UNKNOWN;

                has_ethernet = false;
                has_arp = false;
                has_ipv4 = false;
                has_ipv6 = false;
                has_tcp = false;
                has_udp = false;
                has_icmp = false;
                has_icmpv6 = false;

                payload = nullptr;
                payload_length = 0;

                ip_protocol = 0;
                is_fragmented = false;
                is_truncated = false;

                std::memset(src_mac, 0, 6);
                std::memset(dst_mac, 0, 6);
                eth_type = 0;
                src_ip = 0;
                dst_ip = 0;
                src_port = 0;
                dst_port = 0;
                seq_num = 0;
                ack_num = 0;
                tcp_flags = 0;
                window_size = 0;
                ip_ttl = 0;
                ip_version = 0;
            }
        };

        /**
         * @brief Parser cho các gói tin mạng
         */
        class PacketParser
        {
        public:
            PacketParser();
            ~PacketParser();

            /**
             * @brief Parse gói tin từ raw data
             */
            bool parsePacket(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Parse Ethernet header
             */
            bool parseEthernet(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ARP header
             */
            bool parseARP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse IPv4 header
             */
            bool parseIPv4(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse IPv6 header
             */
            bool parseIPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse TCP header
             */
            bool parseTCP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse UDP header
             */
            bool parseUDP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ICMP header
             */
            bool parseICMP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ICMPv6 header
             */
            bool parseICMPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Utility functions - Conversion
             */
            static std::string ipv4ToString(uint32_t ip);
            static std::string ipv6ToString(const uint8_t *ip);
            static std::string macToString(const uint8_t *mac);
            static std::string protocolToString(uint8_t protocol);
            static std::string tcpFlagsToString(uint8_t flags);
            static std::string icmpTypeToString(uint8_t type);
            static std::string icmpv6TypeToString(uint8_t type);
            static std::string arpOpcodeToString(uint16_t opcode);

            /**
             * @brief Get protocol type name
             */
            static std::string getProtocolTypeName(ProtocolType type);

            /**
             * @brief Get packet summary
             */
            static std::string getPacketSummary(const ParsedPacket &packet);

                    /**
         * @brief Struct đơn giản hóa để lưu database
         */
        struct PacketInfo
        {
            uint64_t timestamp;          // Milliseconds since epoch
            std::string src_mac;
            std::string dst_mac;
            std::string src_ip;
            std::string dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            std::string protocol;        // "TCP", "UDP", "ICMP", etc.
            uint32_t length;
            std::string flags;           // TCP flags (SYN, ACK, etc.)
            uint32_t payload_size;
            uint8_t ttl;
            std::string checksum;

            PacketInfo()
                : timestamp(0), src_port(0), dst_port(0),
                  length(0), payload_size(0), ttl(0) {}

            /**
             * @brief Tạo PacketInfo từ ParsedPacket
             */
            static PacketInfo fromParsedPacket(const ParsedPacket& parsed);
        };

        private:
            // Validation functions
            bool validateEthernet(const struct ethhdr *eth_header, size_t length);
            bool validateIPv4(const struct iphdr *ip_header, size_t length);
            bool validateIPv6(const struct ip6_hdr *ip6_header, size_t length);
            bool validateTCP(const struct tcphdr *tcp_header, size_t length);
            bool validateUDP(const struct udphdr *udp_header, size_t length);
            bool validateICMP(const struct icmphdr *icmp_header, size_t length);

            // Helper functions
            void extractTCPFlags(const struct tcphdr *tcp_header, TCPHeader &tcp);
            void extractIPv4Flags(const struct iphdr *ip_header, IPv4Header &ipv4);
            void copyQuickAccessFields(ParsedPacket &parsed);
        };
        
    } // namespace Common
} // namespace NetworkSecurity

#endif // PACKET_PARSER_HPP
