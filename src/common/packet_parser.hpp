// src/common/packet_parser.hpp
#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Cấu trúc thông tin packet đã parse
         */
        struct ParsedPacket
        {
            // Ethernet header
            uint8_t src_mac[6];
            uint8_t dst_mac[6];
            uint16_t eth_type;

            // IP header
            uint8_t ip_version;
            uint8_t ip_protocol;
            uint32_t src_ip;
            uint32_t dst_ip;
            uint16_t ip_length;
            uint16_t ip_id;
            uint8_t ip_ttl;

            // Transport layer
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq_num;
            uint32_t ack_num;
            uint16_t tcp_flags;
            uint16_t window_size;

            // Payload
            const uint8_t *payload;
            size_t payload_length;

            // Metadata
            uint64_t timestamp;
            size_t packet_size;
            bool is_fragmented;
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
            bool parseEthernet(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Parse IP header
             */
            bool parseIP(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Parse TCP header
             */
            bool parseTCP(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Parse UDP header
             */
            bool parseUDP(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Utility functions
             */
            static std::string ipToString(uint32_t ip);
            static std::string macToString(const uint8_t *mac);
            static std::string protocolToString(uint8_t protocol);
            static std::string tcpFlagsToString(uint16_t flags);

        private:
            // Validation functions
            bool validateEthernet(const struct ethhdr *eth_header, size_t length);
            bool validateIP(const struct iphdr *ip_header, size_t length);
            bool validateTCP(const struct tcphdr *tcp_header, size_t length);
            bool validateUDP(const struct udphdr *udp_header, size_t length);
        };

    } // namespace Common
} // namespace NetworkSecurity

#endif // PACKET_PARSER_HPP
