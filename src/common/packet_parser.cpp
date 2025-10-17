// src/common/packet_parser.cpp
#include "packet_parser.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace NetworkSecurity
{
    namespace Common
    {
        PacketParser::PacketParser()
        {
        }

        PacketParser::~PacketParser()
        {
        }

        bool PacketParser::parsePacket(const uint8_t *data, size_t length, ParsedPacket &parsed)
        {
            if (!data || length == 0)
            {
                return false;
            }

            // Initialize parsed packet
            memset(&parsed, 0, sizeof(ParsedPacket));
            parsed.timestamp = Utils::getCurrentTimestampUs();
            parsed.packet_size = length;

            size_t offset = 0;

            // Parse Ethernet header
            if (!parseEthernet(data + offset, length - offset, parsed))
            {
                return false;
            }
            offset += sizeof(struct ethhdr);

            // Parse based on ethernet type
            switch (ntohs(parsed.eth_type))
            {
            case ETH_P_IP: // IPv4
            {
                if (!parseIP(data + offset, length - offset, parsed))
                {
                    return false;
                }

                // Calculate IP header length
                const struct iphdr *ip_header = reinterpret_cast<const struct iphdr *>(data + offset);
                size_t ip_header_len = ip_header->ihl * 4;
                offset += ip_header_len;

                // Parse transport layer based on protocol
                switch (parsed.ip_protocol)
                {
                case IPPROTO_TCP:
                    if (!parseTCP(data + offset, length - offset, parsed))
                    {
                        return false;
                    }
                    // Calculate TCP header length
                    {
                        const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(data + offset);
                        size_t tcp_header_len = tcp_header->doff * 4;
                        offset += tcp_header_len;
                    }
                    break;

                case IPPROTO_UDP:
                    if (!parseUDP(data + offset, length - offset, parsed))
                    {
                        return false;
                    }
                    offset += sizeof(struct udphdr);
                    break;

                default:
                    // Other protocols - just mark the remaining as payload
                    break;
                }
                break;
            }

            case ETH_P_IPV6: // IPv6
                // IPv6 parsing could be added here
                return false; // Not implemented yet

            case ETH_P_ARP: // ARP
                // ARP parsing could be added here
                return false; // Not implemented yet

            default:
                // Unknown ethernet type
                return false;
            }

            // Set payload information
            if (offset < length)
            {
                parsed.payload = data + offset;
                parsed.payload_length = length - offset;
            }
            else
            {
                parsed.payload = nullptr;
                parsed.payload_length = 0;
            }

            return true;
        }

        bool PacketParser::parseEthernet(const uint8_t *data, size_t length, ParsedPacket &parsed)
        {
            if (length < sizeof(struct ethhdr))
            {
                return false;
            }

            const struct ethhdr *eth_header = reinterpret_cast<const struct ethhdr *>(data);

            if (!validateEthernet(eth_header, length))
            {
                return false;
            }

            // Copy MAC addresses
            memcpy(parsed.src_mac, eth_header->h_source, 6);
            memcpy(parsed.dst_mac, eth_header->h_dest, 6);
            parsed.eth_type = eth_header->h_proto;

            return true;
        }

        bool PacketParser::parseIP(const uint8_t *data, size_t length, ParsedPacket &parsed)
        {
            if (length < sizeof(struct iphdr))
            {
                return false;
            }

            const struct iphdr *ip_header = reinterpret_cast<const struct iphdr *>(data);

            if (!validateIP(ip_header, length))
            {
                return false;
            }

            // Extract IP header fields
            parsed.ip_version = ip_header->version;
            parsed.ip_protocol = ip_header->protocol;
            parsed.src_ip = ip_header->saddr;
            parsed.dst_ip = ip_header->daddr;
            parsed.ip_length = ntohs(ip_header->tot_len);
            parsed.ip_id = ntohs(ip_header->id);
            parsed.ip_ttl = ip_header->ttl;

            // Check for fragmentation
            uint16_t flags_and_frag = ntohs(ip_header->frag_off);
            parsed.is_fragmented = (flags_and_frag & 0x1FFF) != 0 || (flags_and_frag & 0x2000) != 0;

            return true;
        }

        bool PacketParser::parseTCP(const uint8_t *data, size_t length, ParsedPacket &parsed)
        {
            if (length < sizeof(struct tcphdr))
            {
                return false;
            }

            const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(data);

            if (!validateTCP(tcp_header, length))
            {
                return false;
            }

            // Extract TCP header fields
            parsed.src_port = ntohs(tcp_header->source);
            parsed.dst_port = ntohs(tcp_header->dest);
            parsed.seq_num = ntohl(tcp_header->seq);
            parsed.ack_num = ntohl(tcp_header->ack_seq);
            parsed.window_size = ntohs(tcp_header->window);

            // Extract TCP flags
            parsed.tcp_flags = 0;
            if (tcp_header->fin)
                parsed.tcp_flags |= 0x01;
            if (tcp_header->syn)
                parsed.tcp_flags |= 0x02;
            if (tcp_header->rst)
                parsed.tcp_flags |= 0x04;
            if (tcp_header->psh)
                parsed.tcp_flags |= 0x08;
            if (tcp_header->ack)
                parsed.tcp_flags |= 0x10;
            if (tcp_header->urg)
                parsed.tcp_flags |= 0x20;

            return true;
        }

        bool PacketParser::parseUDP(const uint8_t *data, size_t length, ParsedPacket &parsed)
        {
            if (length < sizeof(struct udphdr))
            {
                return false;
            }

            const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(data);

            if (!validateUDP(udp_header, length))
            {
                return false;
            }

            // Extract UDP header fields
            parsed.src_port = ntohs(udp_header->source);
            parsed.dst_port = ntohs(udp_header->dest);

            // UDP doesn't have sequence numbers, flags, etc.
            parsed.seq_num = 0;
            parsed.ack_num = 0;
            parsed.tcp_flags = 0;
            parsed.window_size = 0;

            return true;
        }

        std::string PacketParser::ipToString(uint32_t ip)
        {
            struct in_addr addr;
            addr.s_addr = ip;
            return std::string(inet_ntoa(addr));
        }

        std::string PacketParser::macToString(const uint8_t *mac)
        {
            if (!mac)
            {
                return "00:00:00:00:00:00";
            }

            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (int i = 0; i < 6; ++i)
            {
                if (i > 0)
                    ss << ":";
                ss << std::setw(2) << static_cast<int>(mac[i]);
            }
            return ss.str();
        }

        std::string PacketParser::protocolToString(uint8_t protocol)
        {
            switch (protocol)
            {
            case IPPROTO_ICMP:
                return "ICMP";
            case IPPROTO_TCP:
                return "TCP";
            case IPPROTO_UDP:
                return "UDP";
            case IPPROTO_IPV6:
                return "IPv6";
            case IPPROTO_ICMPV6:
                return "ICMPv6";
            case IPPROTO_ESP:
                return "ESP";
            case IPPROTO_AH:
                return "AH";
            case IPPROTO_SCTP:
                return "SCTP";
            case IPPROTO_GRE:
                return "GRE";
            default:
            {
                std::stringstream ss;
                ss << "Protocol-" << static_cast<int>(protocol);
                return ss.str();
            }
            }
        }

        std::string PacketParser::tcpFlagsToString(uint16_t flags)
        {
            std::vector<std::string> flag_names;

            if (flags & 0x01)
                flag_names.push_back("FIN");
            if (flags & 0x02)
                flag_names.push_back("SYN");
            if (flags & 0x04)
                flag_names.push_back("RST");
            if (flags & 0x08)
                flag_names.push_back("PSH");
            if (flags & 0x10)
                flag_names.push_back("ACK");
            if (flags & 0x20)
                flag_names.push_back("URG");
            if (flags & 0x40)
                flag_names.push_back("ECE");
            if (flags & 0x80)
                flag_names.push_back("CWR");

            if (flag_names.empty())
            {
                return "NONE";
            }

            return Utils::join(flag_names, "|");
        }

        bool PacketParser::validateEthernet(const struct ethhdr *eth_header, size_t length)
        {
            if (!eth_header || length < sizeof(struct ethhdr))
            {
                return false;
            }

            // Check for valid ethernet types
            uint16_t eth_type = ntohs(eth_header->h_proto);
            switch (eth_type)
            {
            case ETH_P_IP:       // IPv4
            case ETH_P_IPV6:     // IPv6
            case ETH_P_ARP:      // ARP
            case ETH_P_RARP:     // RARP
            case ETH_P_8021Q:    // VLAN
            case ETH_P_PPP_DISC: // PPPoE Discovery
            case ETH_P_PPP_SES:  // PPPoE Session
                return true;
            default:
                // Allow other types but could be more restrictive
                return eth_type >= 0x0600; // Ethernet II frame
            }
        }

        bool PacketParser::validateIP(const struct iphdr *ip_header, size_t length)
        {
            if (!ip_header || length < sizeof(struct iphdr))
            {
                return false;
            }

            // Check IP version
            if (ip_header->version != 4)
            {
                return false;
            }

            // Check header length
            size_t header_len = ip_header->ihl * 4;
            if (header_len < sizeof(struct iphdr) || header_len > length)
            {
                return false;
            }

            // Check total length
            uint16_t total_len = ntohs(ip_header->tot_len);
            if (total_len < header_len || total_len > length)
            {
                return false;
            }

            // Check TTL
            if (ip_header->ttl == 0)
            {
                return false;
            }

            // Validate checksum (optional - can be expensive)
            // Could implement checksum validation here

            return true;
        }

        bool PacketParser::validateTCP(const struct tcphdr *tcp_header, size_t length)
        {
            if (!tcp_header || length < sizeof(struct tcphdr))
            {
                return false;
            }

            // Check data offset (header length)
            size_t header_len = tcp_header->doff * 4;
            if (header_len < sizeof(struct tcphdr) || header_len > length)
            {
                return false;
            }

            // Check port numbers (0 is invalid)
            if (ntohs(tcp_header->source) == 0 || ntohs(tcp_header->dest) == 0)
            {
                return false;
            }

            // Check flag combinations for validity
            bool syn = tcp_header->syn;
            bool ack = tcp_header->ack;
            bool fin = tcp_header->fin;
            bool rst = tcp_header->rst;

            // RST should not be combined with SYN or FIN
            if (rst && (syn || fin))
            {
                return false;
            }

            // SYN+FIN combination is suspicious
            if (syn && fin)
            {
                return false;
            }

            return true;
        }

        bool PacketParser::validateUDP(const struct udphdr *udp_header, size_t length)
        {
            if (!udp_header || length < sizeof(struct udphdr))
            {
                return false;
            }

            // Check port numbers (0 is invalid for source in most cases, but allowed)
            if (ntohs(udp_header->dest) == 0)
            {
                return false;
            }

            // Check UDP length
            uint16_t udp_len = ntohs(udp_header->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > length)
            {
                return false;
            }

            return true;
        }

    } // namespace Common
} // namespace NetworkSecurity
