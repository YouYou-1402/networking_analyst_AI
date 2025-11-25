// src/common/packet_parser.cpp
#include "packet_parser.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <netinet/icmp6.h>

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
            parsed = ParsedPacket();
            parsed.raw_data = data;
            parsed.timestamp = Utils::getCurrentTimestampUs();
            parsed.packet_size = length;
            parsed.captured_length = length;

            size_t offset = 0;

            // Parse Ethernet header
            if (!parseEthernet(data, length, parsed, offset))
            {
                return false;
            }

            // Parse based on ethernet type
            switch (ntohs(parsed.ethernet.ether_type))
            {
            case ETH_P_IP: // IPv4
            {
                if (!parseIPv4(data, length, parsed, offset))
                {
                    return false;
                }

                // Parse transport layer based on protocol
                switch (parsed.ipv4.protocol)
                {
                case IPPROTO_TCP:
                    if (!parseTCP(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::TCP;
                    break;

                case IPPROTO_UDP:
                    if (!parseUDP(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::UDP;
                    break;

                case IPPROTO_ICMP:
                    if (!parseICMP(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::ICMP;
                    break;

                default:
                    // Other protocols - just mark the remaining as payload
                    parsed.protocol_type = ProtocolType::IPV4;
                    break;
                }
                break;
            }

            case ETH_P_IPV6: // IPv6
            {
                if (!parseIPv6(data, length, parsed, offset))
                {
                    return false;
                }

                // Parse transport layer based on next header
                switch (parsed.ipv6.next_header)
                {
                case IPPROTO_TCP:
                    if (!parseTCP(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::TCP;
                    break;

                case IPPROTO_UDP:
                    if (!parseUDP(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::UDP;
                    break;

                case IPPROTO_ICMPV6:
                    if (!parseICMPv6(data, length, parsed, offset))
                    {
                        return false;
                    }
                    parsed.protocol_type = ProtocolType::ICMPV6;
                    break;

                default:
                    parsed.protocol_type = ProtocolType::IPV6;
                    break;
                }
                break;
            }

            case ETH_P_ARP: // ARP
            {
                if (!parseARP(data, length, parsed, offset))
                {
                    return false;
                }
                parsed.protocol_type = ProtocolType::ARP;
                break;
            }

            default:
                // Unknown ethernet type
                parsed.protocol_type = ProtocolType::ETHERNET;
                break;
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

            // Check if packet is truncated
            if (parsed.has_ipv4 && parsed.ipv4.total_length > length)
            {
                parsed.is_truncated = true;
            }

            // Copy quick access fields
            copyQuickAccessFields(parsed);

            return true;
        }

        bool PacketParser::parseEthernet(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length < sizeof(struct ethhdr))
            {
                return false;
            }

            const struct ethhdr *eth_header = reinterpret_cast<const struct ethhdr *>(data + offset);

            if (!validateEthernet(eth_header, length - offset))
            {
                return false;
            }

            parsed.has_ethernet = true;

            // Copy MAC addresses
            std::memcpy(parsed.ethernet.src_mac, eth_header->h_source, 6);
            std::memcpy(parsed.ethernet.dst_mac, eth_header->h_dest, 6);
            parsed.ethernet.ether_type = eth_header->h_proto;

            offset += sizeof(struct ethhdr);

            // Check for VLAN tag (802.1Q)
            if (ntohs(parsed.ethernet.ether_type) == ETH_P_8021Q)
            {
                if (length - offset < 4)
                {
                    return false;
                }

                parsed.ethernet.has_vlan = true;
                const uint16_t *vlan_tag = reinterpret_cast<const uint16_t *>(data + offset);
                uint16_t tci = ntohs(vlan_tag[0]);
                parsed.ethernet.vlan_priority = (tci >> 13) & 0x07;
                parsed.ethernet.vlan_id = tci & 0x0FFF;
                parsed.ethernet.ether_type = vlan_tag[1]; // Real EtherType after VLAN tag

                offset += 4;
            }

            return true;
        }

        bool PacketParser::parseARP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            // ARP packet structure
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

            if (length - offset < sizeof(arp_packet))
            {
                return false;
            }

            const arp_packet *arp = reinterpret_cast<const arp_packet *>(data + offset);

            parsed.has_arp = true;
            parsed.arp.hardware_type = ntohs(arp->hardware_type);
            parsed.arp.protocol_type = ntohs(arp->protocol_type);
            parsed.arp.hardware_size = arp->hardware_size;
            parsed.arp.protocol_size = arp->protocol_size;
            parsed.arp.opcode = ntohs(arp->opcode);

            std::memcpy(parsed.arp.sender_mac, arp->sender_mac, 6);
            parsed.arp.sender_ip = arp->sender_ip;
            std::memcpy(parsed.arp.target_mac, arp->target_mac, 6);
            parsed.arp.target_ip = arp->target_ip;

            offset += sizeof(arp_packet);

            return true;
        }

        bool PacketParser::parseIPv4(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct iphdr))
            {
                return false;
            }

            const struct iphdr *ip_header = reinterpret_cast<const struct iphdr *>(data + offset);

            if (!validateIPv4(ip_header, length - offset))
            {
                return false;
            }

            parsed.has_ipv4 = true;

            // Extract IP header fields
            parsed.ipv4.version = ip_header->version;
            parsed.ipv4.ihl = ip_header->ihl;
            parsed.ipv4.tos = ip_header->tos;
            parsed.ipv4.total_length = ntohs(ip_header->tot_len);
            parsed.ipv4.identification = ntohs(ip_header->id);
            parsed.ipv4.ttl = ip_header->ttl;
            parsed.ipv4.protocol = ip_header->protocol;
            parsed.ipv4.checksum = ntohs(ip_header->check);
            parsed.ipv4.src_ip = ip_header->saddr;
            parsed.ipv4.dst_ip = ip_header->daddr;

            // Extract flags and fragment offset
            extractIPv4Flags(ip_header, parsed.ipv4);

            parsed.ip_protocol = ip_header->protocol;
            parsed.is_fragmented = parsed.ipv4.is_fragmented;

            // Calculate IP header length
            size_t ip_header_len = ip_header->ihl * 4;
            offset += ip_header_len;

            return true;
        }

        bool PacketParser::parseIPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct ip6_hdr))
            {
                return false;
            }

            const struct ip6_hdr *ip6_header = reinterpret_cast<const struct ip6_hdr *>(data + offset);

            if (!validateIPv6(ip6_header, length - offset))
            {
                return false;
            }

            parsed.has_ipv6 = true;

            // Extract IPv6 header fields
            uint32_t vtf = ntohl(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow);
            parsed.ipv6.version = (vtf >> 28) & 0x0F;
            parsed.ipv6.traffic_class = (vtf >> 20) & 0xFF;
            parsed.ipv6.flow_label = vtf & 0x000FFFFF;
            parsed.ipv6.payload_length = ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
            parsed.ipv6.next_header = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            parsed.ipv6.hop_limit = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim;

            std::memcpy(parsed.ipv6.src_ip, &ip6_header->ip6_src, 16);
            std::memcpy(parsed.ipv6.dst_ip, &ip6_header->ip6_dst, 16);

            parsed.ip_protocol = parsed.ipv6.next_header;

            offset += sizeof(struct ip6_hdr);

            return true;
        }

        bool PacketParser::parseTCP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct tcphdr))
            {
                return false;
            }

            const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(data + offset);

            if (!validateTCP(tcp_header, length - offset))
            {
                return false;
            }

            parsed.has_tcp = true;

            // Extract TCP header fields
            parsed.tcp.src_port = ntohs(tcp_header->source);
            parsed.tcp.dst_port = ntohs(tcp_header->dest);
            parsed.tcp.seq_number = ntohl(tcp_header->seq);
            parsed.tcp.ack_number = ntohl(tcp_header->ack_seq);
            parsed.tcp.data_offset = tcp_header->doff;
            parsed.tcp.window_size = ntohs(tcp_header->window);
            parsed.tcp.checksum = ntohs(tcp_header->check);
            parsed.tcp.urgent_pointer = ntohs(tcp_header->urg_ptr);

            // Extract TCP flags
            extractTCPFlags(tcp_header, parsed.tcp);

            // Calculate TCP header length
            size_t tcp_header_len = tcp_header->doff * 4;

            // Extract TCP options if present
            if (tcp_header_len > sizeof(struct tcphdr))
            {
                parsed.tcp.has_options = true;
                size_t options_len = tcp_header_len - sizeof(struct tcphdr);
                parsed.tcp.options_length = std::min(options_len, sizeof(parsed.tcp.options));
                std::memcpy(parsed.tcp.options, data + offset + sizeof(struct tcphdr), parsed.tcp.options_length);
            }

            offset += tcp_header_len;

            return true;
        }

        bool PacketParser::parseUDP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct udphdr))
            {
                return false;
            }

            const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(data + offset);

            if (!validateUDP(udp_header, length - offset))
            {
                return false;
            }

            parsed.has_udp = true;

            // Extract UDP header fields
            parsed.udp.src_port = ntohs(udp_header->source);
            parsed.udp.dst_port = ntohs(udp_header->dest);
            parsed.udp.length = ntohs(udp_header->len);
            parsed.udp.checksum = ntohs(udp_header->check);

            offset += sizeof(struct udphdr);

            return true;
        }

        bool PacketParser::parseICMP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct icmphdr))
            {
                return false;
            }

            const struct icmphdr *icmp_header = reinterpret_cast<const struct icmphdr *>(data + offset);

            if (!validateICMP(icmp_header, length - offset))
            {
                return false;
            }

            parsed.has_icmp = true;

            // Extract ICMP header fields
            parsed.icmp.type = icmp_header->type;
            parsed.icmp.code = icmp_header->code;
            parsed.icmp.checksum = ntohs(icmp_header->checksum);

            // For echo request/reply
            if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY)
            {
                parsed.icmp.identifier = ntohs(icmp_header->un.echo.id);
                parsed.icmp.sequence = ntohs(icmp_header->un.echo.sequence);
            }

            offset += sizeof(struct icmphdr);

            return true;
        }

        bool PacketParser::parseICMPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset)
        {
            if (length - offset < sizeof(struct icmp6_hdr))
            {
                return false;
            }

            const struct icmp6_hdr *icmp6_header = reinterpret_cast<const struct icmp6_hdr *>(data + offset);

            parsed.has_icmpv6 = true;

            // Extract ICMPv6 header fields
            parsed.icmpv6.type = icmp6_header->icmp6_type;
            parsed.icmpv6.code = icmp6_header->icmp6_code;
            parsed.icmpv6.checksum = ntohs(icmp6_header->icmp6_cksum);
            
            // Access icmp6_data32 correctly
            parsed.icmpv6.reserved = ntohl(icmp6_header->icmp6_dataun.icmp6_un_data32[0]);

            offset += sizeof(struct icmp6_hdr);

            return true;
        }

        // ==================== Utility Functions ====================

        std::string PacketParser::ipv4ToString(uint32_t ip)
        {
            struct in_addr addr;
            addr.s_addr = ip;
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
            return std::string(buffer);
        }

        std::string PacketParser::ipv6ToString(const uint8_t *ip)
        {
            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip, buffer, INET6_ADDRSTRLEN);
            return std::string(buffer);
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
            case IPPROTO_IGMP:
                return "IGMP";
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

        std::string PacketParser::tcpFlagsToString(uint8_t flags)
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

        std::string PacketParser::icmpTypeToString(uint8_t type)
        {
            switch (type)
            {
            case ICMP_ECHOREPLY:
                return "Echo Reply";
            case ICMP_DEST_UNREACH:
                return "Destination Unreachable";
            case ICMP_SOURCE_QUENCH:
                return "Source Quench";
            case ICMP_REDIRECT:
                return "Redirect";
            case ICMP_ECHO:
                return "Echo Request";
            case ICMP_TIME_EXCEEDED:
                return "Time Exceeded";
            case ICMP_PARAMETERPROB:
                return "Parameter Problem";
            case ICMP_TIMESTAMP:
                return "Timestamp Request";
            case ICMP_TIMESTAMPREPLY:
                return "Timestamp Reply";
            case ICMP_INFO_REQUEST:
                return "Information Request";
            case ICMP_INFO_REPLY:
                return "Information Reply";
            case ICMP_ADDRESS:
                return "Address Mask Request";
            case ICMP_ADDRESSREPLY:
                return "Address Mask Reply";
            default:
                return "Unknown (" + std::to_string(type) + ")";
            }
        }

        std::string PacketParser::icmpv6TypeToString(uint8_t type)
        {
            switch (type)
            {
            case 1:
                return "Destination Unreachable";
            case 2:
                return "Packet Too Big";
            case 3:
                return "Time Exceeded";
            case 4:
                return "Parameter Problem";
            case 128:
                return "Echo Request";
            case 129:
                return "Echo Reply";
            case 133:
                return "Router Solicitation";
            case 134:
                return "Router Advertisement";
            case 135:
                return "Neighbor Solicitation";
            case 136:
                return "Neighbor Advertisement";
            case 137:
                return "Redirect";
            default:
                return "Unknown (" + std::to_string(type) + ")";
            }
        }

        std::string PacketParser::arpOpcodeToString(uint16_t opcode)
        {
            switch (opcode)
            {
            case 1:
                return "ARP Request";
            case 2:
                return "ARP Reply";
            case 3:
                return "RARP Request";
            case 4:
                return "RARP Reply";
            default:
                return "Unknown (" + std::to_string(opcode) + ")";
            }
        }

        std::string PacketParser::getProtocolTypeName(ProtocolType type)
        {
            switch (type)
            {
            case ProtocolType::ETHERNET:
                return "Ethernet";
            case ProtocolType::ARP:
                return "ARP";
            case ProtocolType::IPV4:
                return "IPv4";
            case ProtocolType::IPV6:
                return "IPv6";
            case ProtocolType::TCP:
                return "TCP";
            case ProtocolType::UDP:
                return "UDP";
            case ProtocolType::ICMP:
                return "ICMP";
            case ProtocolType::ICMPV6:
                return "ICMPv6";
            case ProtocolType::IGMP:
                return "IGMP";
            case ProtocolType::ESP:
                return "ESP";
            case ProtocolType::AH:
                return "AH";
            case ProtocolType::SCTP:
                return "SCTP";
            case ProtocolType::GRE:
                return "GRE";
            default:
                return "Unknown";
            }
        }

        std::string PacketParser::getPacketSummary(const ParsedPacket &packet)
        {
            std::stringstream ss;

            ss << "[" << getProtocolTypeName(packet.protocol_type) << "] ";

            if (packet.has_arp)
            {
                ss << arpOpcodeToString(packet.arp.opcode) << " ";
                ss << ipv4ToString(packet.arp.sender_ip) << " -> ";
                ss << ipv4ToString(packet.arp.target_ip);
            }
            else if (packet.has_ipv4)
            {
                ss << ipv4ToString(packet.ipv4.src_ip) << " -> ";
                ss << ipv4ToString(packet.ipv4.dst_ip);

                if (packet.has_tcp)
                {
                    ss << " [" << packet.tcp.src_port << " -> " << packet.tcp.dst_port << "]";
                    ss << " Flags: " << tcpFlagsToString(packet.tcp.flags);
                }
                else if (packet.has_udp)
                {
                    ss << " [" << packet.udp.src_port << " -> " << packet.udp.dst_port << "]";
                }
                else if (packet.has_icmp)
                {
                    ss << " " << icmpTypeToString(packet.icmp.type);
                }
            }
            else if (packet.has_ipv6)
            {
                ss << ipv6ToString(packet.ipv6.src_ip) << " -> ";
                ss << ipv6ToString(packet.ipv6.dst_ip);

                if (packet.has_tcp)
                {
                    ss << " [" << packet.tcp.src_port << " -> " << packet.tcp.dst_port << "]";
                }
                else if (packet.has_udp)
                {
                    ss << " [" << packet.udp.src_port << " -> " << packet.udp.dst_port << "]";
                }
                else if (packet.has_icmpv6)
                {
                    ss << " " << icmpv6TypeToString(packet.icmpv6.type);
                }
            }

            ss << " (" << packet.packet_size << " bytes)";

            return ss.str();
        }

        // ==================== Validation Functions ====================

        bool PacketParser::validateEthernet(const struct ethhdr *eth_header, size_t length)
        {
            if (!eth_header || length < sizeof(struct ethhdr))
            {
                return false;
            }

            uint16_t eth_type = ntohs(eth_header->h_proto);
            switch (eth_type)
            {
            case ETH_P_IP:
            case ETH_P_IPV6:
            case ETH_P_ARP:
            case ETH_P_RARP:
            case ETH_P_8021Q:
            case ETH_P_PPP_DISC:
            case ETH_P_PPP_SES:
                return true;
            default:
                return eth_type >= 0x0600;
            }
        }

        bool PacketParser::validateIPv4(const struct iphdr *ip_header, size_t length)
        {
            if (!ip_header || length < sizeof(struct iphdr))
            {
                return false;
            }

            if (ip_header->version != 4)
            {
                return false;
            }

            size_t header_len = ip_header->ihl * 4;
            if (header_len < sizeof(struct iphdr) || header_len > length)
            {
                return false;
            }

            uint16_t total_len = ntohs(ip_header->tot_len);
            if (total_len < header_len)
            {
                return false;
            }

            if (ip_header->ttl == 0)
            {
                return false;
            }

            return true;
        }

        bool PacketParser::validateIPv6(const struct ip6_hdr *ip6_header, size_t length)
        {
            if (!ip6_header || length < sizeof(struct ip6_hdr))
            {
                return false;
            }

            uint32_t vtf = ntohl(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow);
            uint8_t version = (vtf >> 28) & 0x0F;

            if (version != 6)
            {
                return false;
            }

            return true;
        }

        bool PacketParser::validateTCP(const struct tcphdr *tcp_header, size_t length)
        {
            if (!tcp_header || length < sizeof(struct tcphdr))
            {
                return false;
            }

            size_t header_len = tcp_header->doff * 4;
            if (header_len < sizeof(struct tcphdr) || header_len > length)
            {
                return false;
            }

            if (ntohs(tcp_header->source) == 0 || ntohs(tcp_header->dest) == 0)
            {
                return false;
            }

            bool syn = tcp_header->syn;
            bool fin = tcp_header->fin;
            bool rst = tcp_header->rst;

            if (rst && (syn || fin))
            {
                return false;
            }

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

            if (ntohs(udp_header->dest) == 0)
            {
                return false;
            }

            uint16_t udp_len = ntohs(udp_header->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > length)
            {
                return false;
            }

            return true;
        }

        bool PacketParser::validateICMP(const struct icmphdr *icmp_header, size_t length)
        {
            if (!icmp_header || length < sizeof(struct icmphdr))
            {
                return false;
            }

            return true;
        }

        // ==================== Helper Functions ====================

        void PacketParser::extractTCPFlags(const struct tcphdr *tcp_header, TCPHeader &tcp)
        {
            // Extract individual flags from tcphdr
            tcp.flag_fin = tcp_header->fin;
            tcp.flag_syn = tcp_header->syn;
            tcp.flag_rst = tcp_header->rst;
            tcp.flag_psh = tcp_header->psh;
            tcp.flag_ack = tcp_header->ack;
            tcp.flag_urg = tcp_header->urg;

            // ECE and CWR flags need to be extracted from raw bytes
            // because they may not be in the struct
            const uint8_t *tcp_bytes = reinterpret_cast<const uint8_t *>(tcp_header);
            uint8_t flags_byte = tcp_bytes[13]; // Flags are in byte 13

            tcp.flag_ece = (flags_byte & 0x40) != 0;
            tcp.flag_cwr = (flags_byte & 0x80) != 0;

            // Build combined flags byte
            tcp.flags = 0;
            if (tcp.flag_fin)
                tcp.flags |= 0x01;
            if (tcp.flag_syn)
                tcp.flags |= 0x02;
            if (tcp.flag_rst)
                tcp.flags |= 0x04;
            if (tcp.flag_psh)
                tcp.flags |= 0x08;
            if (tcp.flag_ack)
                tcp.flags |= 0x10;
            if (tcp.flag_urg)
                tcp.flags |= 0x20;
            if (tcp.flag_ece)
                tcp.flags |= 0x40;
            if (tcp.flag_cwr)
                tcp.flags |= 0x80;
        }

        void PacketParser::extractIPv4Flags(const struct iphdr *ip_header, IPv4Header &ipv4)
        {
            uint16_t flags_and_frag = ntohs(ip_header->frag_off);

            ipv4.dont_fragment = (flags_and_frag & 0x4000) != 0;
            ipv4.more_fragments = (flags_and_frag & 0x2000) != 0;
            ipv4.fragment_offset = flags_and_frag & 0x1FFF;
            ipv4.is_fragmented = (ipv4.fragment_offset != 0) || ipv4.more_fragments;
            ipv4.flags = (flags_and_frag >> 13) & 0x07;
        }

        void PacketParser::copyQuickAccessFields(ParsedPacket &parsed)
        {
            // Copy Ethernet
            if (parsed.has_ethernet)
            {
                std::memcpy(parsed.src_mac, parsed.ethernet.src_mac, 6);
                std::memcpy(parsed.dst_mac, parsed.ethernet.dst_mac, 6);
                parsed.eth_type = parsed.ethernet.ether_type;
            }

            // Copy IPv4
            if (parsed.has_ipv4)
            {
                parsed.src_ip = parsed.ipv4.src_ip;
                parsed.dst_ip = parsed.ipv4.dst_ip;
                parsed.ip_ttl = parsed.ipv4.ttl;
                parsed.ip_version = parsed.ipv4.version;
            }

            // Copy TCP
            if (parsed.has_tcp)
            {
                parsed.src_port = parsed.tcp.src_port;
                parsed.dst_port = parsed.tcp.dst_port;
                parsed.seq_num = parsed.tcp.seq_number;
                parsed.ack_num = parsed.tcp.ack_number;
                parsed.tcp_flags = parsed.tcp.flags;
                parsed.window_size = parsed.tcp.window_size;
            }

            // Copy UDP
            if (parsed.has_udp)
            {
                parsed.src_port = parsed.udp.src_port;
                parsed.dst_port = parsed.udp.dst_port;
            }
        }

    } // namespace Common
} // namespace NetworkSecurity
