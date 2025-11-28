// src/common/packet_parser.cpp
#include "packet_parser.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <algorithm>

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== Constructor & Destructor ====================
        PacketParser::PacketParser()
            : packet_counter_(0),
              first_packet_time_(0),
              last_packet_time_(0),
              next_tcp_stream_id_(0),
              next_udp_stream_id_(0)
        {
        }

        PacketParser::~PacketParser()
        {
        }

        void PacketParser::reset()
        {
            packet_counter_ = 0;
            first_packet_time_ = 0;
            last_packet_time_ = 0;
            next_tcp_stream_id_ = 0;
            next_udp_stream_id_ = 0;
            tcp_streams_.clear();
            udp_streams_.clear();
            arp_cache_.clear();
            icmp_echo_requests_.clear();
        }

        // ==================== Main Parse Function ====================
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

            // Set frame metadata
            parsed.frame_metadata.frame_number = ++packet_counter_;
            parsed.frame_metadata.frame_len = length;
            parsed.frame_metadata.frame_cap_len = length;

            // Calculate time relative and delta
            if (first_packet_time_ == 0)
            {
                first_packet_time_ = parsed.timestamp;
            }
            
            parsed.frame_metadata.frame_time_relative = 
                (parsed.timestamp - first_packet_time_) / 1000000.0;
            
            if (last_packet_time_ > 0)
            {
                parsed.frame_metadata.frame_time_delta = 
                    (parsed.timestamp - last_packet_time_) / 1000000.0;
            }
            
            last_packet_time_ = parsed.timestamp;

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
            
            // Build protocol string
            buildProtocolString(parsed);
            
            // Detect application protocol
            parsed.app_protocol = detectApplicationProtocol(parsed);

            // Set encryption flag based on detected protocol
            if (parsed.app_protocol == AppProtocol::HTTPS ||
                parsed.app_protocol == AppProtocol::SSH)
            {
                parsed.is_encrypted = true;
            }
            else
            {
                parsed.is_encrypted = false;
            }
            return true;
        }

        // ==================== Ethernet Parsing ====================
        bool PacketParser::parseEthernet(const uint8_t *data, size_t length, 
                                        ParsedPacket &parsed, size_t &offset)
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

            // Analyze MAC addresses (OUI, LG/IG bits)
            analyzeEthernetMAC(parsed.ethernet);

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
                parsed.ethernet.vlan_cfi = ((tci >> 12) & 0x01) != 0;
                parsed.ethernet.vlan_id = tci & 0x0FFF;
                parsed.ethernet.vlan_etype = vlan_tag[1];
                parsed.ethernet.ether_type = vlan_tag[1]; // Real EtherType after VLAN tag

                offset += 4;
                
                // Check for QinQ (802.1ad) - double VLAN tagging
                if (ntohs(parsed.ethernet.ether_type) == ETH_P_8021Q)
                {
                    if (length - offset < 4)
                    {
                        return false;
                    }
                    
                    parsed.ethernet.has_qinq = true;
                    parsed.ethernet.outer_vlan_id = parsed.ethernet.vlan_id;
                    
                    const uint16_t *inner_vlan_tag = reinterpret_cast<const uint16_t *>(data + offset);
                    uint16_t inner_tci = ntohs(inner_vlan_tag[0]);
                    parsed.ethernet.inner_vlan_id = inner_tci & 0x0FFF;
                    parsed.ethernet.ether_type = inner_vlan_tag[1];
                    
                    offset += 4;
                }
            }

            return true;
        }

        void PacketParser::analyzeEthernetMAC(EthernetHeader &eth)
        {
            // Analyze destination MAC
            eth.dst_lg_bit = (eth.dst_mac[0] & 0x02) != 0; // Local/Global bit
            eth.dst_ig_bit = (eth.dst_mac[0] & 0x01) != 0; // Individual/Group bit
            eth.dst_oui = (eth.dst_mac[0] << 16) | (eth.dst_mac[1] << 8) | eth.dst_mac[2];
            
            // Analyze source MAC
            eth.src_lg_bit = (eth.src_mac[0] & 0x02) != 0;
            eth.src_ig_bit = (eth.src_mac[0] & 0x01) != 0;
            eth.src_oui = (eth.src_mac[0] << 16) | (eth.src_mac[1] << 8) | eth.src_mac[2];
        }

        // ==================== ARP Parsing ====================
        bool PacketParser::parseARP(const uint8_t *data, size_t length, 
                                   ParsedPacket &parsed, size_t &offset)
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
            
            // Analyze ARP packet
            analyzeARP(parsed);

            return true;
        }

        void PacketParser::analyzeARP(ParsedPacket &parsed)
        {
            // Detect gratuitous ARP (sender IP == target IP)
            if (parsed.arp.sender_ip == parsed.arp.target_ip)
            {
                parsed.arp.is_gratuitous = true;
            }
            
            // Detect ARP probe (sender IP == 0.0.0.0)
            if (parsed.arp.sender_ip == 0)
            {
                parsed.arp.is_probe = true;
            }
            
            // Detect ARP announcement (sender IP == target IP && opcode == reply)
            if (parsed.arp.sender_ip == parsed.arp.target_ip && parsed.arp.opcode == 2)
            {
                parsed.arp.is_announcement = true;
            }
            
            // Check for duplicate IP (same IP, different MAC)
            uint64_t sender_mac_as_uint = 0;
            for (int i = 0; i < 6; i++)
            {
                sender_mac_as_uint = (sender_mac_as_uint << 8) | parsed.arp.sender_mac[i];
            }
            
            auto it = arp_cache_.find(parsed.arp.sender_ip);
            if (it != arp_cache_.end())
            {
                if (it->second.first != sender_mac_as_uint)
                {
                    parsed.arp.is_duplicate_ip = true;
                    parsed.arp.duplicate_frame = it->second.second;
                }
            }
            else
            {
                arp_cache_[parsed.arp.sender_ip] = 
                    std::make_pair(sender_mac_as_uint, parsed.frame_metadata.frame_number);
            }
        }

        // ==================== IPv4 Parsing ====================
        bool PacketParser::parseIPv4(const uint8_t *data, size_t length, 
                                    ParsedPacket &parsed, size_t &offset)
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

            // Extract DSCP and ECN from ToS
            extractDSCPandECN(parsed.ipv4.tos, parsed.ipv4.dscp, parsed.ipv4.ecn);

            // Extract flags and fragment offset
            extractIPv4Flags(ip_header, parsed.ipv4);

            parsed.ip_protocol = ip_header->protocol;
            parsed.is_fragmented = parsed.ipv4.is_fragmented;

            // Calculate IP header length
            size_t ip_header_len = ip_header->ihl * 4;
            
            // Parse IPv4 options if present
            if (ip_header_len > sizeof(struct iphdr))
            {
                parsed.ipv4.has_options = true;
                size_t options_offset = offset + sizeof(struct iphdr);
                size_t options_len = ip_header_len - sizeof(struct iphdr);
                parseIPv4Options(data + options_offset, options_len, parsed.ipv4);
            }
            
            // Verify IPv4 checksum
            parsed.ipv4.checksum_calculated = calculateIPv4Checksum(ip_header);
            parsed.ipv4.checksum_valid = (parsed.ipv4.checksum_calculated == 0);

            offset += ip_header_len;

            return true;
        }

        void PacketParser::extractDSCPandECN(uint8_t tos, uint8_t &dscp, uint8_t &ecn)
        {
            dscp = (tos >> 2) & 0x3F;  // Upper 6 bits
            ecn = tos & 0x03;           // Lower 2 bits
        }

        void PacketParser::parseIPv4Options(const uint8_t *data, size_t length, IPv4Header &ipv4)
        {
            size_t offset = 0;
            
            while (offset < length)
            {
                IPv4Option option;
                option.type = data[offset];
                
                // End of options
                if (option.type == 0)
                {
                    option.is_end_of_options = true;
                    ipv4.options.push_back(option);
                    break;
                }
                
                // NOP
                if (option.type ==                 1)
                {
                    option.is_nop = true;
                    option.length = 1;
                    ipv4.options.push_back(option);
                    offset += 1;
                    continue;
                }
                
                // Other options have length field
                if (offset + 1 >= length)
                {
                    break;
                }
                
                option.length = data[offset + 1];
                
                if (option.length < 2 || offset + option.length > length)
                {
                    break;
                }
                
                // Copy option data
                if (option.length > 2)
                {
                    option.data.assign(data + offset + 2, data + offset + option.length);
                }
                
                // Identify common option types
                switch (option.type)
                {
                    case 7:
                        option.is_record_route = true;
                        break;
                    case 68:
                        option.is_timestamp = true;
                        break;
                    case 130:
                        option.is_security = true;
                        break;
                    case 131:
                        option.is_loose_source_route = true;
                        break;
                    case 137:
                        option.is_strict_source_route = true;
                        break;
                }
                
                ipv4.options.push_back(option);
                offset += option.length;
            }
        }

        // ==================== IPv6 Parsing ====================
        bool PacketParser::parseIPv6(const uint8_t *data, size_t length, 
                                    ParsedPacket &parsed, size_t &offset)
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

            // Extract DSCP and ECN from traffic class
            extractDSCPandECN(parsed.ipv6.traffic_class, parsed.ipv6.dscp, parsed.ipv6.ecn);

            parsed.ip_protocol = parsed.ipv6.next_header;

            offset += sizeof(struct ip6_hdr);
            
            // Parse IPv6 extension headers if present
            parseIPv6ExtensionHeaders(data, length, parsed, offset);

            return true;
        }

        bool PacketParser::parseIPv6ExtensionHeaders(const uint8_t *data, size_t length,
                                                     ParsedPacket &parsed, size_t &offset)
        {
            uint8_t next_header = parsed.ipv6.next_header;
            
            while (true)
            {
                // Check if this is an extension header
                switch (next_header)
                {
                    case 0: // Hop-by-Hop Options
                    {
                        if (offset + 2 > length) return false;
                        
                        IPv6HopByHopOptions hop_opt;
                        hop_opt.next_header = data[offset];
                        hop_opt.length = data[offset + 1];
                        
                        size_t ext_len = (hop_opt.length + 1) * 8;
                        if (offset + ext_len > length) return false;
                        
                        hop_opt.options.assign(data + offset + 2, data + offset + ext_len);
                        parsed.ipv6.hop_by_hop = hop_opt;
                        parsed.ipv6.has_extension_headers = true;
                        
                        next_header = hop_opt.next_header;
                        offset += ext_len;
                        break;
                    }
                    
                    case 43: // Routing Header
                    {
                        if (offset + 4 > length) return false;
                        
                        IPv6RoutingHeader routing;
                        routing.next_header = data[offset];
                        routing.length = data[offset + 1];
                        routing.type = data[offset + 2];
                        routing.segments_left = data[offset + 3];
                        
                        size_t ext_len = (routing.length + 1) * 8;
                        if (offset + ext_len > length) return false;
                        
                        routing.addresses.assign(data + offset + 4, data + offset + ext_len);
                        parsed.ipv6.routing = routing;
                        parsed.ipv6.has_extension_headers = true;
                        
                        next_header = routing.next_header;
                        offset += ext_len;
                        break;
                    }
                    
                    case 44: // Fragment Header
                    {
                        if (offset + 8 > length) return false;
                        
                        IPv6FragmentHeader fragment;
                        fragment.next_header = data[offset];
                        fragment.reserved = data[offset + 1];
                        
                        uint16_t offset_and_flags = ntohs(*reinterpret_cast<const uint16_t*>(data + offset + 2));
                        fragment.offset = (offset_and_flags >> 3) & 0x1FFF;
                        fragment.more_fragments = (offset_and_flags & 0x0001) != 0;
                        
                        fragment.identification = ntohl(*reinterpret_cast<const uint32_t*>(data + offset + 4));
                        
                        parsed.ipv6.fragment = fragment;
                        parsed.ipv6.has_extension_headers = true;
                        parsed.is_fragmented = true;
                        
                        next_header = fragment.next_header;
                        offset += 8;
                        break;
                    }
                    
                    case 60: // Destination Options
                    {
                        if (offset + 2 > length) return false;
                        
                        IPv6DestinationOptions dest_opt;
                        dest_opt.next_header = data[offset];
                        dest_opt.length = data[offset + 1];
                        
                        size_t ext_len = (dest_opt.length + 1) * 8;
                        if (offset + ext_len > length) return false;
                        
                        dest_opt.options.assign(data + offset + 2, data + offset + ext_len);
                        parsed.ipv6.destination = dest_opt;
                        parsed.ipv6.has_extension_headers = true;
                        
                        next_header = dest_opt.next_header;
                        offset += ext_len;
                        break;
                    }
                    
                    case 51: // Authentication Header
                    {
                        if (offset + 8 > length) return false;
                        
                        IPv6AuthenticationHeader auth;
                        auth.next_header = data[offset];
                        auth.length = data[offset + 1];
                        auth.reserved = ntohs(*reinterpret_cast<const uint16_t*>(data + offset + 2));
                        auth.spi = ntohl(*reinterpret_cast<const uint32_t*>(data + offset + 4));
                        auth.sequence = ntohl(*reinterpret_cast<const uint32_t*>(data + offset + 8));
                        
                        parsed.ipv6.authentication = auth;
                        parsed.ipv6.has_extension_headers = true;
                        
                        size_t ext_len = (auth.length + 2) * 4;
                        next_header = auth.next_header;
                        offset += ext_len;
                        break;
                    }
                    
                    default:
                        // Not an extension header, update protocol and return
                        parsed.ip_protocol = next_header;
                        return true;
                }
            }
            
            return true;
        }

        // ==================== TCP Parsing ====================
        bool PacketParser::parseTCP(const uint8_t *data, size_t length, 
                                   ParsedPacket &parsed, size_t &offset)
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
                std::memcpy(parsed.tcp.options, data + offset + sizeof(struct tcphdr), 
                           parsed.tcp.options_length);
                
                // Parse TCP options in detail
                parseTCPOptions(parsed.tcp.options, parsed.tcp.options_length, parsed.tcp);
            }
            
            // Calculate payload length
            parsed.tcp.payload_length = length - offset - tcp_header_len;
            parsed.tcp.segment_data_length = parsed.tcp.payload_length;
            
            // Verify TCP checksum
            parsed.tcp.checksum_calculated = calculateTCPChecksum(parsed, data + offset, 
                                                                  tcp_header_len + parsed.tcp.payload_length);
            parsed.tcp.checksum_valid = (parsed.tcp.checksum_calculated == 0);
            
            // Calculate scaled window size
            if (parsed.tcp.opt_window_scale.has_value())
            {
                parsed.tcp.calculated_window_size = 
                    parsed.tcp.window_size << parsed.tcp.opt_window_scale->shift_count;
            }
            else
            {
                parsed.tcp.calculated_window_size = parsed.tcp.window_size;
            }

            offset += tcp_header_len;
            
            // Analyze TCP stream
            analyzeTCPStream(parsed);

            return true;
        }

        void PacketParser::parseTCPOptions(const uint8_t *options_data, size_t options_len, 
                                          TCPHeader &tcp)
        {
            size_t offset = 0;
            
            while (offset < options_len)
            {
                uint8_t kind = options_data[offset];
                
                // End of options
                if (kind == 0)
                {
                    break;
                }
                
                // NOP
                if (kind == 1)
                {
                    offset++;
                    continue;
                }
                
                // Other options have length field
                if (offset + 1 >= options_len)
                {
                    break;
                }
                
                uint8_t length = options_data[offset + 1];
                
                if (length < 2 || offset + length > options_len)
                {
                    break;
                }
                
                switch (kind)
                {
                    case 2: // MSS (Maximum Segment Size)
                    {
                        if (length == 4)
                        {
                            TCPOptionMSS mss;
                            mss.value = ntohs(*reinterpret_cast<const uint16_t*>(options_data + offset + 2));
                            tcp.opt_mss = mss;
                        }
                        break;
                    }
                    
                    case 3: // Window Scale
                    {
                        if (length == 3)
                        {
                            TCPOptionWindowScale wscale;
                            wscale.shift_count = options_data[offset + 2];
                            wscale.multiplier = 1 << wscale.shift_count;
                            tcp.opt_window_scale = wscale;
                        }
                        break;
                    }
                    
                    case 4: // SACK Permitted
                    {
                        if (length == 2)
                        {
                            if (!tcp.opt_sack.has_value())
                            {
                                tcp.opt_sack = TCPOptionSACK();
                            }
                            tcp.opt_sack->permitted = true;
                        }
                        break;
                    }
                    
                    case 5: // SACK
                    {
                        if (length >= 10 && (length - 2) % 8 == 0)
                        {
                            if (!tcp.opt_sack.has_value())
                            {
                                tcp.opt_sack = TCPOptionSACK();
                            }
                            
                            size_t num_blocks = (length - 2) / 8;
                            for (size_t i = 0; i < num_blocks; i++)
                            {
                                TCPOptionSACK::SACKBlock block;
                                block.left_edge = ntohl(*reinterpret_cast<const uint32_t*>(
                                    options_data + offset + 2 + i * 8));
                                block.right_edge = ntohl(*reinterpret_cast<const uint32_t*>(
                                    options_data + offset + 6 + i * 8));
                                tcp.opt_sack->blocks.push_back(block);
                            }
                        }
                        break;
                    }
                    
                    case 8: // Timestamp
                    {
                        if (length == 10)
                        {
                            TCPOptionTimestamp ts;
                            ts.tsval = ntohl(*reinterpret_cast<const uint32_t*>(options_data + offset + 2));
                            ts.tsecr = ntohl(*reinterpret_cast<const uint32_t*>(options_data + offset + 6));
                            tcp.opt_timestamp = ts;
                        }
                        break;
                    }
                }
                
                offset += length;
            }
        }

        void PacketParser::analyzeTCPStream(ParsedPacket &parsed)
        {
            std::string flow_key = getTCPFlowKey(parsed);
            
            // Get or create stream info
            if (tcp_streams_.find(flow_key) == tcp_streams_.end())
            {
                TCPStreamInfo stream;
                stream.stream_index = next_tcp_stream_id_++;
                stream.first_seen_time = parsed.timestamp;
                stream.last_seen_time = parsed.timestamp;
                stream.dup_ack_count = 0;
                stream.last_ack = 0;
                stream.window_scale_factor = 1;
                stream.window_scale_set = false;
                stream.bytes_in_flight = 0;
                tcp_streams_[flow_key] = stream;
            }
            
            TCPStreamInfo &stream = tcp_streams_[flow_key];
            parsed.tcp.analysis.stream_index = stream.stream_index;
            
            // Calculate time relative and delta
            parsed.tcp.analysis.time_relative = 
                (parsed.timestamp - stream.first_seen_time) / 1000000.0;
            parsed.tcp.analysis.time_delta = 
                (parsed.timestamp - stream.last_seen_time) / 1000000.0;
            stream.last_seen_time = parsed.timestamp;
            
            // Calculate next sequence number
            uint32_t payload_len = parsed.tcp.payload_length;
            if (parsed.tcp.flag_syn || parsed.tcp.flag_fin)
            {
                payload_len += 1; // SYN/FIN consume 1 sequence number
            }
            parsed.tcp.analysis.next_seq = parsed.tcp.seq_number + payload_len;
            
            // Store window scale factor from SYN packet
            if (parsed.tcp.flag_syn && parsed.tcp.opt_window_scale.has_value())
            {
                stream.window_scale_factor = parsed.tcp.opt_window_scale->multiplier;
                stream.window_scale_set = true;
            }
            
            // Retransmission detection
            detectTCPRetransmission(parsed, stream);
            
            // Duplicate ACK detection
            detectTCPDuplicateACK(parsed, stream);
            
            // Zero window detection
            if (parsed.tcp.window_size == 0)
            {
                parsed.tcp.analysis.is_zero_window = true;
            }
            
            // Zero window probe detection (1 byte payload with zero window)
            if (parsed.tcp.payload_length == 1 && stream.bytes_in_flight == 0)
            {
                parsed.tcp.analysis.is_zero_window_probe = true;
            }
            
            // Keep-alive detection (empty or 1 byte with seq = last_seq - 1)
            if (parsed.tcp.payload_length <= 1 && stream.next_seq > 0 &&
                parsed.tcp.seq_number == stream.next_seq - 1)
            {
                parsed.tcp.analysis.is_keep_alive = true;
            }
            
            // Window update detection (ACK with no data but window size changed)
            if (parsed.tcp.flag_ack && parsed.tcp.payload_length == 0 && 
                parsed.tcp.window_size != stream.last_ack)
            {
                parsed.tcp.analysis.is_window_update = true;
            }
            
            // Calculate bytes in flight
            calculateTCPBytesInFlight(parsed, stream);
            
            // Update stream state
            stream.next_seq = parsed.tcp.analysis.next_seq;
        }

        std::string PacketParser::getTCPFlowKey(const ParsedPacket &parsed)
        {
            std::stringstream ss;
            
            // Create bidirectional flow key
            uint32_t ip1, ip2;
            uint16_t port1, port2;
            
            if (parsed.has_ipv4)
            {
                ip1 = parsed.ipv4.src_ip;
                ip2 = parsed.ipv4.dst_ip;
            }
            else
            {
                // For IPv6, use hash of addresses
                ip1 = *reinterpret_cast<const uint32_t*>(parsed.ipv6.src_ip);
                ip2 = *reinterpret_cast<const uint32_t*>(parsed.ipv6.dst_ip);
            }
            
            port1 = parsed.tcp.src_port;
            port2 = parsed.tcp.dst_port;
            
            // Normalize (smaller IP/port first)
            if (ip1 > ip2 || (ip1 == ip2 && port1 > port2))
            {
                std::swap(ip1, ip2);
                std::swap(port1, port2);
            }
            
            ss << ip1 << ":" << port1 << "-" << ip2 << ":" << port2;
            return ss.str();
        }

        void PacketParser::detectTCPRetransmission(ParsedPacket &parsed, TCPStreamInfo &stream)
        {
            // Check if this sequence number was seen before
            if (parsed.tcp.payload_length > 0)
            {
                if (stream.seen_seq_numbers.count(parsed.tcp.seq_number) > 0)
                {
                    parsed.tcp.analysis.is_retransmission = true;
                    
                    // Check if it's fast retransmission (after 3 dup ACKs)
                    if (stream.dup_ack_count >= 3)
                    {
                        parsed.tcp.analysis.is_fast_retransmission = true;
                    }
                }
                else
                {
                    stream.seen_seq_numbers.insert(parsed.tcp.seq_number);
                    stream.seq_to_frame[parsed.tcp.seq_number] = parsed.frame_metadata.frame_number;
                }
            }
            
            // Out-of-order detection
            if (stream.next_seq > 0 && parsed.tcp.seq_number > stream.next_seq)
            {
                parsed.tcp.analysis.is_out_of_order = true;
            }
            
            // Lost segment detection
            if (stream.next_seq > 0 && parsed.tcp.seq_number < stream.next_seq &&
                !parsed.tcp.analysis.is_retransmission)
            {
                parsed.tcp.analysis.is_lost_segment = true;
            }
        }

        void PacketParser::detectTCPDuplicateACK(ParsedPacket &parsed, TCPStreamInfo &stream)
        {
            if (parsed.tcp.flag_ack)
            {
                if (parsed.tcp.ack_number == stream.last_ack && parsed.tcp.payload_length == 0)
                {
                    stream.dup_ack_count++;
                    parsed.tcp.analysis.is_dup_ack = true;
                    parsed.tcp.analysis.dup_ack_num = stream.dup_ack_count;
                }
                else
                {
                    stream.dup_ack_count = 0;
                    stream.last_ack = parsed.tcp.ack_number;
                }
            }
        }

        void PacketParser::calculateTCPBytesInFlight(ParsedPacket &parsed, TCPStreamInfo &stream)
        {
            // Simplified calculation: bytes sent but not yet acknowledged
            if (parsed.tcp.payload_length > 0)
            {
                stream.bytes_in_flight += parsed.tcp.payload_length;
            }
            
            if (parsed.tcp.flag_ack && stream.bytes_in_flight > 0)
            {
                // Reduce bytes in flight based on ACK
                // This is simplified; real implementation would track per-segment
                if (stream.bytes_in_flight >= parsed.tcp.payload_length)
                {
                    stream.bytes_in_flight -= parsed.tcp.payload_length;
                }
            }
            
            parsed.tcp.analysis.bytes_in_flight = stream.bytes_in_flight;
        }

        // ==================== UDP Parsing ====================
        bool PacketParser::parseUDP(const uint8_t *data, size_t length, 
                                   ParsedPacket &parsed, size_t &offset)
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
            
            // Calculate payload length
            parsed.udp.payload_length = parsed.udp.length - sizeof(struct udphdr);
            
            // Verify UDP checksum
            parsed.udp.checksum_calculated = calculateUDPChecksum(parsed, data + offset, 
                                                                  parsed.udp.length);
            parsed.udp.checksum_valid = (parsed.udp.checksum_calculated == 0 || 
                                        parsed.udp.checksum == 0); // 0 means checksum disabled

            offset += sizeof(struct udphdr);
            
            // Analyze UDP stream
            analyzeUDPStream(parsed);

            return true;
        }

        void PacketParser::analyzeUDPStream(ParsedPacket &parsed)
        {
            std::string flow_key = getUDPFlowKey(parsed);
            
            if (udp_streams_.find(flow_key) == udp_streams_.end())
            {
                udp_streams_[flow_key] = next_udp_stream_id_++;
            }
            
            parsed.udp.stream_index = udp_streams_[flow_key];
        }

        std::string PacketParser::getUDPFlowKey(const ParsedPacket &parsed)
        {
            std::stringstream ss;
            
            uint32_t ip1, ip2;
            uint16_t port1, port2;
            
            if (parsed.has_ipv4)
            {
                ip1 = parsed.ipv4.src_ip;
                ip2 = parsed.ipv4.dst_ip;
            }
            else
            {
                ip1 = *reinterpret_cast<const uint32_t*>(parsed.ipv6.src_ip);
                ip2 = *reinterpret_cast<const uint32_t*>(parsed.ipv6.dst_ip);
            }
            
            port1 = parsed.udp.src_port;
            port2 = parsed.udp.dst_port;
            
            if (ip1 > ip2 || (ip1 == ip2 && port1 > port2))
            {
                std::swap(ip1, ip2);
                std::swap(port1, port2);
            }
            
            ss << ip1 << ":" << port1 << "-" << ip2 << ":" << port2;
            return ss.str();
        }

        // ==================== ICMP Parsing ====================
        bool PacketParser::parseICMP(const uint8_t *data, size_t length, 
                                    ParsedPacket &parsed, size_t &offset)
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
            else if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_FRAG_NEEDED)
            {
                parsed.icmp.mtu = ntohs(icmp_header->un.frag.mtu);
            }
            else if (icmp_header->type == ICMP_REDIRECT)
            {
                parsed.icmp.gateway = icmp_header->un.gateway;
            }
            
            // Verify ICMP checksum
            size_t icmp_len = length - offset;
            parsed.icmp.checksum_calculated = calculateICMPChecksum(data + offset, icmp_len);
            parsed.icmp.checksum_valid = (parsed.icmp.checksum_calculated == 0);
            
            // Set data pointer (for error messages)
            if (icmp_len > sizeof(struct icmphdr))
            {
                parsed.icmp.data = data + offset + sizeof(struct icmphdr);
                parsed.icmp.data_length = icmp_len - sizeof(struct icmphdr);
            }

            offset += sizeof(struct icmphdr);
            
            // Analyze ICMP response
            analyzeICMPResponse(parsed);

            return true;
        }

        void PacketParser::analyzeICMPResponse(ParsedPacket &parsed)
        {
            if (parsed.icmp.type == ICMP_ECHOREPLY)
            {
                // Try to find matching request
                auto key = std::make_tuple(
                    parsed.ipv4.dst_ip,  // Original source
                    parsed.ipv4.src_ip,  // Original destination
                    parsed.icmp.identifier,
                    parsed.icmp.sequence
                );
                
                auto it = icmp_echo_requests_.find(key);
                if (it != icmp_echo_requests_.end())
                {
                    parsed.icmp.is_response_to = true;
                    parsed.icmp.response_frame = it->second.frame_number;
                    parsed.icmp.response_time = 
                        (parsed.timestamp - it->second.timestamp) / 1000000.0; // Convert to seconds
                    
                    // Remove from map
                    icmp_echo_requests_.erase(it);
                }
            }
            else if (parsed.icmp.type == ICMP_ECHO)
            {
                // Store request for later matching
                auto key = std::make_tuple(
                    parsed.ipv4.src_ip,
                    parsed.ipv4.dst_ip,
                    parsed.icmp.identifier,
                    parsed.icmp.sequence
                );
                
                ICMPEchoInfo info;
                info.timestamp = parsed.timestamp;
                info.frame_number = parsed.frame_metadata.frame_number;
                icmp_echo_requests_[key] = info;
            }
        }

        // ==================== ICMPv6 Parsing ====================
        bool PacketParser::parseICMPv6(const uint8_t *data, size_t length, 
                                      ParsedPacket &parsed, size_t &offset)
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
            parsed.icmpv6.reserved = ntohl(icmp6_header->icmp6_dataun.icmp6_un_data32[0]);
            
            // For echo request/reply
            if (parsed.icmpv6.type == 128 || parsed.icmpv6.type == 129)
            {
                parsed.icmpv6.identifier = ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[0]);
                parsed.icmpv6.sequence = ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[1]);
            }
            
            // Note: ICMPv6 checksum verification requires pseudo-header calculation
            // which is more complex for IPv6

            offset += sizeof(struct icmp6_hdr);

            return true;
        }

        // ==================== Checksum Calculation ====================
        uint16_t PacketParser::calculateIPv4Checksum(const struct iphdr *ip_header)
        {
            uint32_t sum = 0;
            const uint16_t *ptr = reinterpret_cast<const uint16_t*>(ip_header);
            size_t len = ip_header->ihl * 4;
            
            for (size_t i = 0; i < len / 2; i++)
            {
                sum += ptr[i];
            }
            
            // Add carry
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            return ~sum;
        }

        uint16_t PacketParser::calculateTCPChecksum(const ParsedPacket &parsed,
                                                    const uint8_t *tcp_data, size_t tcp_len)
        {
            uint32_t sum = 0;
            
            // Pseudo header for IPv4
            if (parsed.has_ipv4)
            {
                sum += (parsed.ipv4.src_ip >> 16) & 0xFFFF;
                sum += parsed.ipv4.src_ip & 0xFFFF;
                sum += (parsed.ipv4.dst_ip >> 16) & 0xFFFF;
                sum += parsed.ipv4.dst_ip & 0xFFFF;
                sum += htons(IPPROTO_TCP);
                sum += htons(tcp_len);
            }
            else if (parsed.has_ipv6)
            {
                // IPv6 pseudo header
                const uint16_t *src = reinterpret_cast<const uint16_t*>(parsed.ipv6.src_ip);
                const uint16_t *dst = reinterpret_cast<const uint16_t*>(parsed.ipv6.dst_ip);
                
                for (int i = 0; i < 8; i++)
                {
                    sum += src[i];
                    sum += dst[i];
                }
                
                sum += htons(tcp_len);
                sum += htons(IPPROTO_TCP);
            }
            
            // TCP header and data
            const uint16_t *ptr = reinterpret_cast<const uint16_t*>(tcp_data);
            for (size_t i = 0; i < tcp_len / 2; i++)
            {
                sum += ptr[i];
            }
            
            // Handle odd length
            if (tcp_len % 2 == 1)
            {
                sum += tcp_data[tcp_len - 1] << 8;
            }
            
            // Add carry
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            return ~sum;
        }

        uint16_t PacketParser::calculateUDPChecksum(const ParsedPacket &parsed,
                                                    const uint8_t *udp_data, size_t udp_len)
        {
            uint32_t sum = 0;
            
            // Pseudo header for IPv4
            if (parsed.has_ipv4)
            {
                sum += (parsed.ipv4.src_ip >> 16) & 0xFFFF;
                sum += parsed.ipv4.src_ip & 0xFFFF;
                sum += (parsed.ipv4.dst_ip >> 16) & 0xFFFF;
                sum += parsed.ipv4.dst_ip & 0xFFFF;
                sum += htons(IPPROTO_UDP);
                sum += htons(udp_len);
            }
            else if (parsed.has_ipv6)
            {
                const uint16_t *src = reinterpret_cast<const uint16_t*>(parsed.ipv6.src_ip);
                const uint16_t *dst = reinterpret_cast<const uint16_t*>(parsed.ipv6.dst_ip);
                
                for (int i = 0; i < 8; i++)
                {
                    sum += src[i];
                    sum += dst[i];
                }
                
                sum += htons(udp_len);
                sum += htons(IPPROTO_UDP);
            }
            
            // UDP header and data
            const uint16_t *ptr = reinterpret_cast<const uint16_t*>(udp_data);
            for (size_t i = 0; i < udp_len / 2; i++)
            {
                sum += ptr[i];
            }
            
            if (udp_len % 2 == 1)
            {
                sum += udp_data[udp_len - 1] << 8;
            }
            
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            return ~sum;
        }

        uint16_t PacketParser::calculateICMPChecksum(const uint8_t *icmp_DATA, size_t icmp_len)
        {
            uint32_t sum = 0;
            const uint16_t *ptr = reinterpret_cast<const uint16_t*>(icmp_DATA);
            
            for (size_t i = 0; i < icmp_len / 2; i++)
            {
                sum += ptr[i];
            }
            
            if (icmp_len % 2 == 1)
            {
                sum += icmp_DATA[icmp_len - 1] << 8;
            }
            
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            return ~sum;
        }

        // ==================== Application Protocol Detection ====================
        AppProtocol PacketParser::detectApplicationProtocol(const ParsedPacket &parsed)
        {
            if (parsed.has_tcp)
            {
                uint16_t port = std::min(parsed.tcp.src_port, parsed.tcp.dst_port);
                
                switch (port)
                {
                    case 80:
                    case 8080:
                    case 8000:
                        return AppProtocol::HTTP;
                    case 443:
                    case 8443:
                        // parsed.is_encrypted = true;
                        return AppProtocol::HTTPS;
                    case 22:
                        // parsed.is_encrypted = true;
                        return AppProtocol::SSH;
                    case 21:
                        return AppProtocol::FTP;
                    case 20:
                        return AppProtocol::FTP_DATA;
                    case 25:
                    case 587:
                        return AppProtocol::SMTP;
                    case 110:
                        return AppProtocol::POP3;
                    case 143:
                    case 993:
                        return AppProtocol::IMAP;
                    case 23:
                        return AppProtocol::TELNET;
                    case 3389:
                        return AppProtocol::RDP;
                    case 445:
                    case 139:
                        return AppProtocol::SMB;
                    case 3306:
                        return AppProtocol::MYSQL;
                    case 5432:
                        return AppProtocol::POSTGRESQL;
                    case 6379:
                        return AppProtocol::REDIS;
                    case 27017:
                        return AppProtocol::MONGODB;
                }
            }
            else if (parsed.has_udp)
            {
                uint16_t port = std::min(parsed.udp.src_port, parsed.udp.dst_port);
                
                switch (port)
                {
                    case 53:
                        return AppProtocol::DNS;
                    case 67:
                    case 68:
                        return AppProtocol::DHCP;
                    case 123:
                        return AppProtocol::NTP;
                    case 161:
                    case 162:
                        return AppProtocol::SNMP;
                }
            }
            
            return AppProtocol::UNKNOWN;
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
                // Allow unknown types but validate they're in valid range
                return eth_type >= 0x0600 || eth_type <= 0x05DC;
            }
        }

        bool PacketParser::validateIPv4(const struct iphdr *ip_header, size_t length)
        {
            if (!ip_header || length < sizeof(struct iphdr))
            {
                return false;
            }

            // Check version
            if (ip_header->version != 4)
            {
                return false;
            }

            // Check header length
            if (ip_header->ihl < 5)
            {
                return false;
            }

            size_t header_len = ip_header->ihl * 4;
            if (header_len > length)
            {
                return false;
            }

            // Check total length
            uint16_t total_len = ntohs(ip_header->tot_len);
            if (total_len < header_len || total_len > length)
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

            // Check version
            uint32_t vtf = ntohl(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow);
            uint8_t version = (vtf >> 28) & 0x0F;
            if (version != 6)
            {
                return false;
            }

            // Check payload length
            uint16_t payload_len = ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
            if (sizeof(struct ip6_hdr) + payload_len > length)
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

            // Check data offset
            if (tcp_header->doff < 5)
            {
                return false;
            }

            size_t header_len = tcp_header->doff * 4;
            if (header_len > length)
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

            // Check UDP length
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

            // Basic validation - ICMP types range from 0-255
            return true;
        }

        // ==================== Helper Functions ====================
        void PacketParser::extractTCPFlags(const struct tcphdr *tcp_header, TCPHeader &tcp)
        {
            tcp.flags = 0;
            
            tcp.flag_fin = tcp_header->fin;
            tcp.flag_syn = tcp_header->syn;
            tcp.flag_rst = tcp_header->rst;
            tcp.flag_psh = tcp_header->psh;
            tcp.flag_ack = tcp_header->ack;
            tcp.flag_urg = tcp_header->urg;

            const uint8_t *tcp_bytes = reinterpret_cast<const uint8_t*>(tcp_header);
            uint8_t flags_byte = tcp_bytes[13]; 
            
            tcp.flag_ece = (flags_byte & 0x40) != 0; 
            tcp.flag_cwr = (flags_byte & 0x80) != 0; 
    
            
            if (tcp.flag_fin) tcp.flags |= 0x01;
            if (tcp.flag_syn) tcp.flags |= 0x02;
            if (tcp.flag_rst) tcp.flags |= 0x04;
            if (tcp.flag_psh) tcp.flags |= 0x08;
            if (tcp.flag_ack) tcp.flags |= 0x10;
            if (tcp.flag_urg) tcp.flags |= 0x20;
            if (tcp.flag_ece) tcp.flags |= 0x40;
            if (tcp.flag_cwr) tcp.flags |= 0x80;
        }

        void PacketParser::extractIPv4Flags(const struct iphdr *ip_header, IPv4Header &ipv4)
        {
            uint16_t frag_off = ntohs(ip_header->frag_off);
            
            ipv4.flag_reserved = (frag_off & 0x8000) != 0;
            ipv4.flag_df = (frag_off & 0x4000) != 0;
            ipv4.flag_mf = (frag_off & 0x2000) != 0;
            
            ipv4.dont_fragment = ipv4.flag_df;
            ipv4.more_fragments = ipv4.flag_mf;
            
            ipv4.fragment_offset = frag_off & 0x1FFF;
            ipv4.is_fragmented = (ipv4.fragment_offset != 0 || ipv4.more_fragments);
            
            ipv4.flags = 0;
            if (ipv4.flag_reserved) ipv4.flags |= 0x04;
            if (ipv4.flag_df) ipv4.flags |= 0x02;
            if (ipv4.flag_mf) ipv4.flags |= 0x01;
        }

        void PacketParser::copyQuickAccessFields(ParsedPacket &parsed)
        {
            // Copy Ethernet
            if (parsed.has_ethernet)
            {
                std::memcpy(parsed.src_mac, parsed.ethernet.src_mac, 6);
                std::memcpy(parsed.dst_mac, parsed.ethernet.dst_mac, 6);
                parsed.eth_type = ntohs(parsed.ethernet.ether_type);
            }
            
            // Copy IP
            if (parsed.has_ipv4)
            {
                parsed.src_ip = parsed.ipv4.src_ip;
                parsed.dst_ip = parsed.ipv4.dst_ip;
                parsed.ip_ttl = parsed.ipv4.ttl;
                parsed.ip_version = 4;
            }
            else if (parsed.has_ipv6)
            {
                parsed.ip_version = 6;
                parsed.ip_ttl = parsed.ipv6.hop_limit;
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

        void PacketParser::buildProtocolString(ParsedPacket &parsed)
        {
            std::vector<std::string> protocols;
            
            if (parsed.has_ethernet)
            {
                protocols.push_back("eth");
                
                uint16_t eth_type = ntohs(parsed.ethernet.ether_type);
                if (eth_type == ETH_P_IP || eth_type == ETH_P_IPV6 || eth_type == ETH_P_ARP)
                {
                    protocols.push_back("ethertype");
                }
            }
            
            if (parsed.has_arp)
            {
                protocols.push_back("arp");
            }
            else if (parsed.has_ipv4)
            {
                protocols.push_back("ip");
                
                if (parsed.has_tcp)
                {
                    protocols.push_back("tcp");
                }
                else if (parsed.has_udp)
                {
                    protocols.push_back("udp");
                }
                else if (parsed.has_icmp)
                {
                    protocols.push_back("icmp");
                }
            }
            else if (parsed.has_ipv6)
            {
                protocols.push_back("ipv6");
                
                if (parsed.has_tcp)
                {
                    protocols.push_back("tcp");
                }
                else if (parsed.has_udp)
                {
                    protocols.push_back("udp");
                }
                else if (parsed.has_icmpv6)
                {
                    protocols.push_back("icmpv6");
                }
            }
            
            // Add application protocol
            if (parsed.app_protocol != AppProtocol::UNKNOWN)
            {
                protocols.push_back(getAppProtocolName(parsed.app_protocol));
            }
            
            parsed.frame_metadata.frame_protocols = Utils::join(protocols, ":");
        }

        // ==================== Utility Functions - Conversion ====================
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

        std::string PacketParser::getAppProtocolName(AppProtocol proto)
        {
            switch (proto)
            {
            case AppProtocol::HTTP:
                return "http";
            case AppProtocol::HTTPS:
                return "https";
            case AppProtocol::DNS:
                return "dns";
            case AppProtocol::SSH:
                return "ssh";
            case AppProtocol::FTP:
                return "ftp";
            case AppProtocol::FTP_DATA:
                return "ftp-data";
            case AppProtocol::SMTP:
                return "smtp";
            case AppProtocol::POP3:
                return "pop3";
            case AppProtocol::IMAP:
                return "imap";
            case AppProtocol::TELNET:
                return "telnet";
            case AppProtocol::DHCP:
                return "dhcp";
            case AppProtocol::NTP:
                return "ntp";
            case AppProtocol::SNMP:
                return "snmp";
            case AppProtocol::SMB:
                return "smb";
            case AppProtocol::RDP:
                return "rdp";
            case AppProtocol::MYSQL:
                return "mysql";
            case AppProtocol::POSTGRESQL:
                return "postgresql";
            case AppProtocol::REDIS:
                return "redis";
            case AppProtocol::MONGODB:
                return "mongodb";
            default:
                return "unknown";
            }
        }

        std::string PacketParser::getPacketSummary(const ParsedPacket &packet)
        {
            std::stringstream ss;

            ss << "Frame " << packet.frame_metadata.frame_number << ": ";
            ss << packet.packet_size << " bytes on wire, ";
            ss << packet.captured_length << " bytes captured";
            
            if (packet.frame_metadata.frame_time_relative > 0)
            {
                ss << " [" << std::fixed << std::setprecision(6) 
                   << packet.frame_metadata.frame_time_relative << "s]";
            }
            
            ss << "\n";
            ss << "[Protocols in frame: " << packet.frame_metadata.frame_protocols << "]\n";

            // Ethernet layer
            if (packet.has_ethernet)
            {
                ss << "Ethernet II, Src: " << macToString(packet.ethernet.src_mac)
                   << ", Dst: " << macToString(packet.ethernet.dst_mac) << "\n";
                
                if (packet.ethernet.has_vlan)
                {
                    ss << "  802.1Q VLAN, ID: " << packet.ethernet.vlan_id 
                       << ", Priority: " << static_cast<int>(packet.ethernet.vlan_priority) << "\n";
                }
            }

            // ARP
            if (packet.has_arp)
            {
                ss << arpOpcodeToString(packet.arp.opcode) << ", ";
                ss << "Sender IP: " << ipv4ToString(packet.arp.sender_ip) << ", ";
                ss << "Target IP: " << ipv4ToString(packet.arp.target_ip);
                
                if (packet.arp.is_gratuitous)
                {
                    ss << " [Gratuitous ARP]";
                }
                if (packet.arp.is_probe)
                {
                    ss << " [ARP Probe]";
                }
            }
            // IPv4
            else if (packet.has_ipv4)
            {
                ss << "Internet Protocol Version 4, Src: " << ipv4ToString(packet.ipv4.src_ip)
                   << ", Dst: " << ipv4ToString(packet.ipv4.dst_ip) << "\n";
                ss << "  Protocol: " << protocolToString(packet.ipv4.protocol)
                   << ", TTL: " << static_cast<int>(packet.ipv4.ttl)
                   << ", Length: " << packet.ipv4.total_length;
                
                if (packet.ipv4.is_fragmented)
                {
                    ss << " [Fragmented]";
                }
                if (!packet.ipv4.checksum_valid)
                {
                    ss << " [Checksum incorrect]";
                }
                ss << "\n";

                // TCP
                if (packet.has_tcp)
                {
                    ss << "Transmission Control Protocol, Src Port: " << packet.tcp.src_port
                       << ", Dst Port: " << packet.tcp.dst_port << "\n";
                    ss << "  [Stream index: " << packet.tcp.analysis.stream_index << "]\n";
                    ss << "  Seq: " << packet.tcp.seq_number
                       << ", Ack: " << packet.tcp.ack_number << "\n";
                    ss << "  Flags: " << tcpFlagsToString(packet.tcp.flags)
                       << ", Window: " << packet.tcp.window_size;
                    
                    if (packet.tcp.calculated_window_size != packet.tcp.window_size)
                    {
                        ss << " (scaled: " << packet.tcp.calculated_window_size << ")";
                    }
                    
                    if (packet.tcp.analysis.is_retransmission)
                    {
                        ss << " [TCP Retransmission]";
                    }
                    if (packet.tcp.analysis.is_dup_ack)
                    {
                        ss << " [TCP Dup ACK #" << packet.tcp.analysis.dup_ack_num << "]";
                    }
                    if (packet.tcp.analysis.is_zero_window)
                    {
                        ss << " [TCP Zero Window]";
                    }
                    
                    ss << "\n  TCP payload: " << packet.tcp.payload_length << " bytes";
                }
                // UDP
                else if (packet.has_udp)
                {
                    ss << "User Datagram Protocol, Src Port: " << packet.udp.src_port
                       << ", Dst Port: " << packet.udp.dst_port << "\n";
                    ss << "  [Stream index: " << packet.udp.stream_index << "]\n";
                    ss << "  Length: " << packet.udp.length
                       << ", Payload: " << packet.udp.payload_length << " bytes";
                }
                // ICMP
                else if (packet.has_icmp)
                {
                    ss << "Internet Control Message Protocol\n";
                    ss << "  Type: " << icmpTypeToString(packet.icmp.type)
                       << " (" << static_cast<int>(packet.icmp.type) << ")";
                    
                    if (packet.icmp.type == ICMP_ECHO || packet.icmp.type == ICMP_ECHOREPLY)
                    {
                        ss << ", ID: " << packet.icmp.identifier
                           << ", Seq: " << packet.icmp.sequence;
                    }
                    
                    if (packet.icmp.is_response_to)
                    {
                        ss << "\n  [Response to frame: " << packet.icmp.response_frame << "]";
                        ss << "\n  [Response time: " << std::fixed << std::setprecision(6)
                           << packet.icmp.response_time << " seconds]";
                    }
                }
            }
            // IPv6
            else if (packet.has_ipv6)
            {
                ss << "Internet Protocol Version 6, Src: " << ipv6ToString(packet.ipv6.src_ip)
                   << ", Dst: " << ipv6ToString(packet.ipv6.dst_ip) << "\n";
                ss << "  Next Header: " << protocolToString(packet.ipv6.next_header)
                   << ", Hop Limit: " << static_cast<int>(packet.ipv6.hop_limit)
                   << ", Payload Length: " << packet.ipv6.payload_length;
                
                if (packet.ipv6.has_extension_headers)
                {
                    ss << " [Extension Headers]";
                }
                ss << "\n";

                // TCP/UDP/ICMPv6 similar to IPv4...
                if (packet.has_tcp)
                {
                    ss << "Transmission Control Protocol, Src Port: " << packet.tcp.src_port
                       << ", Dst Port: " << packet.tcp.dst_port << "\n";
                }
                else if (packet.has_udp)
                {
                    ss << "User Datagram Protocol, Src Port: " << packet.udp.src_port
                       << ", Dst Port: " << packet.udp.dst_port << "\n";
                }
                else if (packet.has_icmpv6)
                {
                    ss << "Internet Control Message Protocol v6\n";
                    ss << "  Type: " << icmpv6TypeToString(packet.icmpv6.type)
                       << " (" << static_cast<int>(packet.icmpv6.type) << ")";
                }
            }
            
            // Application protocol
            if (packet.app_protocol != AppProtocol::UNKNOWN)
            {
                ss << "\nApplication Protocol: " << getAppProtocolName(packet.app_protocol);
                if (packet.is_encrypted)
                {
                    ss << " [Encrypted]";
                }
            }

            return ss.str();
        }

        // ==================== PacketInfo Implementation ====================
        PacketInfo PacketInfo::fromParsedPacket(const ParsedPacket& parsed)
        {
            PacketInfo info;
            
            // Timestamp (convert microseconds to milliseconds)
            info.timestamp = parsed.timestamp / 1000;
            
            // MAC addresses
            info.src_mac = PacketParser::macToString(parsed.src_mac);
            info.dst_mac = PacketParser::macToString(parsed.dst_mac);
            
            // IP addresses
            if (parsed.has_ipv4)
            {
                info.src_ip = PacketParser::ipv4ToString(parsed.src_ip);
                info.dst_ip = PacketParser::ipv4ToString(parsed.dst_ip);
                info.ttl = parsed.ip_ttl;
            }
            else if (parsed.has_ipv6)
            {
                info.src_ip = PacketParser::ipv6ToString(parsed.ipv6.src_ip);
                info.dst_ip = PacketParser::ipv6ToString(parsed.ipv6.dst_ip);
                info.ttl = parsed.ipv6.hop_limit;
            }
            else if (parsed.has_arp)
            {
                info.src_ip = PacketParser::ipv4ToString(parsed.arp.sender_ip);
                info.dst_ip = PacketParser::ipv4ToString(parsed.arp.target_ip);
            }
            
            // Ports
            info.src_port = parsed.src_port;
            info.dst_port = parsed.dst_port;
            
            // Protocol
            info.protocol = PacketParser::getProtocolTypeName(parsed.protocol_type);
            
            // Length
            info.length = parsed.packet_size;
            info.payload_size = parsed.payload_length;
            
            // TCP specific
            if (parsed.has_tcp)
            {
                info.flags = PacketParser::tcpFlagsToString(parsed.tcp_flags);
                
                std::stringstream ss;
                ss << "0x" << std::hex << std::setw(4) << std::setfill('0') 
                   << parsed.tcp.checksum;
                info.checksum = ss.str();
                
                if (!parsed.tcp.checksum_valid)
                {
                    info.checksum += " [incorrect]";
                }
            }
            else if (parsed.has_udp)
            {
                std::stringstream ss;
                ss << "0x" << std::hex << std::setw(4) << std::setfill('0') 
                   << parsed.udp.checksum;
                info.checksum = ss.str();
                
                if (!parsed.udp.checksum_valid)
                {
                    info.checksum += " [incorrect]";
                }
            }
            else if (parsed.has_ipv4)
            {
                std::stringstream ss;
                ss << "0x" << std::hex << std::setw(4) << std::setfill('0') 
                   << parsed.ipv4.checksum;
                info.checksum = ss.str();
                
                if (!parsed.ipv4.checksum_valid)
                {
                    info.checksum += " [incorrect]";
                }
            }
            
            return info;
        }

    } // namespace Common
} // namespace NetworkSecurity

