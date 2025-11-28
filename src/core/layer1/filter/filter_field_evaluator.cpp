// src/core/layer1/filter/filter_field_evaluator.cpp

#include "filter_field_evaluator.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <regex>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // ==================== Main Extraction Function ====================

            bool FieldEvaluator::extractFieldValue(const Common::ParsedPacket& packet,
                                                  FieldType field,
                                                  FieldValue& value,
                                                  ValueType& type)
            {
                // Route to appropriate extractor based on field category
                if (field >= FieldType::FRAME_NUMBER && field <= FieldType::FRAME_PROTOCOLS)
                {
                    return extractFrameField(packet, field, value, type);
                }
                else if (field >= FieldType::ETH_DST && field <= FieldType::VLAN_PRIORITY)
                {
                    return extractEthernetField(packet, field, value, type);
                }
                else if (field >= FieldType::ARP && field <= FieldType::ARP_DUPLICATE)
                {
                    return extractARPField(packet, field, value, type);
                }
                else if (field >= FieldType::IP && field <= FieldType::IP_DST_HOST)
                {
                    return extractIPv4Field(packet, field, value, type);
                }
                else if (field >= FieldType::IPV6 && field <= FieldType::IPV6_ADDR)
                {
                    return extractIPv6Field(packet, field, value, type);
                }
                else if (field >= FieldType::TCP && field <= FieldType::TCP_ANALYSIS_BYTES_IN_FLIGHT)
                {
                    return extractTCPField(packet, field, value, type);
                }
                else if (field >= FieldType::UDP && field <= FieldType::UDP_STREAM)
                {
                    return extractUDPField(packet, field, value, type);
                }
                else if (field >= FieldType::ICMP && field <= FieldType::ICMPV6_CHECKSUM)
                {
                    return extractICMPField(packet, field, value, type);
                }
                else if (field >= FieldType::HTTP && field <= FieldType::SNMP)
                {
                    return extractAppProtocolField(packet, field, value, type);
                }
                
                return false;
            }

            // ==================== Frame Field Extraction ====================

            bool FieldEvaluator::extractFrameField(const Common::ParsedPacket& packet,
                                                  FieldType field,
                                                  FieldValue& value,
                                                  ValueType& type)
            {
                type = ValueType::NUMBER;
                
                switch (field)
                {
                    case FieldType::FRAME_NUMBER:
                        value.number = packet.frame_metadata.frame_number;
                        return true;
                    
                    case FieldType::FRAME_LEN:
                        value.number = packet.frame_metadata.frame_len;
                        return true;
                    
                    case FieldType::FRAME_CAP_LEN:
                        value.number = packet.frame_metadata.frame_cap_len;
                        return true;
                    
                    case FieldType::FRAME_TIME_RELATIVE:
                        value.number = static_cast<uint64_t>(
                            packet.frame_metadata.frame_time_relative * 1000000);
                        return true;
                    
                    case FieldType::FRAME_TIME_DELTA:
                        value.number = static_cast<uint64_t>(
                            packet.frame_metadata.frame_time_delta * 1000000);
                        return true;
                    
                    case FieldType::FRAME_PROTOCOLS:
                        type = ValueType::STRING;
                        return true; // String comparison handled separately
                    
                    default:
                        return false;
                }
            }

            // ==================== Ethernet Field Extraction ====================

            bool FieldEvaluator::extractEthernetField(const Common::ParsedPacket& packet,
                                                     FieldType field,
                                                     FieldValue& value,
                                                     ValueType& type)
            {
                if (!packet.has_ethernet)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::ETH_SRC:
                    case FieldType::ETH_DST:
                    case FieldType::ETH_ADDR:
                        type = ValueType::MAC_ADDRESS;
                        if (field == FieldType::ETH_SRC || field == FieldType::ETH_ADDR)
                        {
                            std::memcpy(value.mac, packet.ethernet.src_mac, 6);
                        }
                        else
                        {
                            std::memcpy(value.mac, packet.ethernet.dst_mac, 6);
                        }
                        return true;
                    
                    case FieldType::ETH_TYPE:
                        type = ValueType::NUMBER;
                        value.number = ntohs(packet.ethernet.ether_type);
                        return true;
                    
                    case FieldType::ETH_SRC_OUI:
                        type = ValueType::NUMBER;
                        value.number = packet.ethernet.src_oui;
                        return true;
                    
                    case FieldType::ETH_DST_OUI:
                        type = ValueType::NUMBER;
                        value.number = packet.ethernet.dst_oui;
                        return true;
                    
                    case FieldType::VLAN:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.ethernet.has_vlan;
                        return true;
                    
                    case FieldType::VLAN_ID:
                        if (!packet.ethernet.has_vlan)
                        {
                            return false;
                        }
                        type = ValueType::NUMBER;
                        value.number = packet.ethernet.vlan_id;
                        return true;
                    
                    case FieldType::VLAN_PRIORITY:
                        if (!packet.ethernet.has_vlan)
                        {
                            return false;
                        }
                        type = ValueType::NUMBER;
                        value.number = packet.ethernet.vlan_priority;
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== ARP Field Extraction ====================

            bool FieldEvaluator::extractARPField(const Common::ParsedPacket& packet,
                                                FieldType field,
                                                FieldValue& value,
                                                ValueType& type)
            {
                if (!packet.has_arp)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::ARP:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::ARP_OPCODE:
                        type = ValueType::NUMBER;
                        value.number = packet.arp.opcode;
                        return true;
                    
                    case FieldType::ARP_SRC_HW:
                        type = ValueType::MAC_ADDRESS;
                        std::memcpy(value.mac, packet.arp.sender_mac, 6);
                        return true;
                    
                    case FieldType::ARP_DST_HW:
                        type = ValueType::MAC_ADDRESS;
                        std::memcpy(value.mac, packet.arp.target_mac, 6);
                        return true;
                    
                    case FieldType::ARP_SRC_PROTO:
                        type = ValueType::IP_ADDRESS;
                        value.ipv4 = packet.arp.sender_ip;
                        return true;
                    
                    case FieldType::ARP_DST_PROTO:
                        type = ValueType::IP_ADDRESS;
                        value.ipv4 = packet.arp.target_ip;
                        return true;
                    
                    case FieldType::ARP_GRATUITOUS:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.arp.is_gratuitous;
                        return true;
                    
                    case FieldType::ARP_PROBE:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.arp.is_probe;
                        return true;
                    
                    case FieldType::ARP_DUPLICATE:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.arp.is_duplicate_ip;
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== IPv4 Field Extraction ====================

            bool FieldEvaluator::extractIPv4Field(const Common::ParsedPacket& packet,
                                                 FieldType field,
                                                 FieldValue& value,
                                                 ValueType& type)
            {
                if (!packet.has_ipv4)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::IP:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::IP_VERSION:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.version;
                        return true;
                    
                    case FieldType::IP_HDR_LEN:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.ihl * 4;
                        return true;
                    
                    case FieldType::IP_DSCP:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.dscp;
                        return true;
                    
                    case FieldType::IP_ECN:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.ecn;
                        return true;
                    
                    case FieldType::IP_LEN:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.total_length;
                        return true;
                    
                    case FieldType::IP_ID:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.identification;
                        return true;
                    
                    case FieldType::IP_FLAGS:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.flags;
                        return true;
                    
                    case FieldType::IP_FLAGS_DF:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.ipv4.flag_df;
                        return true;
                    
                    case FieldType::IP_FLAGS_MF:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.ipv4.flag_mf;
                        return true;
                    
                    case FieldType::IP_FRAG_OFFSET:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.fragment_offset;
                        return true;
                    
                    case FieldType::IP_ttl:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.ttl;
                        return true;
                    
                    case FieldType::IP_PROTO:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.protocol;
                        return true;
                    
                    case FieldType::IP_checksum:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv4.checksum;
                        return true;
                    
                    case FieldType::IP_SRC:
                    case FieldType::IP_SRC_HOST:
                        type = ValueType::IP_ADDRESS;
                        value.ipv4 = packet.ipv4.src_ip;
                        return true;
                    
                    case FieldType::IP_DST:
                    case FieldType::IP_DST_HOST:
                        type = ValueType::IP_ADDRESS;
                        value.ipv4 = packet.ipv4.dst_ip;
                        return true;
                    
                    case FieldType::IP_ADDR:
                        type = ValueType::IP_ADDRESS;
                        value.ipv4 = packet.ipv4.src_ip; // Will check both in comparison
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== IPv6 Field Extraction ====================

            bool FieldEvaluator::extractIPv6Field(const Common::ParsedPacket& packet,
                                                 FieldType field,
                                                 FieldValue& value,
                                                 ValueType& type)
            {
                if (!packet.has_ipv6)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::IPV6:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::IPV6_version:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.version;
                        return true;
                    
                    case FieldType::IPV6_tclass:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.traffic_class;
                        return true;
                    
                    case FieldType::IPV6_FLOW:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.flow_label;
                        return true;
                    
                    case FieldType::IPV6_PLEN:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.payload_length;
                        return true;
                    
                    case FieldType::IPV6_NXTHDR:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.next_header;
                        return true;
                    
                    case FieldType::IPV6_HLIM:
                        type = ValueType::NUMBER;
                        value.number = packet.ipv6.hop_limit;
                        return true;
                    
                    case FieldType::IPV6_SRC:
                    case FieldType::IPV6_DST:
                    case FieldType::IPV6_ADDR:
                        type = ValueType::IP_ADDRESS;
                        if (field == FieldType::IPV6_SRC || field == FieldType::IPV6_ADDR)
                        {
                            std::memcpy(value.ipv6, packet.ipv6.src_ip, 16);
                        }
                        else
                        {
                            std::memcpy(value.ipv6, packet.ipv6.dst_ip, 16);
                        }
                        return true;
                    
                    default:
                        return false;
                }
            }
            // ==================== TCP Field Extraction ====================

            bool FieldEvaluator::extractTCPField(const Common::ParsedPacket& packet,
                                                FieldType field,
                                                FieldValue& value,
                                                ValueType& type)
            {
                if (!packet.has_tcp)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::TCP:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::TCP_SRCPORT:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.src_port;
                        return true;
                    
                    case FieldType::TCP_DSTPORT:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.dst_port;
                        return true;
                    
                    case FieldType::TCP_PORT:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.src_port; // Will check both in comparison
                        return true;
                    
                    case FieldType::TCP_STREAM:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.analysis.stream_index;
                        return true;
                    
                    case FieldType::TCP_SEQ:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.seq_number;
                        return true;
                    
                    case FieldType::TCP_ACK:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.ack_number;
                        return true;
                    
                    case FieldType::TCP_NXTSEQ:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.analysis.next_seq;
                        return true;
                    
                    case FieldType::TCP_LEN:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.payload_length;
                        return true;
                    
                    case FieldType::TCP_HDR_LEN:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.data_offset * 4;
                        return true;
                    
                    case FieldType::TCP_FLAGS:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.flags;
                        return true;
                    
                    case FieldType::TCP_FLAGS_FIN:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_fin;
                        return true;
                    
                    case FieldType::TCP_FLAGS_SYN:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_syn;
                        return true;
                    
                    case FieldType::TCP_FLAGS_RST:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_rst;
                        return true;
                    
                    case FieldType::TCP_FLAGS_PSH:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_psh;
                        return true;
                    
                    case FieldType::TCP_FLAGS_ACK:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_ack;
                        return true;
                    
                    case FieldType::TCP_FLAGS_URG:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_urg;
                        return true;
                    
                    case FieldType::TCP_FLAGS_ECE:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_ece;
                        return true;
                    
                    case FieldType::TCP_FLAGS_CWR:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.flag_cwr;
                        return true;
                    
                    case FieldType::TCP_WINDOW:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.window_size;
                        return true;
                    
                    case FieldType::TCP_WINDOW_SIZE:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.calculated_window_size;
                        return true;
                    
                    case FieldType::TCP_CHECKSUM:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.checksum;
                        return true;
                    
                    case FieldType::TCP_URGENT:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.urgent_pointer;
                        return true;
                    
                    case FieldType::TCP_OPTIONS:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.has_options;
                        return true;
                    
                    case FieldType::TCP_OPTION_MSS:
                        if (!packet.tcp.opt_mss.has_value())
                        {
                            return false;
                        }
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.opt_mss->value;
                        return true;
                    
                    case FieldType::TCP_OPTION_WSCALE:
                        if (!packet.tcp.opt_window_scale.has_value())
                        {
                            return false;
                        }
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.opt_window_scale->shift_count;
                        return true;
                    
                    case FieldType::TCP_OPTION_SACK:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.opt_sack.has_value();
                        return true;
                    
                    case FieldType::TCP_OPTION_TIMESTAMP:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.opt_timestamp.has_value();
                        return true;
                    
                    // TCP Analysis
                    case FieldType::TCP_ANALYSIS:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_RETRANS:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_retransmission;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_FAST_RETRANS:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_fast_retransmission;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_DUP_ACK:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_dup_ack;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_ZERO_WINDOW:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_zero_window;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_KEEP_ALIVE:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_keep_alive;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_OUT_OF_ORDER:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_out_of_order;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_LOST_SEGMENT:
                        type = ValueType::BOOLEAN;
                        value.boolean = packet.tcp.analysis.is_lost_segment;
                        return true;
                    
                    case FieldType::TCP_ANALYSIS_BYTES_IN_FLIGHT:
                        type = ValueType::NUMBER;
                        value.number = packet.tcp.analysis.bytes_in_flight;
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== UDP Field Extraction ====================

            bool FieldEvaluator::extractUDPField(const Common::ParsedPacket& packet,
                                                FieldType field,
                                                FieldValue& value,
                                                ValueType& type)
            {
                if (!packet.has_udp)
                {
                    return false;
                }
                
                switch (field)
                {
                    case FieldType::UDP:
                        type = ValueType::BOOLEAN;
                        value.boolean = true;
                        return true;
                    
                    case FieldType::UDP_SRCPORT:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.src_port;
                        return true;
                    
                    case FieldType::UDP_DSTPORT:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.dst_port;
                        return true;
                    
                    case FieldType::UDP_PORT:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.src_port; // Will check both
                        return true;
                    
                    case FieldType::UDP_LENGTH:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.length;
                        return true;
                    
                    case FieldType::UDP_CHECKSUM:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.checksum;
                        return true;
                    
                    case FieldType::UDP_STREAM:
                        type = ValueType::NUMBER;
                        value.number = packet.udp.stream_index;
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== ICMP Field Extraction ====================

            bool FieldEvaluator::extractICMPField(const Common::ParsedPacket& packet,
                                                 FieldType field,
                                                 FieldValue& value,
                                                 ValueType& type)
            {
                if (packet.has_icmp)
                {
                    switch (field)
                    {
                        case FieldType::ICMP:
                            type = ValueType::BOOLEAN;
                            value.boolean = true;
                            return true;
                        
                        case FieldType::ICMP_TYPE:
                            type = ValueType::NUMBER;
                            value.number = packet.icmp.type;
                            return true;
                        
                        case FieldType::ICMP_CODE:
                            type = ValueType::NUMBER;
                            value.number = packet.icmp.code;
                            return true;
                        
                        case FieldType::ICMP_CHECKSUM:
                            type = ValueType::NUMBER;
                            value.number = packet.icmp.checksum;
                            return true;
                        
                        case FieldType::ICMP_IDENT:
                            type = ValueType::NUMBER;
                            value.number = packet.icmp.identifier;
                            return true;
                        
                        case FieldType::ICMP_SEQ:
                            type = ValueType::NUMBER;
                            value.number = packet.icmp.sequence;
                            return true;
                        
                        case FieldType::ICMP_RESPTIME:
                            if (!packet.icmp.is_response_to)
                            {
                                return false;
                            }
                            type = ValueType::NUMBER;
                            value.number = static_cast<uint64_t>(packet.icmp.response_time * 1000000);
                            return true;
                        
                        default:
                            break;
                    }
                }
                
                if (packet.has_icmpv6)
                {
                    switch (field)
                    {
                        case FieldType::ICMPV6:
                            type = ValueType::BOOLEAN;
                            value.boolean = true;
                            return true;
                        
                        case FieldType::ICMPV6_TYPE:
                            type = ValueType::NUMBER;
                            value.number = packet.icmpv6.type;
                            return true;
                        
                        case FieldType::ICMPV6_CODE:
                            type = ValueType::NUMBER;
                            value.number = packet.icmpv6.code;
                            return true;
                        
                        case FieldType::ICMPV6_CHECKSUM:
                            type = ValueType::NUMBER;
                            value.number = packet.icmpv6.checksum;
                            return true;
                        
                        default:
                            break;
                    }
                }
                
                return false;
            }

            // ==================== Application Protocol Field Extraction ====================

            bool FieldEvaluator::extractAppProtocolField(const Common::ParsedPacket& packet,
                                                        FieldType field,
                                                        FieldValue& value,
                                                        ValueType& type)
            {
                using AppProto = Common::AppProtocol;
                
                type = ValueType::BOOLEAN;
                
                switch (field)
                {
                    case FieldType::HTTP:
                        value.boolean = (packet.app_protocol == AppProto::HTTP);
                        return true;
                    
                    case FieldType::HTTPS:
                        value.boolean = (packet.app_protocol == AppProto::HTTPS);
                        return true;
                    
                    case FieldType::DNS:
                        value.boolean = (packet.app_protocol == AppProto::DNS);
                        return true;
                    
                    case FieldType::SSH:
                        value.boolean = (packet.app_protocol == AppProto::SSH);
                        return true;
                    
                    case FieldType::FTP:
                        value.boolean = (packet.app_protocol == AppProto::FTP || 
                                       packet.app_protocol == AppProto::FTP_DATA);
                        return true;
                    
                    case FieldType::SMTP:
                        value.boolean = (packet.app_protocol == AppProto::SMTP);
                        return true;
                    
                    case FieldType::POP:
                        value.boolean = (packet.app_protocol == AppProto::POP3);
                        return true;
                    
                    case FieldType::IMAP:
                        value.boolean = (packet.app_protocol == AppProto::IMAP);
                        return true;
                    
                    case FieldType::TELNET:
                        value.boolean = (packet.app_protocol == AppProto::TELNET);
                        return true;
                    
                    case FieldType::DHCP:
                        value.boolean = (packet.app_protocol == AppProto::DHCP);
                        return true;
                    
                    case FieldType::NTP:
                        value.boolean = (packet.app_protocol == AppProto::NTP);
                        return true;
                    
                    case FieldType::SNMP:
                        value.boolean = (packet.app_protocol == AppProto::SNMP);
                        return true;
                    
                    default:
                        return false;
                }
            }

            // ==================== Value Comparison Functions ====================

            bool FieldEvaluator::compareValues(const FieldValue& fieldValue,
                                             ValueType fieldType,
                                             Operator op,
                                             const std::string& expectedValue)
            {
                switch (fieldType)
                {
                    case ValueType::NUMBER:
                    {
                        uint64_t expected = 0;
                        try
                        {
                            // Support hex (0x), octal (0), decimal
                            if (expectedValue.size() > 2 && expectedValue[0] == '0' && 
                                (expectedValue[1] == 'x' || expectedValue[1] == 'X'))
                            {
                                expected = std::stoull(expectedValue, nullptr, 16);
                            }
                            else if (expectedValue.size() > 1 && expectedValue[0] == '0')
                            {
                                expected = std::stoull(expectedValue, nullptr, 8);
                            }
                            else
                            {
                                expected = std::stoull(expectedValue);
                            }
                        }
                        catch (...)
                        {
                            return false;
                        }
                        return compareNumber(fieldValue.number, op, expected);
                    }
                    
                    case ValueType::IP_ADDRESS:
                    {
                        // Try IPv4 first
                        struct in_addr addr;
                        if (inet_pton(AF_INET, expectedValue.c_str(), &addr) == 1)
                        {
                            return compareIP(fieldValue.ipv4, op, addr.s_addr);
                        }
                        
                        // Try IPv6
                        struct in6_addr addr6;
                        if (inet_pton(AF_INET6, expectedValue.c_str(), &addr6) == 1)
                        {
                            return compareIPv6(fieldValue.ipv6, op, 
                                             reinterpret_cast<const uint8_t*>(&addr6));
                        }
                        
                        return false;
                    }
                    
                    case ValueType::MAC_ADDRESS:
                    {
                        uint8_t expected_mac[6];
                        int values[6];
                        if (sscanf(expectedValue.c_str(), "%x:%x:%x:%x:%x:%x",
                                  &values[0], &values[1], &values[2],
                                  &values[3], &values[4], &values[5]) == 6)
                        {
                            for (int i = 0; i < 6; i++)
                            {
                                expected_mac[i] = static_cast<uint8_t>(values[i]);
                            }
                            return compareMAC(fieldValue.mac, op, expected_mac);
                        }
                        return false;
                    }
                    
                    case ValueType::STRING:
                    {
                        // String comparison handled separately
                        return compareString(expectedValue, op, expectedValue);
                    }
                    
                    case ValueType::BOOLEAN:
                    {
                        bool expected = false;
                        std::string lower = expectedValue;
                        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                        
                        if (lower == "true" || lower == "1")
                        {
                            expected = true;
                        }
                        else if (lower == "false" || lower == "0")
                        {
                            expected = false;
                        }
                        else
                        {
                            return false;
                        }
                        
                        switch (op)
                        {
                            case Operator::EQUALS:
                                return fieldValue.boolean == expected;
                            case Operator::NOT_EQUALS:
                                return fieldValue.boolean != expected;
                            default:
                                return false;
                        }
                    }
                    
                    default:
                        return false;
                }
            }

            bool FieldEvaluator::compareNumber(uint64_t fieldValue, Operator op, uint64_t expectedValue)
            {
                switch (op)
                {
                    case Operator::EQUALS:
                        return fieldValue == expectedValue;
                    
                    case Operator::NOT_EQUALS:
                        return fieldValue != expectedValue;
                    
                    case Operator::GREATER_THAN:
                        return fieldValue > expectedValue;
                    
                    case Operator::LESS_THAN:
                        return fieldValue < expectedValue;
                    
                    case Operator::GREATER_OR_EQUAL:
                        return fieldValue >= expectedValue;
                    
                    case Operator::LESS_OR_EQUAL:
                        return fieldValue <= expectedValue;
                    
                    case Operator::BITWISE_AND:
                        return (fieldValue & expectedValue) != 0;
                    
                    default:
                        return false;
                }
            }

            bool FieldEvaluator::compareString(const std::string& fieldValue, 
                                              Operator op, 
                                              const std::string& expectedValue)
            {
                switch (op)
                {
                    case Operator::EQUALS:
                        return fieldValue == expectedValue;
                    
                    case Operator::NOT_EQUALS:
                        return fieldValue != expectedValue;
                    
                    case Operator::CONTAINS:
                        return fieldValue.find(expectedValue) != std::string::npos;
                    
                    case Operator::MATCHES:
                    {
                        try
                        {
                            std::regex pattern(expectedValue);
                            return std::regex_search(fieldValue, pattern);
                        }
                        catch (...)
                        {
                            return false;
                        }
                    }
                    
                    default:
                        return false;
                }
            }

            bool FieldEvaluator::compareIP(uint32_t fieldValue, Operator op, uint32_t expectedValue)
            {
                switch (op)
                {
                    case Operator::EQUALS:
                        return fieldValue == expectedValue;
                    
                    case Operator::NOT_EQUALS:
                        return fieldValue != expectedValue;
                    
                    case Operator::GREATER_THAN:
                        return ntohl(fieldValue) > ntohl(expectedValue);
                    
                    case Operator::LESS_THAN:
                        return ntohl(fieldValue) < ntohl(expectedValue);
                    
                    case Operator::GREATER_OR_EQUAL:
                        return ntohl(fieldValue) >= ntohl(expectedValue);
                    
                    case Operator::LESS_OR_EQUAL:
                        return ntohl(fieldValue) <= ntohl(expectedValue);
                    
                    default:
                        return false;
                }
            }

            bool FieldEvaluator::compareIPv6(const uint8_t* fieldValue, 
                                            Operator op, 
                                            const uint8_t* expectedValue)
            {
                int cmp = std::memcmp(fieldValue, expectedValue, 16);
                
                switch (op)
                {
                    case Operator::EQUALS:
                        return cmp == 0;
                    
                    case Operator::NOT_EQUALS:
                        return cmp != 0;
                    
                    case Operator::GREATER_THAN:
                        return cmp > 0;
                    
                    case Operator::LESS_THAN:
                        return cmp < 0;
                    
                    case Operator::GREATER_OR_EQUAL:
                        return cmp >= 0;
                    
                    case Operator::LESS_OR_EQUAL:
                        return cmp <= 0;
                    
                    default:
                        return false;
                }
            }

            bool FieldEvaluator::compareMAC(const uint8_t* fieldValue, 
                                           Operator op, 
                                           const uint8_t* expectedValue)
            {
                int cmp = std::memcmp(fieldValue, expectedValue, 6);
                
                switch (op)
                {
                    case Operator::EQUALS:
                        return cmp == 0;
                    
                    case Operator::NOT_EQUALS:
                        return cmp != 0;
                    
                    default:
                        return false;
                }
            }

            // ==================== Field Existence Check ====================

            bool FieldEvaluator::fieldExists(const Common::ParsedPacket& packet, FieldType field)
            {
                // Check protocol existence
                if (field >= FieldType::ETH_DST && field <= FieldType::VLAN_PRIORITY)
                {
                    return packet.has_ethernet;
                }
                else if (field >= FieldType::ARP && field <= FieldType::ARP_DUPLICATE)
                {
                    return packet.has_arp;
                }
                else if (field >= FieldType::IP && field <= FieldType::IP_DST_HOST)
                {
                    return packet.has_ipv4;
                }
                else if (field >= FieldType::IPV6 && field <= FieldType::IPV6_ADDR)
                {
                    return packet.has_ipv6;
                }
                else if (field >= FieldType::TCP && field <= FieldType::TCP_ANALYSIS_BYTES_IN_FLIGHT)
                {
                    return packet.has_tcp;
                }
                else if (field >= FieldType::UDP && field <= FieldType::UDP_STREAM)
                {
                    return packet.has_udp;
                }
                else if (field == FieldType::ICMP || 
                        (field >= FieldType::ICMP_TYPE && field <= FieldType::ICMP_RESPTIME))
                {
                    return packet.has_icmp;
                }
                else if (field >= FieldType::ICMPV6 && field <= FieldType::ICMPV6_CHECKSUM)
                {
                    return packet.has_icmpv6;
                }
                else if (field >= FieldType::HTTP && field <= FieldType::SNMP)
                {
                    using AppProto = Common::AppProtocol;
                    
                    switch (field)
                    {
                        case FieldType::HTTP:
                            return packet.app_protocol == AppProto::HTTP;
                        case FieldType::HTTPS:
                            return packet.app_protocol == AppProto::HTTPS;
                        case FieldType::DNS:
                            return packet.app_protocol == AppProto::DNS;
                        case FieldType::SSH:
                            return packet.app_protocol == AppProto::SSH;
                        case FieldType::FTP:
                            return packet.app_protocol == AppProto::FTP || 
                                   packet.app_protocol == AppProto::FTP_DATA;
                        case FieldType::SMTP:
                            return packet.app_protocol == AppProto::SMTP;
                        case FieldType::POP:
                            return packet.app_protocol == AppProto::POP3;
                        case FieldType::IMAP:
                            return packet.app_protocol == AppProto::IMAP;
                        case FieldType::TELNET:
                            return packet.app_protocol == AppProto::TELNET;
                        case FieldType::DHCP:
                            return packet.app_protocol == AppProto::DHCP;
                        case FieldType::NTP:
                            return packet.app_protocol == AppProto::NTP;
                        case FieldType::SNMP:
                            return packet.app_protocol == AppProto::SNMP;
                        default:
                            return false;
                    }
                }
                
                // Frame fields always exist
                if (field >= FieldType::FRAME_NUMBER && field <= FieldType::FRAME_PROTOCOLS)
                {
                    return true;
                }
                
                return false;
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity
